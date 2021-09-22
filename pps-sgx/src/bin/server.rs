use std::collections::HashMap;
use std::path::PathBuf;
use std::{io, iter};

use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::{Request, Response, Status};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use pps_sgx::crypto::{
    ClientKeysBundle, Location, MockedEnclaveMasterKey, ReceiverEncryptionKey, SealedLocation,
    SgxKey, SignalPlaintext, VerificationPublicKey, VerificationSignature,
};
use pps_sgx::proto::pps::signalling_api_server::SignallingApi;
use pps_sgx::proto::pps::*;
use pps_sgx::proto::response::{SetMetricsResponse, SignResponse};

#[derive(StructOpt, Debug)]
struct Settings {
    /// Path to file containing sensitive information, will be created at starting up
    ///
    /// Anjuna Runtime must be configured to encrypt this file with hardware key!
    #[structopt(long, default_value = "data/sensitive.json")]
    sensitive_file: PathBuf,

    /// Path to file containing signals table
    ///
    /// No additional settings in Anjuna Runtime are required, file will be encrypted and authenticated.
    #[structopt(long, default_value = "data/table.json")]
    table_file: PathBuf,

    /// Every location has to have the same length (in bytes)
    #[structopt(long, default_value = "32")]
    location_length: u16,

    /// How many signals every receiver might receive without overwriting the old ones
    #[structopt(short = "l", long, default_value = "100")]
    max_locations: u16,

    /// Address to listen at
    #[structopt(long, default_value = "0.0.0.0:4210")]
    listen_at: std::net::SocketAddr,

    /// Turns off saving persistent state at the end of every request handling
    ///
    /// All persistent state will be lost after server stops.
    #[structopt(long)]
    disable_fs_mirroring: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct SensitiveFile {
    enclave_master_key: MockedEnclaveMasterKey,
    #[serde(with = "serde_with::rust::map_as_tuple_list")]
    parties_table: HashMap<ReceiverEncryptionKey, ReceiverState>,
}

#[derive(Serialize, Deserialize, Debug)]
struct ReceiverState {
    encryption_key: ReceiverEncryptionKey,   // pk
    verification_key: VerificationPublicKey, // vk
    index: u16,
    ctr: u64,
    sgx_key: SgxKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct LocationsTableFile {
    #[serde(with = "serde_with::rust::map_as_tuple_list")]
    table: HashMap<ReceiverEncryptionKey, Vec<SealedLocation>>,
}

struct Server {
    settings: Settings,
    persistent: Mutex<Persistent>,
}

struct Persistent {
    sensitive: SensitiveFile,
    locations: LocationsTableFile,
}

impl Server {
    pub async fn save_persistent_state(&self, state: &Persistent) -> io::Result<()> {
        if self.settings.disable_fs_mirroring {
            return Ok(());
        }
        let sensitive_serialized = serde_json::to_vec_pretty(&state.sensitive)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let table_serialized = serde_json::to_vec_pretty(&state.locations)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        fs::write(&self.settings.sensitive_file, &sensitive_serialized).await?;
        fs::write(&self.settings.table_file, &table_serialized).await?;
        Ok(())
    }
    pub async fn load_persistent_state(settings: &Settings) -> io::Result<Persistent> {
        let sensitive: SensitiveFile = match fs::read(&settings.sensitive_file).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => SensitiveFile {
                enclave_master_key: MockedEnclaveMasterKey::random(&mut OsRng)
                    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
                parties_table: HashMap::default(),
            },
            Err(err) => return Err(err),
        };
        let locations: LocationsTableFile = match fs::read(&settings.table_file).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => LocationsTableFile {
                table: HashMap::default(),
            },
            Err(err) => return Err(err),
        };
        Ok(Persistent {
            sensitive,
            locations,
        })
    }
}

#[async_trait::async_trait]
impl SignallingApi for Server {
    async fn get_pk(
        &self,
        _request: Request<GetPkRequest>,
    ) -> Result<Response<GetPkResponse>, Status> {
        let persistent = self.persistent.lock().await;
        let public_key = persistent.sensitive.enclave_master_key.public_key();
        let public_key = serde_json::to_vec(&public_key)
            .map_err(|e| Status::internal(format!("serialize public key: {}", e)))?;
        Ok(Response::new(GetPkResponse { public_key }))
    }

    async fn setup(
        &self,
        request: Request<SetupRequest>,
    ) -> Result<Response<SetupResponse>, Status> {
        let started = Instant::now();
        let SetupRequest {
            encrypted_public_keys,
        } = request.into_inner();

        let mut persistent = self.persistent.lock().await;

        let encrypted_public_keys =
            serde_json::from_slice(&encrypted_public_keys).map_err(|e| {
                Status::invalid_argument(format!("malformed encrypted public keys: {}", e))
            })?;
        let decrypted_public_keys = persistent
            .sensitive
            .enclave_master_key
            .decrypt(&encrypted_public_keys)
            .map_err(|e| {
                Status::invalid_argument(format!("public keys cannot be decrypted: {}", e))
            })?;
        let decrypted_public_keys: ClientKeysBundle =
            serde_json::from_slice(&decrypted_public_keys).map_err(|e| {
                Status::invalid_argument(format!("decrypted public keys are malformed: {}", e))
            })?;
        let receiver_pk = decrypted_public_keys.pk;
        let receiver_vk = decrypted_public_keys.vk;

        if persistent
            .sensitive
            .parties_table
            .contains_key(&receiver_pk)
        {
            return Err(Status::permission_denied("receiver already exists"));
        }

        let mut sgx_key = SgxKey::random(&mut OsRng);
        let empty_signals_row = {
            let mut cipher = sgx_key.cipher();
            iter::repeat_with(|| vec![0u8; usize::from(self.settings.location_length)])
                .zip(0..)
                .map(|(l, j)| cipher.seal(&receiver_pk, j, Location::new(l)))
                .take(self.settings.max_locations.into())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Status::internal(format!("seal error: {}", e)))?
        };

        let receiver_pk_bytes = serde_json::to_vec(&receiver_pk)
            .map_err(|e| Status::internal(format!("serialize receiver public key: {}", e)))?;

        persistent.sensitive.parties_table.insert(
            receiver_pk.clone(),
            ReceiverState {
                encryption_key: receiver_pk.clone(),
                verification_key: receiver_vk,
                index: 0,
                ctr: 0,
                sgx_key,
            },
        );
        persistent
            .locations
            .table
            .insert(receiver_pk.clone(), empty_signals_row);

        self.save_persistent_state(&persistent)
            .await
            .map_err(|e| Status::internal(format!("failed to save persistent state: {}", e)))?;

        Response::new(SetupResponse {
            public_key: receiver_pk_bytes,
        })
        .sign(&persistent.sensitive.enclave_master_key)?
        .set_took_time(started.elapsed())
    }

    async fn send(&self, request: Request<SendRequest>) -> Result<Response<SendResponse>, Status> {
        let started = Instant::now();

        let mut persistent = self.persistent.lock().await;
        let persistent = &mut *persistent;

        let encrypted_signal = serde_json::from_slice(&request.into_inner().encrypted_signal)
            .map_err(|e| Status::invalid_argument(format!("malformed encrypted signal: {}", e)))?;
        let signal = persistent
            .sensitive
            .enclave_master_key
            .decrypt(&encrypted_signal)
            .map_err(|e| {
                Status::invalid_argument(format!("malformed signal: failed to decrypt: {}", e))
            })?;
        let signal: SignalPlaintext = serde_json::from_slice(&signal).map_err(|e| {
            Status::invalid_argument(format!("malformed signal: failed to parse: {}", e))
        })?;

        for (receiver_pk, locs) in &mut persistent.locations.table {
            let receiver = match persistent.sensitive.parties_table.get_mut(receiver_pk) {
                Some(r) => r,
                None => {
                    // that's not good, but what can we do?
                    continue;
                }
            };
            let mut cipher = receiver.sgx_key.cipher();

            for (loc, j) in locs.iter_mut().zip(0..) {
                // TODO: make it constant-time
                // TODO: check that decrypted location is exactly `self.settings.location_length` bytes
                if signal.recipient == *receiver_pk && j == receiver.index {
                    *loc = cipher
                        .seal(receiver_pk, j, signal.signal.clone())
                        .map_err(|e| Status::internal(format!("encrypt error: {}", e)))?
                } else {
                    cipher
                        .rerandomize(receiver_pk, j, loc)
                        .map_err(|e| Status::internal(format!("rerandomize error: {}", e)))?
                }
            }

            if signal.recipient == *receiver_pk {
                receiver.index += 1
            }
        }

        self.save_persistent_state(&persistent)
            .await
            .map_err(|e| Status::internal(format!("failed to save persistent state: {}", e)))?;

        Response::new(SendResponse {}).set_took_time(started.elapsed())
    }

    async fn receive(
        &self,
        request: Request<ReceiveRequest>,
    ) -> Result<Response<ReceiveResponse>, Status> {
        let started = Instant::now();
        let ReceiveRequest {
            public_key,
            ctr,
            signature,
        } = request.into_inner();
        let public_key: ReceiverEncryptionKey = serde_json::from_slice(&public_key)
            .map_err(|e| Status::invalid_argument(format!("malformed public key: {}", e)))?;
        let signature = VerificationSignature { bytes: signature };

        let mut persistent = self.persistent.lock().await;
        let persistent = &mut *persistent;

        let receiver = persistent
            .sensitive
            .parties_table
            .get_mut(&public_key)
            .ok_or_else(|| Status::permission_denied("permission denied"))?;

        let verified = receiver.verification_key.verify(ctr, &signature);
        if !verified {
            return Err(Status::permission_denied("permission denied"));
        }
        if ctr != receiver.ctr {
            return Err(Status::invalid_argument(format!(
                "expected ctr={}",
                receiver.ctr
            )));
        }
        receiver.ctr += 1;

        let new_sgx_key = SgxKey::random(&mut OsRng);
        let mut old_sgx_key = std::mem::replace(&mut receiver.sgx_key, new_sgx_key);
        let empty_signals_row = {
            let mut cipher = receiver.sgx_key.cipher();
            iter::repeat_with(|| vec![0u8; usize::from(self.settings.location_length)])
                .zip(0..)
                .map(|(l, j)| cipher.seal(&public_key, j, Location::new(l)))
                .take(self.settings.max_locations.into())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Status::internal(format!("seal error: {}", e)))?
        };

        let signals = persistent
            .locations
            .table
            .insert(public_key.clone(), empty_signals_row)
            .ok_or_else(|| Status::internal("signals missing"))?;
        let mut signals_to_send = vec![];

        let cipher = old_sgx_key.cipher();
        for (signal, j) in signals.into_iter().zip(0..) {
            signals_to_send.push(
                cipher
                    .open_to_receiver(&mut OsRng, &public_key, j, signal)
                    .map_err(|e| Status::internal(format!("open to receiver: {}", e)))?
                    .ciphertext,
            )
        }

        self.save_persistent_state(&persistent)
            .await
            .map_err(|e| Status::internal(format!("failed to save persistent state: {}", e)))?;

        Response::new(ReceiveResponse {
            encrypted_row: signals_to_send,
        })
        .sign(&persistent.sensitive.enclave_master_key)?
        .set_took_time(started.elapsed())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings: Settings = StructOpt::from_args();
    let addr = settings.listen_at.clone();
    let persistent = Server::load_persistent_state(&settings).await?;
    let server = Server {
        settings,
        persistent: Mutex::new(persistent),
    };

    tonic::transport::Server::builder()
        .add_service(pps_sgx::proto::pps::signalling_api_server::SignallingApiServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
