use std::collections::HashMap;
use std::path::PathBuf;
use std::{io, iter};

use curv::cryptographic_primitives::twoparty::dh_key_exchange as dh;
use curv::elliptic::curves::secp256_k1::GE;

use tokio::fs;
use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::{Request, Response, Status};

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

use pps_sgx::crypto::{
    EncryptedSetupMsg, Location, MockedEnclaveMasterKey, ReceiverDecryptionKey,
    ReceiverEncryptedLocation, ReceiverEncryptionKey, SealedLocation, SetupEncryptionKey, SgxKey,
    VerificationPublicKey, VerificationSignature,
};
use pps_sgx::proto::pps::signalling_api_server::SignallingApi;
use pps_sgx::proto::pps::*;
use pps_sgx::proto::response::{SetMetricsResponse, SignResponse};

type ReceiverIndex = u64;

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
    next_receiver_index: ReceiverIndex,
    parties_table: HashMap<ReceiverIndex, ReceiverState>,
}

#[derive(Serialize, Deserialize, Debug)]
enum ReceiverState {
    Setup(ReceiverSetup),
    Registered(Receiver),
}

impl ReceiverState {
    fn into_setup(self) -> Option<ReceiverSetup> {
        match self {
            ReceiverState::Setup(r) => Some(r),
            _ => None,
        }
    }
    fn as_registered_mut(&mut self) -> Option<&mut Receiver> {
        match self {
            ReceiverState::Registered(r) => Some(r),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct ReceiverSetup {
    k: SetupEncryptionKey,
    sgx_key: SgxKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct Receiver {
    location_encryption_key: ReceiverEncryptionKey, // pk
    location_decryption_key: ReceiverDecryptionKey, // sk
    verification_key: VerificationPublicKey,        // vk
    index: u16,
    ctr: u64,
    sgx_key: SgxKey,
}

#[derive(Serialize, Deserialize, Debug)]
struct LocationsTableFile {
    table: HashMap<ReceiverIndex, Vec<SealedLocation>>,
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
            return Ok(())
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
                next_receiver_index: 1,
                parties_table: Default::default(),
            },
            Err(err) => return Err(err),
        };
        let locations: LocationsTableFile = match fs::read(&settings.table_file).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
            Err(e) if e.kind() == io::ErrorKind::NotFound => LocationsTableFile {
                table: Default::default(),
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

    async fn key_exchange(
        &self,
        request: Request<KeyExchangeRequest>,
    ) -> Result<Response<KeyExchangeResponse>, Status> {
        let started = Instant::now();
        let request = request.into_inner();

        let ga: dh::Party1FirstMessage<GE> = serde_json::from_slice(&request.ga)
            .map_err(|e| Status::invalid_argument(format!("invalid g^a: {}", e)))?;
        let (gb, server_secret) = dh::Party2FirstMessage::<GE>::first();
        let setup_encryption_key =
            SetupEncryptionKey::from_handshake(&server_secret, &ga.public_share)
                .map_err(|e| Status::internal(format!("derive setup encryption key: {}", e)))?; // todo: display error!

        let gb_serialized = serde_json::to_vec(&gb)
            .map_err(|e| Status::internal(format!("serialize gb: {}", e)))?;

        let sgx_key = SgxKey::random(&mut OsRng);

        let mut persistent = self.persistent.lock().await;

        let receiver_id = persistent.sensitive.next_receiver_index;
        persistent.sensitive.next_receiver_index += 1;

        let was = persistent.sensitive.parties_table.insert(
            receiver_id,
            ReceiverState::Setup(ReceiverSetup {
                k: setup_encryption_key,
                sgx_key,
            }),
        );
        debug_assert!(was.is_none());

        self.save_persistent_state(&persistent)
            .await
            .map_err(|e| Status::internal(format!("failed to save persistent state: {}", e)))?;

        Response::new(KeyExchangeResponse {
            id: receiver_id,
            ga: request.ga,
            gb: gb_serialized,
        })
        .sign(&persistent.sensitive.enclave_master_key)?
        .set_took_time(started.elapsed())
    }

    async fn setup(
        &self,
        request: Request<SetupRequest>,
    ) -> Result<Response<SetupResponse>, Status> {
        let started = Instant::now();
        let SetupRequest { id, encrypted_key } = request.into_inner();

        let mut persistent = self.persistent.lock().await;

        let decrypted_setup_msg = match persistent.sensitive.parties_table.get(&id) {
            Some(ReceiverState::Setup(r)) => {
                r.k.decrypt(EncryptedSetupMsg {
                    bytes: encrypted_key,
                })
                .map_err(|e| Status::permission_denied(format!("decrypt error: {}", e)))?
            }
            Some(ReceiverState::Registered(_)) => {
                return Err(Status::permission_denied("receiver already registered"))
            }
            None => {
                return Err(Status::not_found(
                    "receiver not found: key exchange wasn't performed",
                ))
            }
        };

        let mut sgx_key = persistent
            .sensitive
            .parties_table
            .remove(&id)
            .and_then(|r| r.into_setup())
            .ok_or_else(|| Status::internal("guaranteed by match above"))?
            .sgx_key;
        let empty_signals_row = {
            let mut cipher = sgx_key.cipher();
            iter::repeat_with(|| vec![0u8; usize::from(self.settings.location_length)])
                .zip(0..)
                .map(|(l, j)| cipher.seal(j, Location::new(l)))
                .take(self.settings.max_locations.into())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Status::internal(format!("seal error: {}", e)))?
        };

        let pk = decrypted_setup_msg.sk.encryption_key();
        let pk_bytes = serde_json::to_vec(&pk)
            .map_err(|e| Status::internal(format!("serialize pk: {}", e)))?;

        persistent.sensitive.parties_table.insert(
            id,
            ReceiverState::Registered(Receiver {
                location_encryption_key: pk.clone(),
                location_decryption_key: decrypted_setup_msg.sk,
                verification_key: decrypted_setup_msg.vk,
                index: 0,
                ctr: 0,
                sgx_key,
            }),
        );
        persistent.locations.table.insert(id, empty_signals_row);

        self.save_persistent_state(&persistent)
            .await
            .map_err(|e| Status::internal(format!("failed to save persistent state: {}", e)))?;

        Response::new(SetupResponse {
            public_key: pk_bytes,
        })
        .sign(&persistent.sensitive.enclave_master_key)?
        .set_took_time(started.elapsed())
    }

    async fn send(&self, request: Request<SendRequest>) -> Result<Response<SendResponse>, Status> {
        let started = Instant::now();
        let ciphertext = ReceiverEncryptedLocation {
            ciphertext: request.into_inner().encrypted_signal,
        };

        let mut persistent = self.persistent.lock().await;
        let Persistent {
            sensitive,
            locations,
        } = &mut *persistent;

        for (receiver_id, locs) in &mut locations.table {
            let receiver = match sensitive.parties_table.get_mut(receiver_id) {
                Some(ReceiverState::Registered(r)) => r,
                Some(ReceiverState::Setup(_)) | None => {
                    // that's not good, but what can we do?
                    continue;
                }
            };
            let mut cipher = receiver.sgx_key.cipher();

            let mut result = receiver.location_decryption_key.decrypt(&ciphertext).ok();
            let decrypted_ok = result.is_some();

            for (loc, j) in locs.iter_mut().zip(0..) {
                // TODO: make it constant-time
                // TODO: check that decrypted location is exactly `self.settings.location_length` bytes
                if j == receiver.index {
                    match result.take() {
                        Some(new_loc) => {
                            *loc = cipher
                                .seal(j, new_loc)
                                .map_err(|e| Status::internal(format!("encrypt error: {}", e)))?
                        }
                        None => cipher
                            .rerandomize(j, loc)
                            .map_err(|e| Status::internal(format!("rerandomize error: {}", e)))?,
                    }
                } else {
                    cipher
                        .rerandomize(j, loc)
                        .map_err(|e| Status::internal(format!("rerandomize error: {}", e)))?
                }
            }

            if decrypted_ok {
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
        let ReceiveRequest { id, ctr, signature } = request.into_inner();

        let mut persistent = self.persistent.lock().await;
        let Persistent {
            sensitive,
            locations,
        } = &mut *persistent;

        let receiver = sensitive
            .parties_table
            .get_mut(&id)
            .and_then(|r| r.as_registered_mut())
            .ok_or_else(|| Status::permission_denied("permission denied"))?;

        let verified = receiver
            .verification_key
            .verify(ctr, &VerificationSignature { bytes: signature });
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

        let mut old_sgx_key = {
            let new_sgx_key = SgxKey::random(&mut OsRng);
            std::mem::replace(&mut receiver.sgx_key, new_sgx_key)
        };
        let empty_signals_row = {
            let mut cipher = receiver.sgx_key.cipher();
            iter::repeat_with(|| vec![0u8; usize::from(self.settings.location_length)])
                .zip(0..)
                .map(|(l, j)| cipher.seal(j, Location::new(l)))
                .take(self.settings.max_locations.into())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| Status::internal(format!("seal error: {}", e)))?
        };

        let signals = locations
            .table
            .insert(id, empty_signals_row)
            .ok_or_else(|| Status::internal("signals missing"))?;
        let mut signals_to_send = vec![];

        let cipher = old_sgx_key.cipher();
        for (signal, j) in signals.into_iter().zip(0..) {
            signals_to_send.push(
                cipher
                    .open_to_receiver(&mut OsRng, j, signal, &receiver.location_encryption_key)
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
