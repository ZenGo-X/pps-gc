use std::collections::HashMap;
use std::convert::TryFrom;
use std::iter;

use tokio::sync::Mutex;
use tokio::time::Instant;
use tonic::{Request, Response, Status};

use rand::rngs::OsRng;
use rand::RngCore;
use structopt::StructOpt;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption};

use pps_sgx::crypto::{
    ClientKeysBundle, Location, MockedEnclaveMasterKey, ReceiverEncryptionKey, SignalPlaintext,
    VerificationPublicKey, VerificationSignature,
};
use pps_sgx::proto::pps::signalling_api_server::SignallingApi;
use pps_sgx::proto::pps::*;
use pps_sgx::proto::response::{SetMetricsResponse, SignResponse};

const LOCATION_SIZE: usize = 32;

#[derive(StructOpt, Debug)]
struct Settings {
    /// How many signals every receiver might receive without overwriting the old ones
    #[structopt(short = "l", long, default_value = "100")]
    max_locations: u16,

    /// Address to listen at
    #[structopt(long, default_value = "0.0.0.0:4210")]
    listen_at: std::net::SocketAddr,
}

struct Server {
    settings: Settings,
    enclave_key: MockedEnclaveMasterKey,
    table: Mutex<HashMap<ReceiverEncryptionKey, Receiver>>,
}

struct Receiver {
    vk: VerificationPublicKey,
    pk: ReceiverEncryptionKey,
    index: u16,
    ctr: u64,
    signals: Vec<BlindedSignal>,
}

pub struct BlindedSignal {
    blinding: [u8; LOCATION_SIZE],
    blinded_signal: [u8; LOCATION_SIZE],
}

impl BlindedSignal {
    pub fn new(mut signal: [u8; LOCATION_SIZE]) -> Self {
        let mut blind = [0u8; LOCATION_SIZE];
        OsRng.fill_bytes(&mut blind);
        signal
            .iter_mut()
            .zip(blind.iter())
            .for_each(|(s, b)| *s ^= b);
        Self {
            blinding: blind,
            blinded_signal: signal,
        }
    }
    pub fn empty() -> Self {
        Self::new([0u8; LOCATION_SIZE])
    }
    pub fn assign_new_or_rerandomize(&mut self, new_value: CtOption<[u8; LOCATION_SIZE]>) {
        *self = Self::new(new_value.unwrap_or(self.reveal()))
    }
    pub fn reveal(&self) -> [u8; LOCATION_SIZE] {
        let mut signal = self.blinded_signal;
        signal
            .iter_mut()
            .zip(&self.blinding)
            .for_each(|(s, b)| *s ^= b);
        signal
    }
}

#[async_trait::async_trait]
impl SignallingApi for Server {
    async fn get_pk(
        &self,
        _request: Request<GetPkRequest>,
    ) -> Result<Response<GetPkResponse>, Status> {
        let public_key = self.enclave_key.public_key();
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

        let mut table = self.table.lock().await;

        let encrypted_public_keys =
            serde_json::from_slice(&encrypted_public_keys).map_err(|e| {
                Status::invalid_argument(format!("malformed encrypted public keys: {}", e))
            })?;
        let decrypted_public_keys =
            self.enclave_key
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

        if table.contains_key(&receiver_pk) {
            return Err(Status::permission_denied("receiver already exists"));
        }

        let signals = iter::repeat_with(|| BlindedSignal::empty())
            .take(self.settings.max_locations.into())
            .collect();

        let receiver_pk_bytes = serde_json::to_vec(&receiver_pk)
            .map_err(|e| Status::internal(format!("serialize receiver public key: {}", e)))?;

        table.insert(
            receiver_pk.clone(),
            Receiver {
                pk: receiver_pk.clone(),
                vk: receiver_vk,
                index: 0,
                ctr: 0,
                signals,
            },
        );

        Response::new(SetupResponse {
            public_key: receiver_pk_bytes,
        })
        .sign(&self.enclave_key)?
        .set_took_time(started.elapsed())
    }

    async fn send(&self, request: Request<SendRequest>) -> Result<Response<SendResponse>, Status> {
        let started = Instant::now();

        let mut table = self.table.lock().await;

        let encrypted_signal = serde_json::from_slice(&request.into_inner().encrypted_signal)
            .map_err(|e| Status::invalid_argument(format!("malformed encrypted signal: {}", e)))?;
        let signal = self.enclave_key.decrypt(&encrypted_signal).map_err(|e| {
            Status::invalid_argument(format!("malformed signal: failed to decrypt: {}", e))
        })?;
        let SignalPlaintext { signal, recipient } =
            serde_json::from_slice(&signal).map_err(|e| {
                Status::invalid_argument(format!("malformed signal: failed to parse: {}", e))
            })?;
        let signal = <[u8; LOCATION_SIZE]>::try_from(signal.as_ref()).map_err(|_| {
            Status::invalid_argument(format!(
                "signal must be exactly {} bytes length",
                LOCATION_SIZE
            ))
        })?;

        for (receiver_i_pk, receiver_i) in &mut *table {
            // TODO: comparison should be constant time
            let signal_destined_for_this_receiver =
                Choice::from(u8::from(recipient == *receiver_i_pk));

            for (loc, j) in receiver_i.signals.iter_mut().zip(0..) {
                let overwrite_signal =
                    j.ct_eq(&receiver_i.index) & signal_destined_for_this_receiver;
                let new_value = CtOption::new(signal, overwrite_signal);
                loc.assign_new_or_rerandomize(new_value);
            }

            receiver_i
                .index
                .conditional_assign(&(receiver_i.index + 1), signal_destined_for_this_receiver);
        }

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

        let mut table = self.table.lock().await;

        let receiver = table
            .get_mut(&public_key)
            .ok_or_else(|| Status::permission_denied("permission denied"))?;

        let verified = receiver.vk.verify(ctr, &signature);
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

        let mut signals_to_send = vec![];
        for signal in &mut receiver.signals {
            signals_to_send.push(
                receiver
                    .pk
                    .encrypt(&mut OsRng, Location::new(signal.reveal().to_vec()))
                    .map_err(|e| Status::internal(format!("cannot encrypt the signal: {}", e)))?
                    .ciphertext,
            )
        }
        receiver.index = 0;

        Response::new(ReceiveResponse {
            encrypted_row: signals_to_send,
        })
        .sign(&self.enclave_key)?
        .set_took_time(started.elapsed())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let settings: Settings = StructOpt::from_args();
    let addr = settings.listen_at.clone();
    let server = Server {
        settings,
        enclave_key: MockedEnclaveMasterKey::random(&mut OsRng).unwrap(),
        table: HashMap::new().into(),
    };

    tonic::transport::Server::builder()
        .add_service(pps_sgx::proto::pps::signalling_api_server::SignallingApiServer::new(server))
        .serve(addr)
        .await?;

    Ok(())
}
