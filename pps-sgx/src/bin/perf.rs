use std::convert::TryFrom;
use std::path::PathBuf;

use pps_sgx::crypto::*;
use rand::rngs::OsRng;

use pps_sgx::proto::pps::signalling_api_client::SignallingApiClient;
use pps_sgx::proto::pps::*;
use pps_sgx::proto::response::GetMetricsResponse;
use tokio::fs;
use tokio::io::{self, AsyncWriteExt};

use anyhow::{ensure, Context};
use rand::RngCore;
use std::time::{Duration, Instant};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Cli {
    /// SGX server address
    #[structopt(long, default_value = "http://localhost:4210", env = "ENDPOINT")]
    address: String,

    /// Receivers to be registered by perf tool
    ///
    /// After registering every receiver, perf will send N signals to that recipient and print
    /// average performance.
    #[structopt(long, short)]
    receivers: u16,

    /// Number of signals that will be sent to every registered recipient per RECEIVE request
    #[structopt(short, long, default_value = "5")]
    signals: u16,

    /// Number of RECEIVE requests sent per every receiver
    ///
    /// Prior to any RECEIVE request, fixed amount of signals is sent to the receiver (specified by
    /// `--signals` flag)
    #[structopt(long, default_value = "1")]
    receives: u16,

    /// Directory with cached RSA private keys
    ///
    /// Generating RSA keys is time consuming operation, so we cache and reuse generated certificates
    #[structopt(long, default_value = "./cache")]
    cache: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Cli = StructOpt::from_args();

    let cache = CachedPrivateKeys::from_dir(args.cache).await?;

    let mut client = SignallingApiClient::connect(args.address).await?;
    println!("PPS Server: Connection established");
    println!();

    let enclave_pk = client
        .get_pk(GetPkRequest {})
        .await
        .context("get pk request")?
        .into_inner();
    let enclave_pk: MockedEnclavePublicMasterKey =
        serde_json::from_slice(&enclave_pk.public_key).context("read attestation pk")?;
    println!("Attestation key: Retrieved");
    println!();

    let mut registration_average = AverageTime::new();
    let mut signal_encryption_average = AverageTime::new();
    let mut signals_decryption_average = AverageTime::new();
    let mut signals_receive_average = AverageTime::new();
    let mut signal_send_stats = Vec::<(u16, Duration)>::new();
    let mut signal_receive_stats = Vec::<(u16, Duration)>::new();

    for receiver_ind in 1..=args.receivers {
        // Register new recipient
        println!("Register receiver {}", receiver_ind);
        let (sk, vk) = cache.load_or_generate(receiver_ind).await?;
        let pk = sk.encryption_key();
        let keys_bundle = ClientKeysBundle {
            pk: pk.clone(),
            vk: vk.public_key(),
        };
        let keys_bundle = serde_json::to_vec(&keys_bundle).context("serialize keys bundle")?;
        let keys_bundle = enclave_pk
            .encrypt(&keys_bundle)
            .context("encrypt keys bundle")?;
        let keys_bundle =
            serde_json::to_vec(&keys_bundle).context("serialize enclave ciphertext")?;
        println!(" └ receiver keys generation: completed");
        let response = client
            .setup(SetupRequest {
                encrypted_public_keys: keys_bundle,
            })
            .await
            .context("setup request")?;
        let took = response.get_took_time().context("get took-time")?;
        registration_average.add(took.as_duration().unwrap());
        println!(" └ registration: completed");
        println!(" └ took: {} (at server side)", took);
        println!();

        let mut signal_send_average = AverageTime::new();

        for receive_req_i in 1..=args.receives {
            let mut sent_signals = vec![];
            for signal_i in 1..=args.signals {
                println!(
                    "Send signal {}/{}",
                    (receive_req_i - 1) * args.signals + signal_i,
                    args.signals * args.receives
                );
                let mut location = [0u8; 32];
                OsRng.fill_bytes(&mut location);
                sent_signals.push(location);

                let signal_encryption_started = signal_encryption_average.start_stopwatch();
                let signal = SignalPlaintext {
                    recipient: pk.clone(),
                    signal: Location::new(location.to_vec()),
                };
                let signal = serde_json::to_vec(&signal).context("serialize signal")?;
                let signal = enclave_pk.encrypt(&signal).context("encrypt signal")?;
                let signal = serde_json::to_vec(&signal).context("serialize encrypted signal")?;
                let signal_encryption_took = signal_encryption_started.stop_and_save();
                println!(" └ signal encryption: completed");
                println!(" └ signal encryption took: {:?}", signal_encryption_took);
                let response = client
                    .send(SendRequest {
                        encrypted_signal: signal,
                    })
                    .await
                    .context("`send` request")?;
                let took = response.get_took_time().context("get took-time")?;
                signal_send_average.add(took.as_duration().unwrap());
                println!(" └ signal sending: completed");
                println!(" └ took: {} (at server side)", took);
            }

            println!("Receive signals");
            let ctr = receive_req_i - 1;
            let signature = vk.sign(ctr.into()).context("sign ctr")?;
            let public_key_bytes = serde_json::to_vec(&pk).context("serialize public key")?;
            let response = client
                .receive(ReceiveRequest {
                    public_key: public_key_bytes,
                    ctr: ctr.into(),
                    signature: signature.bytes,
                })
                .await
                .context("`receive` request")?;
            let took = response.get_took_time().context("get took-time")?;
            signals_receive_average.add(took.as_duration().unwrap());
            println!(" └ response: received");
            println!(" └ took: {} (at server side)", took);

            let decryption_started = signals_decryption_average.start_stopwatch();
            let mut decrypted_signals = vec![];
            for signal in response.into_inner().encrypted_row {
                let decrypted = sk
                    .decrypt(&ReceiverEncryptedLocation { ciphertext: signal })
                    .context("decrypt signal")?;
                if decrypted.as_ref() == &[0u8; 32] {
                    continue;
                }
                decrypted_signals.push(<[u8; 32]>::try_from(decrypted.as_ref()).unwrap())
            }
            let decryption_took = decryption_started.stop_and_save();
            ensure!(
                decrypted_signals == sent_signals,
                "received signals don't match sent signals"
            );
            println!(" └ decrypted {} signal(s)", decrypted_signals.len());
            println!(" └ decryption took: {:?}", decryption_took);
            println!();
        }
        signal_send_stats.push((receiver_ind, signal_send_average.average()));
    }

    println!("# Summary");
    println!();
    println!(
        "* Registration takes: {:?} (in average, on server side)",
        registration_average.average()
    );
    println!(
        "* RECEIVE takes: {:?} (in average, on server side)",
        signals_receive_average.average()
    );
    println!(
        "* Signal encryption takes: {:?} (in average)",
        signal_encryption_average.average()
    );
    println!(
        "* Signals decryption takes: {:?} (in average)",
        signals_decryption_average.average()
    );

    println!("* On server side, processing SEND/RECEIVE request takes: (depending on number of registered receivers)");
    for (n, av_send) in &signal_send_stats {
        println!("  * {}: {:?}", n, av_send);
    }

    Ok(())
}

pub struct CachedPrivateKeys {
    path: PathBuf,
}

impl CachedPrivateKeys {
    pub async fn from_dir(path: PathBuf) -> anyhow::Result<Self> {
        fs::create_dir_all(&path)
            .await
            .with_context(|| format!("create cache directory {:?}", path))?;
        Ok(Self { path })
    }

    pub async fn load(
        &self,
        index: u16,
    ) -> anyhow::Result<Option<(ReceiverDecryptionKey, VerificationPrivateKey)>> {
        let path = self.path.join(format!("sk{}", index));
        let sk_bytes = match fs::read(&path).await {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).context(format!("read cached private key {:?}", path)),
        };
        serde_json::from_slice(&sk_bytes)
            .with_context(|| format!("parse cached private key {:?}", path))
            .map(Some)
    }

    pub async fn save(
        &self,
        index: u16,
        private_key: &ReceiverDecryptionKey,
        verification_key: &VerificationPrivateKey,
    ) -> anyhow::Result<()> {
        let path = self.path.join(format!("sk{}", index));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .await
            .with_context(|| format!("create cache file {:?}", path))?;
        let bytes = serde_json::to_vec(&(private_key, verification_key))
            .context("serialize private key")?;
        file.write_all(&bytes)
            .await
            .with_context(|| format!("write to cache file {:?}", path))?;
        file.flush()
            .await
            .with_context(|| format!("flush cache file {:?}", path))
    }

    pub async fn load_or_generate(
        &self,
        index: u16,
    ) -> anyhow::Result<(ReceiverDecryptionKey, VerificationPrivateKey)> {
        match self.load(index).await? {
            Some(keys) => Ok(keys),
            None => {
                let sk = ReceiverDecryptionKey::random(&mut OsRng)
                    .context("generate receiver private key")?;
                let vk = VerificationPrivateKey::random(&mut OsRng)
                    .context("generate receiver verification private key")?;
                self.save(index, &sk, &vk)
                    .await
                    .context("save generated private key")?;
                Ok((sk, vk))
            }
        }
    }
}

pub struct AverageTime {
    time: Duration,
    n: u32,
}

impl AverageTime {
    pub fn new() -> Self {
        Self {
            time: Duration::default(),
            n: 0,
        }
    }

    pub fn add(&mut self, time: Duration) {
        self.add_weighted(time, 1)
    }

    pub fn add_weighted(&mut self, time: Duration, w: u32) {
        assert_ne!(w, 0);
        assert!(!time.is_zero());
        self.time = self.time.checked_add(time).unwrap();
        self.n = self.n.checked_add(w).unwrap();
    }

    pub fn average(&self) -> Duration {
        assert_ne!(self.n, 0);
        self.time.checked_div(self.n).unwrap()
    }

    pub fn start_stopwatch(&mut self) -> Stopwatch {
        Stopwatch {
            average: self,
            started_at: Instant::now(),
        }
    }
}

pub struct Stopwatch<'t> {
    average: &'t mut AverageTime,
    started_at: Instant,
}

impl<'t> Stopwatch<'t> {
    pub fn stop_and_save(self) -> Duration {
        self.stop_and_save_weighted(1)
    }

    pub fn stop_and_save_weighted(self, w: u32) -> Duration {
        let took = self.started_at.elapsed();
        self.average.add_weighted(took, w);
        took
    }
}
