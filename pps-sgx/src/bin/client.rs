use std::io;
use std::path::{Path, PathBuf};

use curv::cryptographic_primitives::twoparty::dh_key_exchange as dh;
use curv::elliptic::curves::secp256_k1::GE;
use pps_sgx::crypto::*;
use rand::rngs::OsRng;

use pps_sgx::proto::pps::signalling_api_client::SignallingApiClient;
use pps_sgx::proto::pps::*;
use pps_sgx::proto::response::{AttestResponse, GetMetricsResponse};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tonic::transport::Channel;

use anyhow::{bail, ensure, Context};
use serde::{Deserialize, Serialize};
use structopt::StructOpt;

#[derive(StructOpt, Debug)]
struct Cli {
    /// SGX server address
    #[structopt(long, default_value = "http://localhost:4210", env = "ENDPOINT")]
    address: String,

    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(StructOpt, Debug)]
enum Cmd {
    /// Registers new receiver
    Register(ReceiverSecretsPath),
    /// Receive signals
    Receive(ReceiverSecretsPath),
    /// Retrieves base64 encoded receiver's public key
    GetPk(ReceiverSecretsPath),

    /// Sends signal to receiver
    Send(SendArgs),
}

#[derive(StructOpt, Debug)]
struct ReceiverSecretsPath {
    /// File containing receiver client keys
    #[structopt(long = "keys-file", default_value = "./secret-keys.json")]
    path: PathBuf,
}

#[derive(StructOpt, Debug)]
struct SendArgs {
    /// Base64 encoded receiver's public key
    #[structopt(short, long, default_value = "./receiver.der")]
    receiver_path: PathBuf,
    /// Hex encoded location. Must be exactly 32 bytes.
    #[structopt(short, long)]
    location: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Cli = StructOpt::from_args();

    let cmd = match args.cmd {
        Cmd::GetPk(file) => return get_pk(file).await,
        cmd => cmd,
    };

    let client = SignallingApiClient::connect(args.address).await?;
    println!("PPS Server: Connection established");
    println!();

    match cmd {
        Cmd::Register(file) => register(client, file).await?,
        Cmd::Receive(file) => receive(client, file).await?,
        Cmd::Send(args) => send(client, args).await?,
        Cmd::GetPk(_) => unreachable!(),
    }

    Ok(())
}

async fn register(
    mut client: SignallingApiClient<Channel>,
    file: ReceiverSecretsPath,
) -> anyhow::Result<()> {
    let result = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&file.path)
        .await;
    let mut file = match result {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            bail!("file already exists")
        }
        Err(e) => return Err(e).context("create secrets file"),
    };

    let server_attestation_pk = client
        .get_pk(GetPkRequest {})
        .await
        .context("get pk request")?
        .into_inner();
    let attestation_pk: MockedEnclavePublicMasterKey =
        serde_json::from_slice(&server_attestation_pk.public_key).context("read attestation pk")?;
    println!("Attestation key: Retrieved");
    println!();

    let (msg, local_secret) = dh::Party1FirstMessage::<GE>::first();
    let msg = serde_json::to_vec(&msg).context("serialize ga")?;

    println!("Registration[1/2]: KeyExchange");
    let response = client
        .key_exchange(KeyExchangeRequest { ga: msg.clone() })
        .await
        .context("key exchange request")?;
    println!(" └ completed!");
    let took = response.get_took_time().context("get took-time")?;
    println!(" └ took: {}", took);
    response.attest(&attestation_pk).context("attestation")?;
    println!(" └ attestation: passed");
    println!();

    let KeyExchangeResponse { id, ga, gb } = response.into_inner();
    ensure!(ga == msg, "`ga` was modified");

    let gb: dh::Party2FirstMessage<GE> = serde_json::from_slice(&gb).context("read gb")?;

    let setup_key = SetupEncryptionKey::from_handshake(&local_secret, &gb.public_share)
        .context("derive setup encryption key")?;

    let sk = ReceiverDecryptionKey::random(&mut OsRng).context("generate sk")?;
    let pk = sk.encryption_key();
    let vk = VerificationPrivateKey::random(&mut OsRng).context("generate vk")?;
    let vk_pub = vk.public_key();

    let setup_msg = SetupMsg {
        sk: sk.clone(),
        vk: vk_pub,
    };
    let encrypted_setup_msg = setup_key.encrypt(setup_msg).context("encrypt setup msg")?;

    println!("Registration[2/2]: Setup");
    let response = client
        .setup(SetupRequest {
            id,
            encrypted_key: encrypted_setup_msg.bytes,
        })
        .await
        .context("setup request")?;
    println!(" └ completed!");
    let took = response.get_took_time().context("get took-time")?;
    println!(" └ took: {}", took);
    response.attest(&attestation_pk).context("attestation")?;
    println!(" └ attestation: passed");
    println!();

    let responded_pk: ReceiverEncryptionKey =
        serde_json::from_slice(&response.get_ref().public_key).context("read pk")?;
    ensure!(responded_pk == pk, "responded pk doesn't match sent pk!");

    ReceiverSecretsFile {
        id,
        sk,
        pk,
        vk,
        ctr: 0,
        attestation_key: attestation_pk,
    }
    .save_to_file(&mut file)
    .await
    .context("save secrets")?;

    Ok(())
}

async fn receive(
    mut client: SignallingApiClient<Channel>,
    file: ReceiverSecretsPath,
) -> anyhow::Result<()> {
    let mut secrets = ReceiverSecretsFile::read(&file.path)
        .await
        .context("read secrets")?;
    let ctr = secrets.ctr;
    let signature = secrets.vk.sign(ctr).context("sign ctr")?;

    println!("Receiving signals...");
    let response = client
        .receive(ReceiveRequest {
            id: secrets.id,
            ctr,
            signature: signature.bytes,
        })
        .await
        .context("`receive` request")?;
    println!(" └ completed!");
    let took = response.get_took_time().context("get took-time")?;
    println!(" └ took: {}", took);
    response
        .attest(&secrets.attestation_key)
        .context("attestation")?;
    println!(" └ attestation: passed");
    println!();

    secrets.ctr += 1;
    secrets.save_to(&file.path).await.context("save secrets")?;

    println!("Received signals:");
    let mut counter = 0;
    for signal in response.into_inner().encrypted_row {
        let decrypted = secrets
            .sk
            .decrypt(&ReceiverEncryptedLocation { ciphertext: signal })
            .context("decrypt signal")?;
        if decrypted.as_ref() == &[0u8; 32] {
            continue;
        }
        println!("{}", hex::encode(decrypted.as_ref()));
        counter += 1;
    }
    println!();
    println!("-- {} signals received", counter);
    println!();

    Ok(())
}

async fn send(mut client: SignallingApiClient<Channel>, args: SendArgs) -> anyhow::Result<()> {
    let receiver_pk = fs::read(args.receiver_path)
        .await
        .context("read receiver pk")?;
    let receiver_pk =
        String::from_utf8(receiver_pk).context("invalid receiver pk - not a string")?;
    let receiver_pk = ReceiverEncryptionKey::from_pkcs8(receiver_pk.trim())
        .context("parse receiver's public key")?;

    let location = hex::decode(args.location).context("parse hex-encoded location")?;
    ensure!(
        location.len() == 32,
        "wrong location length: expected 32, got {}",
        location.len()
    );
    let location = Location::new(location);

    let encrypted_location = receiver_pk
        .encrypt(&mut OsRng, location)
        .context("encrypt location")?;

    println!("Sending...");
    let response = client
        .send(SendRequest {
            encrypted_signal: encrypted_location.ciphertext,
        })
        .await
        .context("`send` request")?;
    println!(" └ completed!");
    let took = response.get_took_time().context("get took-time")?;
    println!(" └ took: {}", took);
    println!(" └ attestation: skipped");
    println!();

    Ok(())
}

async fn get_pk(file: ReceiverSecretsPath) -> anyhow::Result<()> {
    let file = ReceiverSecretsFile::read(&file.path)
        .await
        .context("open file")?;
    let pk = file.pk.to_pkcs8().context("serialize")?;
    println!("{}", pk);
    Ok(())
}

#[derive(Serialize, Deserialize, Debug)]
struct ReceiverSecretsFile {
    id: u64,
    sk: ReceiverDecryptionKey,
    pk: ReceiverEncryptionKey,
    vk: VerificationPrivateKey,
    ctr: u64,
    attestation_key: MockedEnclavePublicMasterKey,
}

impl ReceiverSecretsFile {
    pub async fn save_to_file(&self, file: &mut fs::File) -> anyhow::Result<()> {
        let serialized = serde_json::to_vec_pretty(self).context("serialize secrets")?;
        file.write_all(&serialized).await.context("write secrets")
    }

    pub async fn save_to(&self, path: impl AsRef<Path>) -> anyhow::Result<()> {
        let serialized = serde_json::to_vec_pretty(self).context("serialize secrets")?;
        fs::write(path, &serialized).await.context("write secrets")
    }

    pub async fn read(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let bytes = fs::read(path).await.context("read file")?;
        serde_json::from_slice(&bytes).context("parse secrets")
    }
}
