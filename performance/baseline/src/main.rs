use std::collections::HashMap;
use std::iter;
use std::num::NonZeroU32;
use std::sync::Arc;

use nonzero_ext::nonzero;
use rand::{
    rngs::SmallRng,
    seq::{index, SliceRandom},
    RngCore, SeedableRng,
};
use rsa::{PublicKey, RsaPrivateKey, RsaPublicKey};

use governor::state::direct::StreamRateLimitExt;
use governor::{Quota, RateLimiter};
use std::time::Instant;
use tokio_stream::{Stream, StreamExt};

const TOTAL_TRANSACTIONS: usize = 1_600_000;
const PRIVATE_TRANSACTIONS: usize = 7_000;
const TRANSACTIONS_ADDRESSED_TO_USER: usize = 30;
const RATE_LIMIT_TX_PER_SECOND: NonZeroU32 = nonzero!(2000u32);

enum Transaction {
    NotInteresting,
    EncryptedSignal(Arc<Box<[u8]>>),
}

fn mocked_blockchain(party_pk: &RsaPublicKey) -> impl Stream<Item = Transaction> {
    let mut rng = SmallRng::from_entropy();
    // Choose position of encrypted signals
    let enc_signals_position: Vec<usize> =
        index::sample(&mut rng, TOTAL_TRANSACTIONS, PRIVATE_TRANSACTIONS).into_vec();
    // Choose position of encrypted signals addressed to this party
    let signals_addressed_to_me =
        enc_signals_position.choose_multiple(&mut rng, TRANSACTIONS_ADDRESSED_TO_USER);

    // Combine above two lists into single hashmap
    let mut enc_signals: HashMap<usize, bool> =
        enc_signals_position.iter().map(|i| (*i, false)).collect();
    for i in signals_addressed_to_me {
        *enc_signals.get_mut(i).unwrap() = true;
    }

    // Generate signals encrypted with party_pk
    let mut signals = iter::repeat_with(|| {
        let mut signal = [0u8; 64];
        rng.fill_bytes(&mut signal[0..32]);
        party_pk
            .encrypt(
                &mut rng,
                rsa::padding::PaddingScheme::OAEP {
                    digest: Box::new(sha2::Sha256::default()),
                    mgf_digest: Box::new(sha2::Sha256::default()),
                    label: None,
                },
                &signal,
            )
            .unwrap()
            .into_boxed_slice()
    })
    .take(TRANSACTIONS_ADDRESSED_TO_USER)
    .collect::<Vec<_>>();

    // Generate a bunch of random bytes that are indistinguishable from signals encrypted with
    // some another_party_pk
    let junk = iter::repeat_with(|| {
        let mut signal = vec![0u8; 100].into_boxed_slice();
        rng.fill_bytes(&mut signal);
        Arc::new(signal)
    })
    .take(200)
    .collect::<Vec<_>>();

    // Construct a stream that yields mocked transactions
    async_stream::stream! {
        for i in 0..TOTAL_TRANSACTIONS {
            match enc_signals.get(&i) {
                Some(true) => yield Transaction::EncryptedSignal(Arc::new(signals.pop().unwrap())),
                Some(false) => yield Transaction::EncryptedSignal(junk.choose(&mut rng).unwrap().clone()),
                None => yield Transaction::NotInteresting,
            }
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Preparation is going...");

    let mut rng = SmallRng::from_entropy();
    let party_sk = RsaPrivateKey::new(&mut rng, 4096).unwrap();
    let party_pk = party_sk.to_public_key();

    let rate_limiter = RateLimiter::direct(Quota::per_second(RATE_LIMIT_TX_PER_SECOND));
    let transactions = mocked_blockchain(&party_pk);
    tokio::pin!(transactions);
    let mut transactions = transactions.ratelimit_stream(&rate_limiter);

    println!("Start scanning blockchain");
    println!();

    let mut received_signals = 0;
    let mut encountered_encrypted_transactions = 0;
    let mut amount_of_scanned_transactions = 0;
    let start = Instant::now();

    loop {
        match transactions.next().await {
            Some(Transaction::EncryptedSignal(signal)) => {
                amount_of_scanned_transactions += 1;
                encountered_encrypted_transactions += 1;

                let decryption_result = party_sk.decrypt(
                    rsa::padding::PaddingScheme::OAEP {
                        digest: Box::new(sha2::Sha256::default()),
                        mgf_digest: Box::new(sha2::Sha256::default()),
                        label: None,
                    },
                    &signal,
                );
                if let Ok(decrypted_signal) = decryption_result {
                    if decrypted_signal.ends_with(&[0u8; 32]) {
                        received_signals += 1;
                    }
                }
            }
            Some(Transaction::NotInteresting) => {
                amount_of_scanned_transactions += 1;
            }
            None => break,
        }
    }
    let took = start.elapsed();

    println!("Blockchain scanning is finished");
    println!(" * Took: {:?}", took);
    println!(
        " * Number of scanned transactions: {}",
        amount_of_scanned_transactions
    );
    println!(
        " * Number of encountered encrypted signals: {}",
        encountered_encrypted_transactions
    );
    println!(" * Number of received signals: {}", received_signals);
}
