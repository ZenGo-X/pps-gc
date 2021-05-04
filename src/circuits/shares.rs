use std::convert::TryInto;
use std::{fmt, ops};

use anyhow::{ensure, Context, Result};
use fancy_garbling::{FancyInput, HasModulus};

use super::byte_array::{ByteArray, BytesBundle, FancyBytesInput};
use super::{INDEX_BYTES, SECURITY_BYTES};

pub struct R<W> {
    pub gb: IndexShare<W>,
    pub ev: IndexShare<W>,
}

impl<W> R<W> {
    pub fn new(garbler: IndexShare<W>, evaluator: IndexShare<W>) -> Self {
        Self {
            gb: garbler,
            ev: evaluator,
        }
    }
}

pub struct LocationShare<W> {
    loc: BytesBundle<W, SECURITY_BYTES>,
}

impl<W> LocationShare<W>
where
    W: Clone + HasModulus,
{
    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(Self {
            loc: input
                .bytes_receive()
                .context("receive evaluator's location")?,
        })
    }

    pub fn encode<F>(circuit: &mut F, loc: &[u8]) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        ensure!(
            loc.len() == SECURITY_BYTES,
            "location share must be {} bytes length",
            SECURITY_BYTES
        );

        let loc: [u8; SECURITY_BYTES] = loc
            .try_into()
            .expect("guaranteed by ensure! statement above");

        Ok(Self {
            loc: circuit
                .bytes_encode(&ByteArray::new(loc))
                .context("encode location")?,
        })
    }
}

impl<W> ops::Deref for LocationShare<W> {
    type Target = BytesBundle<W, SECURITY_BYTES>;

    fn deref(&self) -> &Self::Target {
        &self.loc
    }
}

pub struct IndexShare<W> {
    bundle: BytesBundle<W, INDEX_BYTES>,
}

impl<W> IndexShare<W>
where
    W: Clone + HasModulus,
{
    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(Self {
            bundle: input.bytes_receive().context("receive index")?,
        })
    }

    pub fn encode<F>(circuit: &mut F, share: u16) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(Self {
            bundle: circuit
                .bytes_encode(&ByteArray::new(share.to_be_bytes()))
                .context("encode index")?,
        })
    }
}

impl<W> ops::Deref for IndexShare<W> {
    type Target = BytesBundle<W, INDEX_BYTES>;

    fn deref(&self) -> &Self::Target {
        &self.bundle
    }
}

#[cfg(test)]
mod tests {
    use std::iter;

    use rand::Rng;
    use rand::SeedableRng;

    use fancy_garbling::dummy::Dummy;
    use fancy_garbling::twopac::semihonest::{Evaluator, Garbler};
    use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
    use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

    use super::*;
    use crate::circuits::byte_array::BytesGadgets;

    #[test]
    fn location_share_encode() {
        let mut loc = vec![0u8; SECURITY_BYTES];
        loc[0] = 0b1111_1110;

        let mut circuit = Dummy::new();
        let location_share = LocationShare::encode(&mut circuit, &loc).unwrap();

        let mut wires = location_share.loc.iter();
        assert!(wires
            .by_ref()
            .take(7)
            .all(|b| b.val() == 1 && b.modulus() == 2));
        assert!(wires.all(|b| b.val() == 0 && b.modulus() == 2))
    }

    #[test]
    fn index_share_exchange() {
        let (channel_gb, channel_ev) = unix_channel_pair();
        let handle = std::thread::spawn(move || index_share_exchange_garbler(channel_gb));
        index_share_exchange_evaluator(channel_ev);
        handle.join().unwrap();
    }

    fn index_share_exchange_garbler(channel: UnixChannel) {
        let rng = AesRng::new();
        let mut gb =
            Garbler::<UnixChannel, AesRng, OtSender>::new(channel, rng).expect("garbler init");

        let gb_in = IndexShare::encode(&mut gb, 0xdead).unwrap();
        let ev_in = IndexShare::receive(&mut gb).unwrap();

        let out = gb.bytes_xor(&gb_in.bundle, &ev_in.bundle).unwrap();
        gb.bytes_output(&out).unwrap();
    }

    fn index_share_exchange_evaluator(channel: UnixChannel) {
        let rng = AesRng::new();
        let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng)
            .expect("evaluator init");

        let gb_in = IndexShare::receive(&mut ev).unwrap();
        let ev_in = IndexShare::encode(&mut ev, 0xbeaf).unwrap();

        let out = ev.bytes_xor(&gb_in.bundle, &ev_in.bundle).unwrap();
        let out = ev.bytes_output(&out).unwrap().unwrap();

        assert_eq!(out.as_buffer(), &(0xdead_u16 ^ 0xbeaf_u16).to_be_bytes());
    }

    #[test]
    fn exchange_location_share() {
        let (channel_gb, channel_ev) = unix_channel_pair();
        let handle = std::thread::spawn(move || exchange_location_share_garbler(channel_gb));
        exchange_location_share_evaluator(channel_ev);
        handle.join().unwrap();
    }

    fn exchange_location_share_garbler(channel: UnixChannel) {
        let mut rng = AesRng::seed_from_u64(900);
        let loc_gb: Vec<u8> = iter::repeat_with(|| rng.gen())
            .take(SECURITY_BYTES)
            .collect();

        let mut gb =
            Garbler::<UnixChannel, AesRng, OtSender>::new(channel, rng).expect("garbler init");

        let gb_in = LocationShare::encode(&mut gb, &loc_gb).unwrap();
        let ev_in = LocationShare::receive(&mut gb).unwrap();

        let out = gb.bytes_xor(&gb_in.loc, &ev_in.loc).unwrap();
        gb.bytes_output(&out).unwrap();
    }

    fn exchange_location_share_evaluator(channel: UnixChannel) {
        // first of, we reconstruct garbler input
        let mut rng = AesRng::seed_from_u64(900);
        let loc_gb: Vec<u8> = iter::repeat_with(|| rng.gen())
            .take(SECURITY_BYTES)
            .collect();

        let mut rng = AesRng::seed_from_u64(901);
        let loc_ev: Vec<u8> = iter::repeat_with(|| rng.gen())
            .take(SECURITY_BYTES)
            .collect();

        let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng)
            .expect("evaluator init");

        let gb_in = LocationShare::receive(&mut ev).unwrap();
        let ev_in = LocationShare::encode(&mut ev, &loc_ev).unwrap();

        let out = ev.bytes_xor(&gb_in.loc, &ev_in.loc).unwrap();
        let actual = ev.bytes_output(&out).unwrap().unwrap();

        let expected: Vec<_> = loc_gb.into_iter().zip(loc_ev).map(|(a, b)| a ^ b).collect();

        assert_eq!(&actual.as_buffer()[..], &expected);
    }
}
