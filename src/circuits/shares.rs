use std::{fmt, ops};

use anyhow::{anyhow, ensure, Result};
use fancy_garbling::{BinaryBundle, BinaryGadgets, BundleGadgets, FancyInput, HasModulus, Wire};

use super::utils::{encode_bits, u16_to_bits};
use super::{INDEX_BITS, MOD_2, SECURITY_BITS};

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
    loc: BinaryBundle<W>,
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
                .bin_receive(SECURITY_BITS)
                .map_err(|_e| anyhow!("receive evaluator's location"))?,
        })
    }

    pub fn encode<F>(circuit: &mut F, loc: &[u8]) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        ensure!(
            loc.len() == SECURITY_BITS / 8,
            "location share must be {} bits length",
            SECURITY_BITS
        );

        let mut bits = vec![];
        for byte in loc {
            for bit_i in (0..8).rev() {
                bits.push(((*byte >> bit_i) & 1) == 1)
            }
        }

        Ok(Self {
            loc: encode_bits(circuit, &bits)?,
        })
    }

    // TODO: replace this method, it's ugly
    pub(super) fn decode(output: &[bool]) -> Result<[u8; SECURITY_BITS / 8]> {
        ensure!(output.len() == SECURITY_BITS);
        let mut result = [0u8; SECURITY_BITS / 8];

        let bytes = result.iter_mut().zip(output.chunks(8));
        for (result_byte, bits) in bytes {
            for (_i, bit) in bits.iter().enumerate() {
                *result_byte <<= 1;
                if *bit {
                    *result_byte |= 1;
                }
            }
        }

        Ok(result)
    }
}

impl<W> ops::Deref for LocationShare<W> {
    type Target = BinaryBundle<W>;

    fn deref(&self) -> &Self::Target {
        &self.loc
    }
}

pub struct IndexShare<W> {
    bundle: BinaryBundle<W>,
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
            bundle: input
                .receive_many(&vec![MOD_2; INDEX_BITS])
                .map(BinaryBundle::new)
                .map_err(|e| anyhow!("receive index: {}", e))?,
        })
    }

    pub fn encode<F>(circuit: &mut F, share: u16) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(Self {
            bundle: encode_bits(circuit, &u16_to_bits(share))
                .map_err(|_e| anyhow!("encode index share"))?,
        })
    }
}

impl<W> ops::Deref for IndexShare<W> {
    type Target = BinaryBundle<W>;

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

    #[test]
    fn location_share_encode() {
        let mut loc = vec![0u8; SECURITY_BITS / 8];
        loc[0] = 0b1111_1110;

        let mut circuit = Dummy::new();
        let location_share = LocationShare::encode(&mut circuit, &loc).unwrap();

        let wires = location_share.loc.extract();
        let mut wires = wires.iter();
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

        let out = gb.bin_xor(&gb_in.bundle, &ev_in.bundle).unwrap();
        gb.output_bundle(&out).unwrap();
    }

    fn index_share_exchange_evaluator(channel: UnixChannel) {
        let rng = AesRng::new();
        let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng)
            .expect("evaluator init");

        let gb_in = IndexShare::receive(&mut ev).unwrap();
        let ev_in = IndexShare::encode(&mut ev, 0xbeaf).unwrap();

        let out = ev.bin_xor(&gb_in.bundle, &ev_in.bundle).unwrap();
        let out = ev.output_bundle(&out).unwrap().unwrap();
        let out: Vec<_> = out.into_iter().map(|i| i == 1).collect();

        assert_eq!(&out, &u16_to_bits(0xdead ^ 0xbeaf));
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
            .take(SECURITY_BITS / 8)
            .collect();

        let mut gb =
            Garbler::<UnixChannel, AesRng, OtSender>::new(channel, rng).expect("garbler init");

        let gb_in = LocationShare::encode(&mut gb, &loc_gb).unwrap();
        let ev_in = LocationShare::receive(&mut gb).unwrap();

        let out = gb.bin_xor(&gb_in.loc, &ev_in.loc).unwrap();
        gb.output_bundle(&out).unwrap();
    }

    fn exchange_location_share_evaluator(channel: UnixChannel) {
        // first of, we reconstruct garbler input
        let mut rng = AesRng::seed_from_u64(900);
        let loc_gb: Vec<u8> = iter::repeat_with(|| rng.gen())
            .take(SECURITY_BITS / 8)
            .collect();

        let mut rng = AesRng::seed_from_u64(901);
        let loc_ev: Vec<u8> = iter::repeat_with(|| rng.gen())
            .take(SECURITY_BITS / 8)
            .collect();

        let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng)
            .expect("evaluator init");

        let gb_in = LocationShare::receive(&mut ev).unwrap();
        let ev_in = LocationShare::encode(&mut ev, &loc_ev).unwrap();

        let out = ev.bin_xor(&gb_in.loc, &ev_in.loc).unwrap();
        let out = ev.output_bundle(&out).unwrap().unwrap();
        let actual: Vec<_> = out.into_iter().map(|x| x == 1).collect();
        let actual = LocationShare::<Wire>::decode(&actual).unwrap();

        let expected: Vec<_> = loc_gb.into_iter().zip(loc_ev).map(|(a, b)| a ^ b).collect();

        assert_eq!(&actual[..], &expected);
    }
}
