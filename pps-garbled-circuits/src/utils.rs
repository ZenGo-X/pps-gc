use rand::rngs::OsRng;
use rand::{Rng, SeedableRng};

use fancy_garbling::twopac::semihonest::{Evaluator, Garbler};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

impl<I> IteratorExt for I where I: Iterator + Sized {}

pub trait IteratorExt: Iterator + Sized {
    fn enumerate_u16(self) -> EnumerateU16<Self> {
        EnumerateU16(0, self)
    }
}

pub struct EnumerateU16<I>(u16, I);

impl<I> Iterator for EnumerateU16<I>
where
    I: Iterator,
{
    type Item = (u16, I::Item);
    fn next(&mut self) -> Option<Self::Item> {
        let nxt = self.1.next()?;
        let i = self.0;
        self.0 += 1;
        Some((i, nxt))
    }
}

pub struct TwopacTest<G, E> {
    garbler: G,
    evaluator: E,
}

impl TwopacTest<(), ()> {
    pub fn new() -> Self {
        Self {
            garbler: (),
            evaluator: (),
        }
    }
}

impl<E> TwopacTest<(), E> {
    pub fn set_garbler<F>(self, garbler: F) -> TwopacTest<F, E>
    where
        F: FnOnce(&mut Garbler<UnixChannel, AesRng, OtSender>),
    {
        TwopacTest {
            garbler,
            evaluator: self.evaluator,
        }
    }
}

impl<G> TwopacTest<G, ()> {
    pub fn set_evaluator<F>(self, evaluator: F) -> TwopacTest<G, F>
    where
        F: FnOnce(&mut Evaluator<UnixChannel, AesRng, OtReceiver>),
    {
        TwopacTest {
            garbler: self.garbler,
            evaluator,
        }
    }
}

impl<G, E> TwopacTest<G, E>
where
    G: FnOnce(&mut Garbler<UnixChannel, AesRng, OtSender>) + Send + 'static,
    E: FnOnce(&mut Evaluator<UnixChannel, AesRng, OtReceiver>),
{
    pub fn run(self) {
        let Self {
            garbler: garbler_fn,
            evaluator: evaluator_fn,
        } = self;
        let (channel_a, channel_b) = unix_channel_pair();

        let seed1 = OsRng.gen::<u64>();
        let seed2 = OsRng.gen::<u64>();

        eprintln!("Garbler seed = {}, evaluator seed = {}", seed1, seed2);
        let rng1 = AesRng::seed_from_u64(seed1);
        let rng2 = AesRng::seed_from_u64(seed2);

        let handle = std::thread::spawn(move || {
            let mut garbler = Garbler::<_, _, OtSender>::new(channel_a, rng1).unwrap();
            garbler_fn(&mut garbler)
        });

        let mut evaluator = Evaluator::<_, _, OtReceiver>::new(channel_b, rng2).unwrap();
        evaluator_fn(&mut evaluator);
        handle.join().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use fancy_garbling::{Fancy, FancyInput};

    use crate::byte_array::{ByteArray, BytesGadgets, FancyBytesInput};

    use super::TwopacTest;

    #[test]
    fn xor_two_byte_bundles() {
        TwopacTest::new()
            .set_garbler(|g| xor_two_byte_bundles_circuit(g, true))
            .set_evaluator(|e| xor_two_byte_bundles_circuit(e, false))
            .run()
    }

    fn xor_two_byte_bundles_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let a = ByteArray::new(1234u16.to_be_bytes());
        let b = ByteArray::new(5678u16.to_be_bytes());

        let a_encoded = if is_garbler {
            circuit.bytes_encode(&a).unwrap()
        } else {
            circuit.bytes_receive().unwrap()
        };
        let b_encoded = if is_garbler {
            circuit.bytes_receive().unwrap()
        } else {
            circuit.bytes_encode(&b).unwrap()
        };

        let out = circuit.bytes_xor(&a_encoded, &b_encoded).unwrap();
        let out = circuit.bytes_output(&out).unwrap();
        if is_garbler {
            return;
        }

        assert_eq!(out.unwrap(), a ^ b);
    }
}
