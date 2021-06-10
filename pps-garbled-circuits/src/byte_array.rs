use std::convert::TryInto;
use std::iter::ExactSizeIterator;

use anyhow::{anyhow, ensure};

use fancy_garbling::{BinaryBundle, BinaryGadgets, BundleGadgets, Fancy, FancyInput};
use itertools::Itertools;

pub type ByteArray<const N: usize> = bitvec::array::BitArray<bitvec::order::Msb0, [u8; N]>;

#[derive(Clone)]
struct ByteBundle<W> {
    bits: [W; 8],
}

#[derive(Clone)]
pub struct BytesBundle<W, const N: usize> {
    bytes: [ByteBundle<W>; N],
}

impl<W, const N: usize> BytesBundle<W, N>
where
    W: Clone,
{
    pub fn from_wires(wires: &[W]) -> anyhow::Result<Self> {
        ensure!(
            wires.len() == N * 8,
            "expected to have {} wires, got {}",
            N * 8,
            wires.len()
        );

        let bytes: Vec<ByteBundle<W>> = wires
            .array_chunks::<8>()
            .map(|bits| ByteBundle { bits: bits.clone() })
            .collect();

        bytes
            .try_into()
            .map(|bytes| BytesBundle { bytes })
            .map_err(|_| anyhow!("unreachable: there were exactly N bytes (see ensure! macro)"))
    }
}

impl<W, const N: usize> BytesBundle<W, N> {
    pub fn iter(&self) -> impl Iterator<Item = &W> {
        self.bytes.iter().map(|byte| byte.bits.iter()).flatten()
    }
}

impl<F> BytesGadgets for F where F: Fancy {}

pub trait BytesGadgets: Fancy + Sized {
    fn bytes_constant<const N: usize>(
        &mut self,
        x: &ByteArray<N>,
    ) -> anyhow::Result<BytesBundle<Self::Item, N>> {
        let bits: Vec<_> = x
            .iter()
            .map(|x| u16::from(*x))
            .map(|x| self.constant(x, 2))
            .try_collect()
            .map_err(|e| anyhow!("construct constant wire: {}", e))?;
        BytesBundle::<Self::Item, N>::from_wires(&bits)
    }

    fn bytes_xor<const N: usize>(
        &mut self,
        x: &BytesBundle<Self::Item, N>,
        y: &BytesBundle<Self::Item, N>,
    ) -> anyhow::Result<BytesBundle<Self::Item, N>> {
        let wires: Vec<_> = x
            .iter()
            .zip(y.iter())
            .map(|(a, b)| self.xor(a, b))
            .try_collect()
            .map_err(|e| anyhow!("construct a xor wire: {}", e))?;
        BytesBundle::<Self::Item, N>::from_wires(&wires)
    }

    fn bytes_output<const N: usize>(
        &mut self,
        x: &BytesBundle<Self::Item, N>,
    ) -> anyhow::Result<Option<ByteArray<N>>> {
        let bits: Vec<Option<u16>> = x
            .iter()
            .map(|wire| self.output(wire))
            .try_collect()
            .map_err(|e| anyhow!("construct output wire: {}", e))?;
        let bits: Option<Vec<u16>> = bits.into_iter().collect();
        let bits = match bits {
            Some(bits) => bits,
            None => return Ok(None),
        };
        byte_array_from_bits::<_, N>(bits.into_iter().map(|x| x != 0)).map(Some)
    }

    fn bytes_output_many<'a, I, const N: usize>(
        &mut self,
        x: I,
    ) -> anyhow::Result<Option<Vec<ByteArray<N>>>>
    where
        Self::Item: 'a,
        I: IntoIterator<Item = &'a BytesBundle<Self::Item, N>>,
    {
        Ok(x.into_iter()
            .map(|x| self.bytes_output(x))
            .collect::<anyhow::Result<Vec<Option<_>>>>()?
            .into_iter()
            .collect())
    }

    /// If b=0 then return x, else return y.
    fn bytes_mux<const N: usize>(
        &mut self,
        x: &Self::Item,
        a: &BytesBundle<Self::Item, N>,
        b: &BytesBundle<Self::Item, N>,
    ) -> anyhow::Result<BytesBundle<Self::Item, N>> {
        let wires: Vec<_> = a
            .iter()
            .zip(b.iter())
            .map(|(bit_a, bit_b)| self.mux(x, bit_a, bit_b))
            .try_collect()
            .map_err(|e| anyhow!("construct a mux wire: {}", e))?;
        BytesBundle::<_, N>::from_wires(&wires)
    }

    fn bytes_eq<const N: usize>(
        &mut self,
        a: &BytesBundle<Self::Item, N>,
        b: &BytesBundle<Self::Item, N>,
    ) -> anyhow::Result<Self::Item> {
        let wires_a = a.iter().cloned().collect();
        let wires_b = b.iter().cloned().collect();
        self.eq_bundles(&BinaryBundle::new(wires_a), &BinaryBundle::new(wires_b))
            .map_err(|e| anyhow!("construct eq wire: {}", e))
    }

    fn bytes_add<const N: usize>(
        &mut self,
        a: &BytesBundle<Self::Item, N>,
        b: &BytesBundle<Self::Item, N>,
    ) -> anyhow::Result<(BytesBundle<Self::Item, N>, Self::Item)> {
        let mut wires_a: Vec<_> = a.iter().cloned().collect();
        let mut wires_b: Vec<_> = b.iter().cloned().collect();
        wires_a.reverse();
        wires_b.reverse();

        let a = BinaryBundle::new(wires_a);
        let b = BinaryBundle::new(wires_b);
        let (result, c) = self
            .bin_addition(&a, &b)
            .map_err(|e| anyhow!("construct addition wires: {}", e))?;
        let result_wires: Vec<_> = result.extract().iter().rev().cloned().collect();
        Ok((BytesBundle::from_wires(&result_wires)?, c))
    }
}

impl<F> FancyBytesInput for F
where
    F: FancyInput,
    F::Error: std::fmt::Display,
{
}

pub trait FancyBytesInput: FancyInput
where
    Self::Error: std::fmt::Display,
{
    fn bytes_encode<const N: usize>(
        &mut self,
        bytes: &ByteArray<N>,
    ) -> anyhow::Result<BytesBundle<Self::Item, N>> {
        debug_assert_eq!(bytes.len(), N * 8);
        let bits: Vec<_> = bytes.iter().map(|i| u16::from(*i)).collect();
        self.encode_many(&bits, &vec![2; N * 8])
            .map(|wires| BytesBundle::<Self::Item, N>::from_wires(&wires))
            .map_err(|e| anyhow!("encoding byte array: {}", e))?
    }
    fn bytes_encode_many<'a, I, const N: usize>(
        &mut self,
        v: I,
    ) -> anyhow::Result<Vec<BytesBundle<Self::Item, N>>>
    where
        I: IntoIterator<Item = &'a ByteArray<N>>,
    {
        let bits: Vec<_> = v
            .into_iter()
            .flat_map(|bytes| bytes.iter())
            .map(|i| u16::from(*i))
            .collect();
        let wires = self
            .encode_many(&bits, &vec![2; bits.len()])
            .map_err(|e| anyhow!("encoding byte array: {}", e))?;

        let result: Vec<_> = wires
            .chunks_exact(N * 8)
            .map(BytesBundle::<Self::Item, N>::from_wires)
            .try_collect()?;

        Ok(result)
    }
    fn bytes_receive<const N: usize>(&mut self) -> anyhow::Result<BytesBundle<Self::Item, N>> {
        self.receive_many(&vec![2; N * 8])
            .map(|wires| BytesBundle::<Self::Item, N>::from_wires(&wires))
            .map_err(|e| anyhow!("receive counterparty inputs: {}", e))?
    }
    fn bytes_receive_many<const N: usize>(
        &mut self,
        amount: usize,
    ) -> anyhow::Result<Vec<BytesBundle<Self::Item, N>>> {
        let wires = self
            .receive_many(&vec![2; N * 8 * amount])
            .map_err(|e| anyhow!("receive wires: {}", e))?;

        let result: Vec<_> = wires
            .chunks_exact(N * 8)
            .map(BytesBundle::<Self::Item, N>::from_wires)
            .try_collect()?;

        Ok(result)
    }
}

fn byte_array_from_bits<I, const N: usize>(mut bits: I) -> anyhow::Result<ByteArray<N>>
where
    I: Iterator<Item = bool> + ExactSizeIterator,
{
    ensure!(
        bits.len() == N * 8,
        "byte array with fixed size of {} bytes cannot be constructed from {} bits",
        N,
        bits.len()
    );

    let bits = &mut bits;
    let mut bytes = vec![];
    for _ in 0..N {
        let bits = bits.take(8);
        let byte = bits.fold(0u8, |n, bit| (n << 1) | u8::from(bit));
        bytes.push(byte);
    }

    bytes
        .try_into()
        .map(|bytes: [u8; N]| ByteArray::from(bytes))
        .map_err(|_| {
            anyhow!("unreachable: we processed exactly N bytes (see ensure! and the loop)")
        })
}

#[cfg(test)]
mod tests {
    use std::fmt;

    use fancy_garbling::dummy::Dummy;

    use super::*;
    use crate::utils::TwopacTest;

    #[test]
    fn bitvec_iter() {
        let a = [0b1011_1001u8];
        let bits: Vec<bool> = ByteArray::<1>::from(a).iter().map(|x| *x).collect();
        assert_eq!(
            bits,
            vec![true, false, true, true, true, false, false, true]
        );
    }

    #[test]
    fn encode_byte_array() {
        let mut dummy = Dummy::new();
        let arr = [1, 2, 3, 45, 255];
        let arr = ByteArray::from(arr);

        let encoded = dummy.bytes_encode(&arr).unwrap();
        let actual = dummy.bytes_output(&encoded).unwrap().unwrap();
        assert_eq!(actual, arr);
    }

    #[test]
    fn encode_many() {
        let a = 0x1111_u16.to_be_bytes().into();
        let b = 0x2222_u16.to_be_bytes().into();
        let c = 0x3333_u16.to_be_bytes().into();

        let mut dummy = Dummy::new();
        let encoded = dummy.bytes_encode_many(&[a, b, c]).unwrap();
        let actual = dummy.bytes_output_many(&encoded).unwrap().unwrap();

        assert_eq!(actual, &[a, b, c]);
    }

    #[test]
    fn encode_and_receive() {
        TwopacTest::new()
            .set_garbler(|circuit| encode_and_receive_circuit(circuit, true))
            .set_evaluator(|circuit| encode_and_receive_circuit(circuit, false))
            .run()
    }

    fn encode_and_receive_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let a = 0x1111_u16.to_be_bytes().into();
        let b = 0x2222_u16.to_be_bytes().into();

        let gb_in = if is_garbler {
            circuit.bytes_encode(&a).unwrap()
        } else {
            circuit.bytes_receive().unwrap()
        };
        let ev_in = if is_garbler {
            circuit.bytes_receive().unwrap()
        } else {
            circuit.bytes_encode(&b).unwrap()
        };

        let out = circuit.bytes_xor(&gb_in, &ev_in).unwrap();
        let actual = circuit.bytes_output(&out).unwrap();
        if is_garbler {
            return;
        }

        let expected = (0x1111_u16 ^ 0x2222_u16).to_be_bytes();
        assert_eq!(actual.unwrap().as_buffer(), &expected);
    }

    #[test]
    fn encode_many_and_receive() {
        TwopacTest::new()
            .set_garbler(|circuit| encode_many_and_receive_circuit(circuit, true))
            .set_evaluator(|circuit| encode_many_and_receive_circuit(circuit, false))
            .run()
    }

    fn encode_many_and_receive_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let gb_in = &[
            0x1111_u16.to_be_bytes().into(),
            0x2222_u16.to_be_bytes().into(),
            0x3333_u16.to_be_bytes().into(),
        ];
        let ev_in = &[
            0x4444_u16.to_be_bytes().into(),
            0x5555_u16.to_be_bytes().into(),
            0x6666_u16.to_be_bytes().into(),
        ];

        let gb_in = if is_garbler {
            circuit.bytes_encode_many(gb_in).unwrap()
        } else {
            circuit.bytes_receive_many(3).unwrap()
        };
        let ev_in = if is_garbler {
            circuit.bytes_receive_many(3).unwrap()
        } else {
            circuit.bytes_encode_many(ev_in).unwrap()
        };

        let out: Vec<_> = gb_in
            .iter()
            .zip(&ev_in)
            .map(|(a, b)| circuit.bytes_xor(a, b))
            .try_collect()
            .unwrap();
        let actual = circuit.bytes_output_many(&out).unwrap();
        if is_garbler {
            return;
        }

        let expected = &[
            ByteArray::new((0x1111_u16 ^ 0x4444_u16).to_be_bytes()),
            ByteArray::new((0x2222_u16 ^ 0x5555_u16).to_be_bytes()),
            ByteArray::new((0x3333_u16 ^ 0x6666_u16).to_be_bytes()),
        ];

        assert_eq!(&actual.unwrap(), expected);
    }

    #[test]
    fn constant_byte_array() {
        let mut dummy = Dummy::new();
        let arr = [1, 2, 3, 45, 255];
        let arr = ByteArray::from(arr);

        let encoded = dummy.bytes_constant(&arr).unwrap();
        let actual = dummy.bytes_output(&encoded).unwrap().unwrap();
        assert_eq!(actual, arr);
    }

    #[test]
    fn xor() {
        let a: u16 = 0x74a9;
        let b: u16 = 0xda50;

        let mut dummy = Dummy::new();

        let a_bytes = a.to_be_bytes();
        let a_encoded = dummy.bytes_encode(&ByteArray::from(a_bytes)).unwrap();
        let b_bytes = b.to_be_bytes();
        let b_encoded = dummy.bytes_encode(&ByteArray::from(b_bytes)).unwrap();

        let out = dummy.bytes_xor(&a_encoded, &b_encoded).unwrap();
        let output = dummy.bytes_output(&out).unwrap().unwrap();

        assert_eq!(output.as_buffer(), &(a ^ b).to_be_bytes());
    }

    #[test]
    fn mux() {
        let a: u16 = 0x1111;
        let b: u16 = 0x2222;

        let mut dummy = Dummy::new();

        let condition = dummy.constant(1, 2).unwrap();

        let a_bytes = a.to_be_bytes();
        let a_encoded = dummy.bytes_encode(&ByteArray::from(a_bytes)).unwrap();
        let b_bytes = b.to_be_bytes();
        let b_encoded = dummy.bytes_encode(&ByteArray::from(b_bytes)).unwrap();

        let out = dummy.bytes_mux(&condition, &a_encoded, &b_encoded).unwrap();
        let output = dummy.bytes_output(&out).unwrap().unwrap();

        assert_eq!(output.as_buffer(), &b_bytes);
    }

    #[test]
    fn eq() {
        let a: u16 = 0x1111;
        let b: u16 = 0x2222;

        let mut dummy = Dummy::new();

        let a_bytes = a.to_be_bytes();
        let a_encoded = dummy.bytes_encode(&ByteArray::from(a_bytes)).unwrap();
        let a_encoded2 = dummy.bytes_encode(&ByteArray::from(a_bytes)).unwrap();
        let b_bytes = b.to_be_bytes();
        let b_encoded = dummy.bytes_encode(&ByteArray::from(b_bytes)).unwrap();

        let out1 = dummy.bytes_eq(&a_encoded, &b_encoded).unwrap();
        let output1 = dummy.output(&out1).unwrap().unwrap();
        let out2 = dummy.bytes_eq(&a_encoded, &a_encoded2).unwrap();
        let output2 = dummy.output(&out2).unwrap().unwrap();

        assert_eq!(output1, 0);
        assert_eq!(output2, 1);
    }

    #[test]
    fn add() {
        let a: u16 = 100;
        let b: u16 = 13;
        let mut dummy = Dummy::new();

        let a_bytes = a.to_be_bytes();
        let a_encoded = dummy.bytes_encode(&ByteArray::from(a_bytes)).unwrap();
        let b_bytes = b.to_be_bytes();
        let b_encoded = dummy.bytes_encode(&ByteArray::from(b_bytes)).unwrap();

        let (out, c) = dummy.bytes_add(&a_encoded, &b_encoded).unwrap();
        let output = dummy.bytes_output(&out).unwrap().unwrap();
        let output_c = dummy.output(&c).unwrap().unwrap();

        assert_eq!(output.as_buffer(), &(a + b).to_be_bytes());
        assert_eq!(output_c, 0);
    }

    #[test]
    fn add_overflowing() {
        let a: u8 = 255;
        let b: u8 = 3;
        let mut dummy = Dummy::new();

        let a_bytes = a.to_be_bytes();
        let a_encoded = dummy.bytes_encode(&ByteArray::from(a_bytes)).unwrap();
        let b_bytes = b.to_be_bytes();
        let b_encoded = dummy.bytes_encode(&ByteArray::from(b_bytes)).unwrap();

        let (out, c) = dummy.bytes_add(&a_encoded, &b_encoded).unwrap();
        let output = dummy.bytes_output(&out).unwrap().unwrap();
        let output_c = dummy.output(&c).unwrap().unwrap();

        assert_eq!(output.as_buffer(), &2_u8.to_be_bytes());
        assert_eq!(output_c, 1);
    }
}
