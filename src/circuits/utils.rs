use std::fmt;

use anyhow::{anyhow, Result};
use fancy_garbling::{BinaryBundle, Fancy, FancyInput, HasModulus};

use super::{INDEX_BITS, MOD_2};

pub fn constant_binary_wires<F: Fancy>(
    circuit: &mut F,
    bits: &[bool],
) -> Result<BinaryBundle<F::Item>> {
    let mut wires = vec![];
    for index_bit in bits {
        let bit = u16::from(*index_bit);
        let wire = circuit
            .constant(bit, MOD_2)
            .map_err(|e| anyhow!("convert bit to the wire: {}", e))?;
        wires.push(wire);
    }

    Ok(BinaryBundle::new(wires))
}

pub fn encode_bits<F: FancyInput>(circuit: &mut F, bits: &[bool]) -> Result<BinaryBundle<F::Item>>
where
    F: FancyInput,
    F::Error: fmt::Display,
{
    let bits: Vec<_> = bits.iter().cloned().map(u16::from).collect();
    circuit
        .encode_many(&bits, &vec![MOD_2; bits.len()])
        .map(BinaryBundle::new)
        .map_err(|e| anyhow!("convert bits to input wires: {}", e))
}

pub fn u16_to_bits(mut i: u16) -> [bool; INDEX_BITS] {
    let mut bits = [false; INDEX_BITS];
    for bit in bits.iter_mut() {
        *bit = (i & 1) == 1;
        i >>= 1;
    }
    bits.reverse();
    bits
}

pub fn join3<'a, W, const M: usize, const L: usize>(
    table1: &'a [[BinaryBundle<W>; L]; M],
    table2: &'a [[BinaryBundle<W>; L]; M],
    table3: &'a [[BinaryBundle<W>; L]; M],
) -> impl Iterator<
    Item = impl Iterator<
        Item = (
            &'a BinaryBundle<W>,
            &'a BinaryBundle<W>,
            &'a BinaryBundle<W>,
        ),
    >,
> {
    let joint_rows = table1.iter().zip(table2.iter()).zip(table3.iter());

    joint_rows.map(|((row1, row2), row3)| {
        row1.iter()
            .zip(row2.iter())
            .zip(row3.iter())
            .map(|((item1, item2), item3)| (item1, item2, item3))
    })
}

#[cfg(test)]
mod tests {
    use fancy_garbling::dummy::Dummy;

    use super::*;

    #[test]
    fn u16_to_bits_produces_correct_sequence() {
        let num = 0b_1011_1110_0011_1111_u16;
        let expected = [
            true, false, true, true, true, true, true, false, false, false, true, true, true, true,
            true, true,
        ];

        let actual = u16_to_bits(num);

        assert_eq!(expected, actual);
    }

    #[test]
    fn encode_bits_test() {
        let seq = [true, false, true, true, false];

        let mut circuit = Dummy::new();
        let bundle = encode_bits(&mut circuit, &seq).unwrap();

        assert!(bundle
            .iter()
            .zip(seq.iter())
            .all(|(actual, expected)| (actual.val() == 1) == *expected && actual.modulus() == 2));
    }

    #[test]
    fn constant_binary_wires_test() {
        let seq = [true, false, true, true, false];

        let mut circuit = Dummy::new();
        let bundle = constant_binary_wires(&mut circuit, &seq).unwrap();

        assert!(bundle
            .iter()
            .zip(seq.iter())
            .all(|(actual, expected)| (actual.val() == 1) == *expected && actual.modulus() == 2));
    }
}
