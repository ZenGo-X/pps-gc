use std::convert::{TryFrom, TryInto};
use std::{fmt, iter, mem, ops};

use anyhow::{anyhow, ensure, Result};

use fancy_garbling::{BinaryBundle, FancyInput, HasModulus};
use rand::{CryptoRng, Rng};

use super::shares::LocationShare;
use super::utils::u16_to_bits;
use super::{INDEX_BITS, MOD_2, SECURITY_BITS};

#[derive(PartialEq, Debug)]
pub struct Table<const M: usize, const L: usize> {
    receivers: Box<[[[bool; SECURITY_BITS]; L]; M]>,
}

impl<const M: usize, const L: usize> Table<M, L> {
    pub fn new(r: Box<[[[bool; SECURITY_BITS]; L]; M]>) -> Self {
        Self { receivers: r }
    }

    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut table = vec![];
        for _ in 0..M {
            let mut row = vec![];
            for _ in 0..L {
                let bits: Vec<bool> = iter::repeat_with(|| rng.gen())
                    .take(SECURITY_BITS)
                    .collect();
                row.push(
                    <[bool; SECURITY_BITS]>::try_from(bits)
                        .expect("unreachable: we generated exactly SECURITY_BITS amount of bits"),
                )
            }

            table.push(
                <[[bool; SECURITY_BITS]; L]>::try_from(row)
                    .expect("unreachable: we generated exactly L items"),
            )
        }

        Self {
            receivers: table
                .into_boxed_slice()
                .try_into()
                .expect("unreachable: we generated exactly M rows"),
        }
    }

    pub fn get(&self, r: u16, i: u16) -> Option<[u8; SECURITY_BITS / 8]> {
        let (r, i) = (usize::from(r), usize::from(i));
        if r >= M || i >= L {
            return None;
        }

        let bits = self[r][i];
        Some(LocationShare::<fancy_garbling::Wire>::decode(&bits).unwrap())
    }
}

impl<const M: usize, const L: usize> ops::Deref for Table<M, L> {
    type Target = [[[bool; SECURITY_BITS]; L]; M];

    fn deref(&self) -> &Self::Target {
        &self.receivers
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct LastUpdTable<const M: usize> {
    indexes: Box<[u16; M]>,
}

impl<const M: usize> LastUpdTable<M> {
    pub fn new(indexes: Box<[u16; M]>) -> Self {
        Self { indexes }
    }

    pub fn random<R>(rng: &mut R) -> Self
    where
        R: Rng + CryptoRng,
    {
        let table: Vec<_> = iter::repeat_with(|| rng.gen()).take(M).collect();
        Self {
            indexes: table
                .into_boxed_slice()
                .try_into()
                .expect("we generated exactly M items"),
        }
    }
}

impl<const M: usize> ops::Deref for LastUpdTable<M> {
    type Target = [u16; M];

    fn deref(&self) -> &Self::Target {
        &self.indexes
    }
}

pub struct EncodedTable<W, const M: usize, const L: usize> {
    pub encoded: Box<[[BinaryBundle<W>; L]; M]>,
}

impl<W, const M: usize, const L: usize> EncodedTable<W, M, L>
where
    W: Clone + HasModulus,
{
    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let wires = input
            .receive_many(&vec![MOD_2; M * L * SECURITY_BITS])
            .map_err(|e| anyhow!("receive encoded table: {}", e))?;
        Self::from_flat_wires(wires, SECURITY_BITS)
    }

    pub fn encode<F>(circuit: &mut F, table: &Table<M, L>) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let mut flat_table = vec![];
        for row in table.receivers.iter() {
            for loc in row.iter() {
                flat_table.extend(loc.iter().cloned().map(u16::from))
            }
        }
        let wires = circuit
            .encode_many(&flat_table, &vec![MOD_2; M * L * SECURITY_BITS])
            .map_err(|e| anyhow!("encode the table: {}", e))?;
        Self::from_flat_wires(wires, SECURITY_BITS)
    }

    fn from_flat_wires(mut wires: Vec<W>, item_size: usize) -> Result<Self> {
        ensure!(
            wires.len() == M * L * item_size,
            "got {} wires, but expected {}",
            wires.len(),
            M * L * item_size
        );

        let mut table = vec![];
        for _ in 0..M {
            let mut row = vec![];
            for _ in 0..L {
                let mut bundle = wires.split_off(item_size);
                mem::swap(&mut bundle, &mut wires);
                row.push(BinaryBundle::new(bundle))
            }
            table.push(
                <[BinaryBundle<W>; L]>::try_from(row)
                    .map_err(|_| anyhow!("unreachable: we received exactly L items"))?,
            )
        }
        Ok(Self {
            encoded: table
                .into_boxed_slice()
                .try_into()
                .map_err(|_| anyhow!("unreachable: we received exactly M rows"))?,
        })
    }
}

impl<W, const M: usize> EncodedTable<W, M, 1>
where
    W: Clone + HasModulus,
{
    pub fn receive_last_upd_table<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let wires = input
            .receive_many(&vec![MOD_2; M * INDEX_BITS])
            .map_err(|e| anyhow!("receive encoded table: {}", e))?;
        Self::from_flat_wires(wires, INDEX_BITS)
    }

    pub fn encode_last_upd_table<F>(circuit: &mut F, table: &LastUpdTable<M>) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let mut flat_table = vec![];
        for row in table.indexes.iter() {
            flat_table.extend(u16_to_bits(*row).iter().cloned().map(u16::from))
        }
        let wires = circuit
            .encode_many(&flat_table, &vec![MOD_2; M * INDEX_BITS])
            .map_err(|e| anyhow!("encode the table: {}", e))?;
        Self::from_flat_wires(wires, INDEX_BITS)
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn same_seed_produces_same_table() {
        let mut rng1 = StdRng::seed_from_u64(1234);
        let mut rng2 = rng1.clone();

        let table1 = Table::<3, 4>::random(&mut rng1);
        let table2 = Table::<3, 4>::random(&mut rng2);

        assert_eq!(table1, table2);
    }

    #[test]
    fn same_seed_produces_same_last_upd_table() {
        let mut rng1 = StdRng::seed_from_u64(98);
        let mut rng2 = rng1.clone();

        let table1 = LastUpdTable::<3>::random(&mut rng1);
        let table2 = LastUpdTable::<3>::random(&mut rng2);

        assert_eq!(table1, table2);
    }
}
