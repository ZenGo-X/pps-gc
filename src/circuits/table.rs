use std::convert::{TryFrom, TryInto};
use std::{fmt, iter, mem, ops};

use anyhow::{anyhow, ensure, Context, Result};

use fancy_garbling::{FancyInput, HasModulus};
use rand::{CryptoRng, Rng};

use super::byte_array::ByteArray;
use super::byte_array::{BytesBundle, FancyBytesInput};
use super::{INDEX_BYTES, SECURITY_BYTES};

#[derive(PartialEq, Debug)]
pub struct Table<const M: usize, const L: usize, const N: usize> {
    receivers: Box<[[ByteArray<N>; L]; M]>,
}

impl<const M: usize, const L: usize, const N: usize> Table<M, L, N> {
    pub fn new(r: Box<[[ByteArray<N>; L]; M]>) -> Self {
        Self { receivers: r }
    }

    pub fn random<R: Rng>(rng: &mut R) -> Self {
        let mut table: Vec<[ByteArray<N>; L]> = vec![];
        for _ in 0..M {
            let mut row = vec![];
            for _ in 0..L {
                let mut random_loc = [0u8; N];
                random_loc.iter_mut().for_each(|b| *b = rng.gen());
                row.push(ByteArray::new(random_loc))
            }

            table.push(
                <[ByteArray<N>; L]>::try_from(row)
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
}

impl<const M: usize, const L: usize, const N: usize> ops::Deref for Table<M, L, N> {
    type Target = [[ByteArray<N>; L]; M];

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

pub struct EncodedTable<W, const M: usize, const L: usize, const N: usize> {
    pub encoded: Box<[[BytesBundle<W, N>; L]; M]>,
}

impl<W, const M: usize, const L: usize, const N: usize> EncodedTable<W, M, L, N>
where
    W: Clone + HasModulus,
{
    pub fn encode_table<F>(circuit: &mut F, table: &Table<M, L, N>) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let flat_table = table.receivers.iter().flat_map(|row| row.iter());
        let bundles = circuit
            .bytes_encode_many(flat_table)
            .context("encode the table")?;
        Self::from_flat_bundles(bundles)
    }

    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let bundles = input
            .bytes_receive_many(M * L)
            .context("receive encoded table")?;
        Self::from_flat_bundles(bundles)
    }

    fn from_flat_bundles(mut bundles: Vec<BytesBundle<W, N>>) -> Result<Self> {
        ensure!(
            bundles.len() == M * L,
            "got {} bundles, but expected {}",
            bundles.len(),
            M * L
        );

        let mut table: Vec<[BytesBundle<W, N>; L]> = vec![];
        for _ in 0..M {
            let mut row = bundles.split_off(L);
            mem::swap(&mut bundles, &mut row);
            table.push(
                <[BytesBundle<W, N>; L]>::try_from(row)
                    .map_err(|_| anyhow!("unreachable: we took exactly L items (see split_off)"))?,
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

impl<W, const M: usize> EncodedTable<W, M, 1, INDEX_BYTES>
where
    W: Clone + HasModulus,
{
    pub fn encode_last_upd_table<F>(circuit: &mut F, table: &LastUpdTable<M>) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let flat_table: Vec<_> = table
            .indexes
            .iter()
            .map(|x| ByteArray::new(x.to_be_bytes()))
            .collect();
        let bundles = circuit
            .bytes_encode_many(&flat_table)
            .context("encode the table")?;
        Self::from_flat_bundles(bundles)
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

        let table1 = Table::<3, 4, SECURITY_BYTES>::random(&mut rng1);
        let table2 = Table::<3, 4, SECURITY_BYTES>::random(&mut rng2);

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
