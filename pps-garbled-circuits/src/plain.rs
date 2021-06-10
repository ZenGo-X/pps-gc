use std::{iter, ops};

use anyhow::{ensure, Result};

use rand::Rng;

use super::byte_array::ByteArray;
use super::consts::{INDEX_BYTES, LOCATION_BYTES};

#[derive(Copy, Clone, Debug, PartialEq)]
pub struct TableSize {
    pub m: usize,
    pub l: usize,
}

// todo: remove const generic
#[derive(PartialEq, Debug, Clone)]
pub struct LocationTable {
    receivers: Box<[ByteArray<LOCATION_BYTES>]>,
    size: TableSize,
}

impl LocationTable {
    pub fn new(table: Box<[ByteArray<LOCATION_BYTES>]>, size: TableSize) -> Result<Self> {
        ensure!(
            table.len() == size.m * size.l,
            "table len={}, expected=m*l={}",
            table.len(),
            size.m * size.l
        );
        Ok(Self {
            receivers: table,
            size,
        })
    }

    pub fn random<R: Rng>(rng: &mut R, size: TableSize) -> Result<Self> {
        ensure!(size.m > 0, "m must be non-zero");
        ensure!(size.l > 0, "l must be non-zero");

        let gen_loc = || {
            let mut random_loc = [0u8; LOCATION_BYTES];
            random_loc.iter_mut().for_each(|b| *b = rng.gen());
            ByteArray::new(random_loc)
        };

        Ok(Self {
            receivers: iter::repeat_with(gen_loc)
                .take(size.m * size.l)
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            size,
        })
    }

    pub fn rows(&self) -> impl Iterator<Item = &[ByteArray<LOCATION_BYTES>]> {
        self.receivers.chunks_exact(self.size.l)
    }

    pub fn size(&self) -> TableSize {
        self.size
    }
}

impl ops::Index<u16> for LocationTable {
    type Output = [ByteArray<LOCATION_BYTES>];
    fn index(&self, receiver: u16) -> &Self::Output {
        let receiver = usize::from(receiver);
        &self.receivers[self.size.l * receiver..self.size.l * (receiver + 1)]
    }
}

#[derive(Clone)]
pub struct IndexColumn {
    column: Box<[ByteArray<INDEX_BYTES>]>,
    m: usize,
}

impl IndexColumn {
    pub fn new(column: Box<[ByteArray<INDEX_BYTES>]>, m: usize) -> Result<Self> {
        ensure!(column.len() == m, "column size doesn't match m");
        Ok(Self { column, m })
    }

    pub fn random<R: Rng>(rng: &mut R, m: usize) -> Result<Self> {
        let column: Vec<_> = iter::repeat_with(|| rng.gen::<u16>())
            .map(|x| x.to_be_bytes().into())
            .take(m)
            .collect();
        Ok(Self {
            column: column.into_boxed_slice(),
            m,
        })
    }

    pub fn receivers(&self) -> impl Iterator<Item = &ByteArray<INDEX_BYTES>> {
        self.column.iter()
    }

    pub fn size(&self) -> usize {
        self.column.len()
    }
}

impl ops::Index<u16> for IndexColumn {
    type Output = ByteArray<INDEX_BYTES>;

    fn index(&self, receiver: u16) -> &Self::Output {
        &self.column[usize::from(receiver)]
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn same_seed_produces_same_table() {
        let rng = StdRng::seed_from_u64(1234);
        let params = TableSize { m: 3, l: 4 };

        let table1 = LocationTable::random(&mut rng.clone(), params).unwrap();
        let table2 = LocationTable::random(&mut rng.clone(), params).unwrap();

        assert_eq!(table1, table2);
    }
}
