use std::marker::PhantomData;

use anyhow::{ensure, Context};
use fancy_garbling::Fancy;

use crate::byte_array::{ByteArray, BytesBundle, BytesGadgets};
use crate::consts::{INDEX_BYTES, LOCATION_BYTES};
use crate::{plain, TableSize};

pub trait OutputBuilder<F>
where
    F: Fancy,
{
    type Item;
    type Output;
    type Error;

    fn process_next(&mut self, circuit: &mut F, item: &Self::Item) -> Result<(), Self::Error>;
    fn finish(self) -> Result<Self::Output, Self::Error>;
}

pub struct GarblerOutput<const N: usize>(PhantomData<[u8; N]>);

impl<const N: usize> GarblerOutput<N> {
    pub fn new() -> Self {
        Self(PhantomData)
    }
}

impl<F, const N: usize> OutputBuilder<F> for GarblerOutput<N>
where
    F: Fancy,
{
    type Item = BytesBundle<F::Item, N>;
    type Output = ();
    type Error = anyhow::Error;

    fn process_next(&mut self, circuit: &mut F, item: &Self::Item) -> Result<(), Self::Error> {
        circuit.bytes_output(item).map(|_| ())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        Ok(())
    }
}

pub struct LocationTableBuilder {
    flat_table: Vec<ByteArray<LOCATION_BYTES>>,
    size: TableSize,
}

impl LocationTableBuilder {
    pub fn new(size: TableSize) -> Self {
        assert!(
            size.m > 0 && size.l > 0,
            "table dimensions must be positive"
        );
        Self {
            flat_table: Vec::with_capacity(size.m * size.l),
            size,
        }
    }
}

impl<F> OutputBuilder<F> for LocationTableBuilder
where
    F: Fancy,
{
    type Item = BytesBundle<F::Item, LOCATION_BYTES>;
    type Output = plain::LocationTable;
    type Error = anyhow::Error;

    fn process_next(&mut self, circuit: &mut F, item: &Self::Item) -> Result<(), Self::Error> {
        ensure!(
            self.flat_table.len() < self.size.m * self.size.l,
            "all table items were already received"
        );
        let out = circuit
            .bytes_output(&item)
            .context("output item")?
            .context("output produced nothing")?;
        self.flat_table.push(out);
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        ensure!(
            self.flat_table.len() == self.size.m * self.size.l,
            "not enough items were received"
        );
        plain::LocationTable::new(self.flat_table.into_boxed_slice(), self.size)
            .context("construct the table")
    }
}

pub struct IndexColumnBuilder {
    column: Vec<ByteArray<INDEX_BYTES>>,
    size: usize,
}

impl IndexColumnBuilder {
    pub fn new(size: usize) -> Self {
        assert!(size > 0, "column length must be positive");
        Self {
            column: Vec::with_capacity(size),
            size,
        }
    }
}

impl<F> OutputBuilder<F> for IndexColumnBuilder
where
    F: Fancy,
{
    type Item = BytesBundle<F::Item, INDEX_BYTES>;
    type Output = plain::IndexColumn;
    type Error = anyhow::Error;

    fn process_next(&mut self, circuit: &mut F, item: &Self::Item) -> Result<(), Self::Error> {
        ensure!(
            self.column.len() < self.size,
            "all table items were already received"
        );
        let out = circuit
            .bytes_output(&item)
            .context("output item")?
            .context("output produced nothing")?;
        self.column.push(out);
        Ok(())
    }

    fn finish(self) -> Result<Self::Output, Self::Error> {
        ensure!(
            self.column.len() == self.size,
            "not enough items were received"
        );
        plain::IndexColumn::new(self.column.into_boxed_slice(), self.size)
            .context("construct the table")
    }
}
