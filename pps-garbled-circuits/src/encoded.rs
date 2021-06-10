use std::convert::TryInto;
use std::marker::PhantomData;
use std::{fmt, ops};

use anyhow::{ensure, Context, Result};
use fancy_garbling::FancyInput;
use rand::{CryptoRng, Rng};

use super::byte_array::BytesBundle;
use super::consts::{INDEX_BYTES, LOCATION_BYTES};
use super::plain::{self, TableSize};
use crate::byte_array::{ByteArray, FancyBytesInput};

pub struct LocationTable<W> {
    encoded: Box<[BytesBundle<W, LOCATION_BYTES>]>,
    size: TableSize,
}

impl<W> LocationTable<W> {
    pub fn new(encoded: Box<[BytesBundle<W, LOCATION_BYTES>]>, size: TableSize) -> Result<Self> {
        ensure!(
            encoded.len() == size.m * size.l,
            "encoded table doesn't match size"
        );
        Ok(Self { encoded, size })
    }
    pub fn encode<F>(circuit: &mut F, table: &plain::LocationTable) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let bundles = circuit
            .bytes_encode_many(table.rows().flat_map(|row| row.iter()))
            .context("encode the table")?;
        Ok(Self {
            encoded: bundles.into_boxed_slice(),
            size: table.size(),
        })
    }

    pub fn receive<F>(input: &mut F, size: TableSize) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let bundles = input
            .bytes_receive_many(size.m * size.l)
            .context("receive encoded table")?;
        Ok(Self {
            encoded: bundles.into_boxed_slice(),
            size,
        })
    }

    pub fn rows(&self) -> impl Iterator<Item = &[BytesBundle<W, LOCATION_BYTES>]> {
        self.encoded.chunks_exact(self.size.l)
    }

    pub fn size(&self) -> TableSize {
        self.size
    }
}

impl<W> ops::Index<u16> for LocationTable<W> {
    type Output = [BytesBundle<W, LOCATION_BYTES>];

    fn index(&self, receiver: u16) -> &Self::Output {
        let receiver = usize::from(receiver);
        &self.encoded[receiver * self.size.l..(receiver + 1) * self.size.l]
    }
}

pub struct IndexColumns<W> {
    gb: IndexColumn<W>,
    ev: IndexColumn<W>,
}

impl<W> IndexColumns<W> {
    pub fn new(garbler: IndexColumn<W>, evaluator: IndexColumn<W>) -> Result<Self> {
        ensure!(
            garbler.size() == evaluator.size(),
            "IndexColumns are differently sized (gb size = {:?}, ev size = {:?})",
            garbler.size(),
            evaluator.size()
        );
        Ok(Self {
            gb: garbler,
            ev: evaluator,
        })
    }

    pub fn size(&self) -> usize {
        // Both tables guaranteed to have the same size by constructor
        self.gb.size()
    }

    pub fn join(
        &self,
    ) -> impl Iterator<Item = (&BytesBundle<W, INDEX_BYTES>, &BytesBundle<W, INDEX_BYTES>)> {
        self.gb.receivers().zip(self.ev.receivers())
    }
}

pub struct IndexColumn<W> {
    column: Box<[BytesBundle<W, INDEX_BYTES>]>,
}

impl<W> IndexColumn<W> {
    pub fn receive<F>(circuit: &mut F, m: usize) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(IndexColumn {
            column: circuit
                .bytes_receive_many(m)
                .context("receive index column")?
                .into_boxed_slice(),
        })
    }

    pub fn encode<F>(circuit: &mut F, table: &plain::IndexColumn) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(IndexColumn {
            column: circuit
                .bytes_encode_many(table.receivers())
                .context("encode index column")?
                .into_boxed_slice(),
        })
    }

    pub fn receivers(&self) -> impl Iterator<Item = &BytesBundle<W, INDEX_BYTES>> {
        self.column.iter()
    }

    pub fn size(&self) -> usize {
        self.column.len()
    }
}

impl<W> ops::Index<u16> for IndexColumn<W> {
    type Output = BytesBundle<W, INDEX_BYTES>;

    fn index(&self, receiver: u16) -> &Self::Output {
        &self.column[usize::from(receiver)]
    }
}

pub struct LocationBlindingTables<W> {
    gb: LocationBlindingTable<W>,
    ev: LocationBlindingTable<W>,
}

impl<W> LocationBlindingTables<W> {
    pub fn new(
        garbler: LocationBlindingTable<W>,
        evaluator: LocationBlindingTable<W>,
    ) -> Result<Self> {
        ensure!(
            garbler.size() == evaluator.size(),
            "delta tables are differently sized (gb size = {:?}, ev size = {:?}",
            garbler.size(),
            evaluator.size()
        );
        Ok(Self {
            gb: garbler,
            ev: evaluator,
        })
    }

    pub fn size(&self) -> TableSize {
        // Constructor guarantees that both tables have the same size
        self.gb.size()
    }

    pub fn join(
        &self,
    ) -> impl Iterator<
        Item = (
            &[BytesBundle<W, LOCATION_BYTES>],
            &[BytesBundle<W, LOCATION_BYTES>],
        ),
    > {
        self.gb.rows().zip(self.ev.rows())
    }
}

pub struct IndexBlindingColumns<W> {
    gb: IndexBlindingColumn<W>,
    ev: IndexBlindingColumn<W>,
}

impl<W> IndexBlindingColumns<W> {
    pub fn new(garbler: IndexBlindingColumn<W>, evaluator: IndexBlindingColumn<W>) -> Result<Self> {
        ensure!(
            garbler.size() == evaluator.size(),
            "delta tables are differently sized (gb size = {:?}, ev size = {:?}",
            garbler.size(),
            evaluator.size()
        );
        Ok(Self {
            gb: garbler,
            ev: evaluator,
        })
    }

    pub fn size(&self) -> usize {
        // Constructor guarantees that both tables have the same size
        self.gb.size()
    }

    pub fn join(
        &self,
    ) -> impl Iterator<Item = (&BytesBundle<W, INDEX_BYTES>, &BytesBundle<W, INDEX_BYTES>)> {
        self.gb.receivers().zip(self.ev.receivers())
    }
}

pub struct LocationBlindingTable<W> {
    table: LocationTable<W>,
}

impl<W> LocationBlindingTable<W> {
    pub fn receive<F>(circuit: &mut F, size: TableSize) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(LocationBlindingTable {
            table: LocationTable::receive(circuit, size)?,
        })
    }

    pub fn generate_and_encode<R, F>(rng: &mut R, size: TableSize, circuit: &mut F) -> Result<Self>
    where
        R: Rng + CryptoRng,
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let table = plain::LocationTable::random(rng, size).context("generate random table")?;
        Ok(LocationBlindingTable {
            table: LocationTable::encode(circuit, &table)?,
        })
    }

    pub fn rows(&self) -> impl Iterator<Item = &[BytesBundle<W, LOCATION_BYTES>]> {
        self.table.rows()
    }

    pub fn size(&self) -> TableSize {
        self.table.size()
    }
}

pub struct IndexBlindingColumn<W> {
    column: IndexColumn<W>,
}

impl<W> IndexBlindingColumn<W> {
    pub fn receive<F>(circuit: &mut F, size: usize) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(Self {
            column: IndexColumn::receive(circuit, size).context("recieve blinding index column")?,
        })
    }

    pub fn generate_and_encode<R, F>(rng: &mut R, size: usize, circuit: &mut F) -> Result<Self>
    where
        R: Rng + CryptoRng,
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let column = plain::IndexColumn::random(rng, size)
            .context("generate random index blinding column")?;
        Ok(Self {
            column: IndexColumn::encode(circuit, &column)
                .context("encode random index blinding column")?,
        })
    }

    pub fn receivers(&self) -> impl Iterator<Item = &BytesBundle<W, INDEX_BYTES>> {
        self.column.receivers()
    }

    pub fn size(&self) -> usize {
        self.column.size()
    }
}

// todo: rename to Receiver
pub struct Receiver<W> {
    pub gb: IndexShare<W>,
    pub ev: IndexShare<W>,
}

impl<W> Receiver<W> {
    pub fn new(garbler: IndexShare<W>, evaluator: IndexShare<W>) -> Self {
        Self {
            gb: garbler,
            ev: evaluator,
        }
    }
}

pub struct LocationShare<W> {
    loc: BytesBundle<W, LOCATION_BYTES>,
}

impl<W> LocationShare<W> {
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
            loc.len() == LOCATION_BYTES,
            "location share must be {} bytes length",
            LOCATION_BYTES
        );

        let loc: [u8; LOCATION_BYTES] = loc
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
    type Target = BytesBundle<W, LOCATION_BYTES>;

    fn deref(&self) -> &Self::Target {
        &self.loc
    }
}

// todo: rename to ReceiverShare?
pub struct IndexShare<W> {
    bundle: BytesBundle<W, INDEX_BYTES>,
}

impl<W> IndexShare<W> {
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

pub trait LazilyEncodedTable<F>
where
    F: FancyInput,
{
    type Row: LazilyEncodedRow<
        F,
        Item = <Self as LazilyEncodedTable<F>>::Item,
        Error = <Self as LazilyEncodedTable<F>>::Error,
    >;
    type Item;
    type Error;

    fn next_row(&mut self) -> Option<Self::Row>;
    fn size(&self) -> TableSize;
}

impl<T, F> LazilyEncodedTableExt<F> for T
where
    T: LazilyEncodedTable<F>,
    F: FancyInput,
{
}

pub trait LazilyEncodedTableExt<F>: LazilyEncodedTable<F>
where
    F: FancyInput,
{
    fn rows_iter(self) -> RowsIter<Self, F>
    where
        Self: Sized,
    {
        RowsIter {
            table: self,
            _ph: PhantomData,
        }
    }

    fn zip<T>(self, second_table: T) -> Result<Zip<Self, T>>
    where
        T: LazilyEncodedTable<F, Item = Self::Item, Error = Self::Error>,
        Self: Sized,
    {
        ensure!(
            self.size() == second_table.size(),
            "tables must have the same size"
        );
        Ok(Zip(self, second_table))
    }
}

pub struct RowsIter<T, F> {
    table: T,
    _ph: PhantomData<F>,
}

impl<T, F> Iterator for RowsIter<T, F>
where
    T: LazilyEncodedTable<F>,
    F: FancyInput,
{
    type Item = T::Row;

    fn next(&mut self) -> Option<Self::Item> {
        self.table.next_row()
    }
}

pub struct Zip<T1, T2>(T1, T2);

impl<F, T1, T2> LazilyEncodedTable<F> for Zip<T1, T2>
where
    T1: LazilyEncodedTable<F>,
    T2: LazilyEncodedTable<F, Error = T1::Error>,
    F: FancyInput,
{
    type Row = ZipRow<T1::Row, T2::Row>;
    type Item = (T1::Item, T2::Item);
    type Error = T1::Error;

    fn next_row(&mut self) -> Option<Self::Row> {
        Some(ZipRow(self.0.next_row()?, self.1.next_row()?))
    }

    fn size(&self) -> TableSize {
        debug_assert_eq!(self.0.size(), self.1.size());
        self.0.size()
    }
}

pub struct ZipRow<R1, R2>(R1, R2);

impl<R1, R2, F> LazilyEncodedRow<F> for ZipRow<R1, R2>
where
    R1: LazilyEncodedRow<F>,
    R2: LazilyEncodedRow<F, Error = R1::Error>,
    F: FancyInput,
{
    type Item = (R1::Item, R2::Item);
    type Error = R1::Error;

    fn next_item(&mut self, circuit: &mut F) -> Result<Option<Self::Item>, Self::Error> {
        let i1 = self.0.next_item(circuit)?;
        let i2 = self.1.next_item(circuit)?;
        match (i1, i2) {
            (Some(i1), Some(i2)) => Ok(Some((i1, i2))),
            _ => Ok(None),
        }
    }
}

pub trait LazilyEncodedRow<F>
where
    F: FancyInput,
{
    type Item;
    type Error;

    fn next_item(&mut self, circuit: &mut F) -> Result<Option<Self::Item>, Self::Error>;
}

pub struct LazilyEncodeTable<R> {
    plain_rows: R,
    size: TableSize,
}

pub fn lazily_encode_table(
    plain_table: &plain::LocationTable,
) -> LazilyEncodeTable<impl Iterator<Item = &[ByteArray<LOCATION_BYTES>]>> {
    LazilyEncodeTable {
        plain_rows: plain_table.rows(),
        size: plain_table.size(),
    }
}

impl<'a, R, F> LazilyEncodedTable<F> for LazilyEncodeTable<R>
where
    R: Iterator<Item = &'a [ByteArray<LOCATION_BYTES>]> + 'a,
    F: FancyInput,
    F::Error: fmt::Display,
{
    type Row = LazilyEncodeRow<'a>;
    type Item = BytesBundle<F::Item, LOCATION_BYTES>;
    type Error = anyhow::Error;

    fn next_row(&mut self) -> Option<Self::Row> {
        self.plain_rows.next().map(|row| LazilyEncodeRow { row })
    }

    fn size(&self) -> TableSize {
        self.size
    }
}

pub struct LazilyEncodeRow<'a> {
    row: &'a [ByteArray<LOCATION_BYTES>],
}

impl<'a, F> LazilyEncodedRow<F> for LazilyEncodeRow<'a>
where
    F: FancyInput,
    F::Error: fmt::Display,
{
    type Item = BytesBundle<F::Item, LOCATION_BYTES>;
    type Error = anyhow::Error;

    fn next_item(&mut self, circuit: &mut F) -> Result<Option<Self::Item>, Self::Error> {
        match self.row {
            [] => Ok(None),
            [x, xs @ ..] => {
                let x = circuit.bytes_encode(x).context("encode item")?;
                self.row = xs;
                Ok(Some(x))
            }
        }
    }
}

pub struct LazilyReceiveTable {
    size: TableSize,
    rows_left: usize,
}

pub fn lazily_receive_table(size: TableSize) -> LazilyReceiveTable {
    LazilyReceiveTable {
        size,
        rows_left: size.m,
    }
}

impl<F> LazilyEncodedTable<F> for LazilyReceiveTable
where
    F: FancyInput,
    F::Error: fmt::Display,
{
    type Row = LazilyReceiveRow;
    type Item = BytesBundle<F::Item, LOCATION_BYTES>;
    type Error = anyhow::Error;

    fn next_row(&mut self) -> Option<Self::Row> {
        if self.rows_left > 0 {
            self.rows_left -= 1;
            Some(LazilyReceiveRow {
                items_left: self.size.l,
            })
        } else {
            None
        }
    }

    fn size(&self) -> TableSize {
        self.size
    }
}

pub struct LazilyReceiveRow {
    items_left: usize,
}

impl<F> LazilyEncodedRow<F> for LazilyReceiveRow
where
    F: FancyInput,
    F::Error: fmt::Display,
{
    type Item = BytesBundle<F::Item, LOCATION_BYTES>;
    type Error = anyhow::Error;

    fn next_item(&mut self, circuit: &mut F) -> Result<Option<Self::Item>, Self::Error> {
        if self.items_left == 0 {
            return Ok(None);
        }
        let item = circuit.bytes_receive().context("receive item")?;
        self.items_left -= 1;
        Ok(Some(item))
    }
}

#[cfg(test)]
mod tests {
    use std::{fmt, iter};

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use fancy_garbling::dummy::Dummy;
    use fancy_garbling::{Fancy, FancyInput, HasModulus};
    use scuttlebutt::AesRng;

    use super::LazilyEncodedTableExt;
    use crate::byte_array::{BytesBundle, BytesGadgets};
    use crate::consts::LOCATION_BYTES;
    use crate::encoded;
    use crate::encoded::LazilyEncodedRow;
    use crate::plain::{IndexColumn, LocationTable, TableSize};
    use crate::utils::{IteratorExt, TwopacTest};

    #[test]
    fn delta_tables_xor() {
        TwopacTest::new()
            .set_garbler(|circuit| delta_tables_xor_circuit(circuit, true))
            .set_evaluator(|circuit| delta_tables_xor_circuit(circuit, false))
            .run()
    }

    fn delta_tables_xor_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let size = TableSize { m: 4, l: 4 };

        let mut rng_gb = StdRng::seed_from_u64(42);
        let mut rng_ev = StdRng::seed_from_u64(43);

        let delta_gb = if is_garbler {
            encoded::LocationBlindingTable::generate_and_encode(&mut rng_gb, size, circuit).unwrap()
        } else {
            encoded::LocationBlindingTable::receive(circuit, size).unwrap()
        };
        let delta_ev = if is_garbler {
            encoded::LocationBlindingTable::receive(circuit, size).unwrap()
        } else {
            encoded::LocationBlindingTable::generate_and_encode(&mut rng_ev, size, circuit).unwrap()
        };

        // Reconstruct both tables
        let mut rng_gb = StdRng::seed_from_u64(42);
        let mut rng_ev = StdRng::seed_from_u64(43);
        let table_gb = LocationTable::random(&mut rng_gb, size).unwrap();
        let table_ev = LocationTable::random(&mut rng_ev, size).unwrap();

        let joint_rows = delta_gb.rows().zip(delta_ev.rows());
        for (i, (row_gb, row_ev)) in joint_rows.enumerate_u16() {
            let joint_items = row_gb.iter().zip(row_ev);
            for (j, (item_gb, item_ev)) in joint_items.enumerate_u16() {
                let out = circuit.bytes_xor(item_gb, item_ev).unwrap();
                let actual = circuit.bytes_output(&out).unwrap();
                if is_garbler {
                    continue;
                }

                let expected_a = table_gb[i][usize::from(j)];
                let expected_b = table_ev[i][usize::from(j)];
                let expected = expected_a ^ expected_b;

                assert_eq!(expected, actual.unwrap());
            }
        }
    }

    #[test]
    fn last_upd_tables_xor() {
        TwopacTest::new()
            .set_garbler(|circuit| last_upd_tables_xor_circuit(circuit, true))
            .set_evaluator(|circuit| last_upd_tables_xor_circuit(circuit, false))
            .run()
    }

    fn last_upd_tables_xor_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let m = 4_usize;

        let gb_table = IndexColumn::random(&mut StdRng::seed_from_u64(1), m).unwrap();
        let ev_table = IndexColumn::random(&mut StdRng::seed_from_u64(2), m).unwrap();
        let expected = gb_table
            .receivers()
            .zip(ev_table.receivers())
            .map(|(a, b)| *a ^ *b);

        let delta_gb = if is_garbler {
            encoded::IndexColumn::encode(circuit, &gb_table).unwrap()
        } else {
            encoded::IndexColumn::receive(circuit, m).unwrap()
        };
        let delta_ev = if is_garbler {
            encoded::IndexColumn::receive(circuit, m).unwrap()
        } else {
            encoded::IndexColumn::encode(circuit, &ev_table).unwrap()
        };

        let joint_rows = delta_gb.receivers().zip(delta_ev.receivers()).zip(expected);
        for ((row_gb, row_ev), expected) in joint_rows {
            let out = circuit.bytes_xor(row_gb, row_ev).unwrap();
            let out = circuit.bytes_output(&out).unwrap();
            if is_garbler {
                continue;
            }
            assert_eq!(out.unwrap(), expected)
        }
    }

    #[test]
    fn location_share_encode() {
        let mut loc = vec![0u8; LOCATION_BYTES];
        loc[0] = 0b1111_1110;

        let mut circuit = Dummy::new();
        let location_share = encoded::LocationShare::encode(&mut circuit, &loc).unwrap();

        let mut wires = location_share.loc.iter();
        assert!(wires
            .by_ref()
            .take(7)
            .all(|b| b.val() == 1 && b.modulus() == 2));
        assert!(wires.all(|b| b.val() == 0 && b.modulus() == 2))
    }

    #[test]
    fn index_share_exchange() {
        TwopacTest::new()
            .set_garbler(|circuit| index_share_exchange_circuit(circuit, true))
            .set_evaluator(|circuit| index_share_exchange_circuit(circuit, false))
            .run()
    }

    fn index_share_exchange_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let a = 0xdead;
        let b = 0xbeaf;
        let gb_in = if is_garbler {
            encoded::IndexShare::encode(circuit, a).unwrap()
        } else {
            encoded::IndexShare::receive(circuit).unwrap()
        };
        let ev_in = if is_garbler {
            encoded::IndexShare::receive(circuit).unwrap()
        } else {
            encoded::IndexShare::encode(circuit, b).unwrap()
        };

        let out = circuit.bytes_xor(&gb_in.bundle, &ev_in.bundle).unwrap();
        let out = circuit.bytes_output(&out).unwrap();

        if is_garbler {
            return;
        }

        assert_eq!(out.unwrap().as_buffer(), &(a ^ b).to_be_bytes());
    }

    #[test]
    fn exchange_location_share() {
        TwopacTest::new()
            .set_garbler(|circuit| exchange_location_share_circuit(circuit, true))
            .set_evaluator(|circuit| exchange_location_share_circuit(circuit, false))
            .run()
    }

    fn exchange_location_share_circuit<F>(circuit: &mut F, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let mut rng_gb = AesRng::seed_from_u64(900);
        let loc_gb: Vec<u8> = iter::repeat_with(|| rng_gb.gen())
            .take(LOCATION_BYTES)
            .collect();

        let mut rng_ev = AesRng::seed_from_u64(901);
        let loc_ev: Vec<u8> = iter::repeat_with(|| rng_ev.gen())
            .take(LOCATION_BYTES)
            .collect();

        let gb_in = if is_garbler {
            encoded::LocationShare::encode(circuit, &loc_gb).unwrap()
        } else {
            encoded::LocationShare::receive(circuit).unwrap()
        };
        let ev_in = if is_garbler {
            encoded::LocationShare::receive(circuit).unwrap()
        } else {
            encoded::LocationShare::encode(circuit, &loc_ev).unwrap()
        };

        let out = circuit.bytes_xor(&gb_in, &ev_in).unwrap();
        let actual = circuit.bytes_output(&out).unwrap();

        if is_garbler {
            return;
        }

        let expected: Vec<_> = loc_gb.into_iter().zip(loc_ev).map(|(a, b)| a ^ b).collect();

        assert_eq!(&actual.unwrap().as_buffer()[..], &expected);
    }

    #[test]
    fn lazy_encoding() {
        let size = TableSize { m: 4, l: 4 };
        TwopacTest::new()
            .set_garbler(move |circuit| lazily_encode_garbler(circuit, size))
            .set_evaluator(move |circuit| lazily_encode_evaluator(circuit, size))
            .run()
    }

    fn lazily_encode_garbler<F>(circuit: &mut F, size: TableSize)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let table_a = LocationTable::random(&mut StdRng::seed_from_u64(42), size).unwrap();

        let encoded_a = encoded::lazily_encode_table(&table_a);
        let encoded_b = encoded::lazily_receive_table(size);

        lazily_encode_circuit(circuit, encoded_a, encoded_b, true);
    }

    fn lazily_encode_evaluator<F>(circuit: &mut F, size: TableSize)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
    {
        let table_b = LocationTable::random(&mut StdRng::seed_from_u64(43), size).unwrap();

        let encoded_a = encoded::lazily_receive_table(size);
        let encoded_b = encoded::lazily_encode_table(&table_b);

        lazily_encode_circuit(circuit, encoded_a, encoded_b, false);
    }

    fn lazily_encode_circuit<F, T1, T2>(circuit: &mut F, table_a: T1, table_b: T2, is_garbler: bool)
    where
        F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
        <F as Fancy>::Error: fmt::Display,
        <F as FancyInput>::Error: fmt::Display,
        T1: encoded::LazilyEncodedTable<F>,
        T2: encoded::LazilyEncodedTable<F>,
        <T1::Row as LazilyEncodedRow<F>>::Error: fmt::Debug,
        <T2::Row as LazilyEncodedRow<F>>::Error: fmt::Debug,
        T1::Row: LazilyEncodedRow<F, Item = BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>>,
        T2::Row: LazilyEncodedRow<F, Item = BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>>,
    {
        assert_eq!(table_a.size(), table_b.size());
        let size = table_a.size();

        let plain_table_a = LocationTable::random(&mut StdRng::seed_from_u64(42), size).unwrap();
        let plain_table_b = LocationTable::random(&mut StdRng::seed_from_u64(43), size).unwrap();

        let rows = table_a.rows_iter().zip(table_b.rows_iter());
        for (i, (mut row_a, mut row_b)) in rows.enumerate_u16() {
            for j in 0..size.l {
                let item_a = row_a.next_item(circuit).unwrap().unwrap();
                let item_b = row_b.next_item(circuit).unwrap().unwrap();

                let x = circuit.bytes_xor(&item_a, &item_b).unwrap();
                let out = circuit.bytes_output(&x).unwrap();
                if is_garbler {
                    continue;
                }

                assert_eq!(out.unwrap(), plain_table_a[i][j] ^ plain_table_b[i][j])
            }
        }
    }
}
