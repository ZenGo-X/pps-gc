use anyhow::{anyhow, ensure, Context, Result};
use fancy_garbling::{Fancy, FancyInput};
use itertools::Itertools;

use super::output::OutputBuilder;
use crate::byte_array::{ByteArray, BytesBundle, BytesGadgets};
use crate::consts::{INDEX_BYTES, LOCATION_BYTES};
use crate::encoded::{self, LazilyEncodedRow, LazilyEncodedTableExt};
use bitvec::array::BitArray;

pub fn batched_update_table_circuit<F, O1, O2>(
    circuit: &mut F,
    evaluator_table: impl encoded::LazilyEncodedTable<
        F,
        Item = BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
        Error = anyhow::Error,
    >,
    blinding_table: impl encoded::LazilyEncodedTable<
        F,
        Item = (
            BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
            BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
        ),
        Error = anyhow::Error,
    >,
    index_column: encoded::IndexColumns<<F as Fancy>::Item>, // todo: encode index column lazily
    index_blindings: encoded::IndexColumns<<F as Fancy>::Item>,
    index_update_strategy: UpdateIndexesStrategy,
    signals: impl IntoIterator<
        Item = (
            encoded::Receiver<<F as Fancy>::Item>,
            encoded::LocationShare<<F as Fancy>::Item>,
        ),
    >,
    mut output_table: O1,
    mut output_indexes: O2,
) -> Result<(O1::Output, O2::Output)>
where
    F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
    O1: OutputBuilder<
        F,
        Item = BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
        Error = anyhow::Error,
    >,
    O2: OutputBuilder<
        F,
        Item = BytesBundle<<F as Fancy>::Item, INDEX_BYTES>,
        Error = anyhow::Error,
    >,
{
    {
        let loc_table_size = evaluator_table.size();
        let index_table_size = index_column.size();
        let blinding_table_size = blinding_table.size();

        ensure!(
            loc_table_size == blinding_table_size,
            "evaluator_table size doesn't match blinding_table size"
        );
        ensure!(
            loc_table_size.m == index_table_size,
            "evaluator_table size doesn't match index_table size"
        );
    }

    let size = evaluator_table.size();

    let zero = circuit
        .constant(0, 2)
        .map_err(|e| anyhow!("construct constant false: {}", e))?;

    let zero_location = circuit
        .bytes_constant(&ByteArray::new([0u8; LOCATION_BYTES]))
        .context("construct zero_location")?;
    let one_index = circuit
        .bytes_constant(&BitArray::new(1u16.to_be_bytes()))
        .context("construct one_index")?;

    let mut signals: Vec<Signal<_>> = signals
        .into_iter()
        .map(|(recipient, location_share)| {
            Ok(Signal {
                recipient: circuit
                    .bytes_xor(&recipient.gb, &recipient.ev)
                    .context("construct recipient index")?,
                location_share: location_share.clone(),
                was_handled: zero.clone(),
            })
        })
        .try_collect::<_, _, anyhow::Error>()?;
    ensure!(signals.len() > 0, "at least one signal should be provided");

    let receiver_indexes: Vec<BytesBundle<_, INDEX_BYTES>> = (0..size.m as u16)
        .map(|i| circuit.bytes_constant(&ByteArray::new(i.to_be_bytes())))
        .try_collect()?;
    let location_indexes: Vec<BytesBundle<_, INDEX_BYTES>> = (0..size.l as u16)
        .map(|i| circuit.bytes_constant(&ByteArray::new(i.to_be_bytes())))
        .try_collect()?;

    let index_table = index_column.join();
    let index_blindings = index_blindings.join();
    let loc_table = evaluator_table.rows_iter();
    let blinding_rows = blinding_table.rows_iter();
    let rows = index_table
        .zip(index_blindings)
        .zip(loc_table)
        .zip(blinding_rows);

    for (i, (((index, index_blindings), mut loc_row), mut blinding_row)) in rows.enumerate() {
        let index = circuit
            .bytes_xor(&index.0, &index.1)
            .context("construct last upd index")?;
        let mut new_index = index;

        for j in 0..size.l {
            let (blinding_gb, blinding_ev) = blinding_row
                .next_item(circuit)
                .context("retrieve next blinding")?
                .context("internal: unexpected end of blinding row")?;

            let mut j_is_updated = zero.clone();

            let mut new_location = circuit
                .bytes_xor(&blinding_gb, &blinding_ev)
                .context("construct blinding")?;

            for signal in &mut signals {
                let j_wasnt_updated_yet = circuit
                    .negate(&j_is_updated)
                    .map_err(|e| anyhow!("construct wasnt_updated: {}", e))?;

                let signal_addressed_to_this_recipient = circuit
                    .bytes_eq(&receiver_indexes[i], &signal.recipient)
                    .context("construct caught_signal_a")?;
                let signal_wasnt_handled_yet = circuit
                    .negate(&signal.was_handled)
                    .map_err(|e| anyhow!("construct signal_wasnt_handled_yet: {}", e))?;
                let j_equals_to_new_index = circuit
                    .bytes_eq(&location_indexes[j], &new_index)
                    .context("construct caught_signal_b")?;
                let caught_signal = circuit
                    .and_many(&[
                        signal_addressed_to_this_recipient,
                        signal_wasnt_handled_yet,
                        j_equals_to_new_index,
                        j_wasnt_updated_yet,
                    ])
                    .map_err(|e| anyhow!("construct caught_signal: {}", e))?;

                let updated_location = circuit
                    .bytes_xor(&new_location, &signal.location_share)
                    .context("construct updated_location")?;
                new_location = circuit
                    .bytes_mux(&caught_signal, &new_location, &updated_location)
                    .context("construct updated new_location")?;

                j_is_updated = circuit
                    .or(&j_is_updated, &caught_signal)
                    .map_err(|e| anyhow!("update was_updated: {}", e))?;
                signal.was_handled = circuit
                    .or(&signal.was_handled, &caught_signal)
                    .map_err(|e| anyhow!("update signal.was_handled: {}", e))?;

                let (index_plus_one, _carry_bit) = circuit
                    .bytes_add(&new_index, &one_index)
                    .context("construct index_plus_one")?;
                new_index = circuit
                    .bytes_mux(&caught_signal, &new_index, &index_plus_one)
                    .context("update new_index")?;
            }

            let old_location = loc_row
                .next_item(circuit)
                .context("retrieve next old location")?
                .context("internal: unexpected end of location row")?;

            let old_location_or_zero = circuit
                .bytes_mux(&j_is_updated, &old_location, &zero_location)
                .context("construct old_location_or_zero")?;
            new_location = circuit
                .bytes_xor(&new_location, &old_location_or_zero)
                .context("construct final new_location")?;

            output_table
                .process_next(circuit, &new_location)
                .context("output_table.process_next")?;
        }

        let index_blinding = circuit
            .bytes_xor(&index_blindings.0, &index_blindings.1)
            .context("construct index_blinding")?;

        let new_index = if matches!(index_update_strategy, UpdateIndexesStrategy::A) {
            circuit
                .bytes_xor(&index_blinding, &new_index)
                .context("construct blinded new_index")?
        } else {
            index_blinding
        };

        output_indexes
            .process_next(circuit, &new_index)
            .context("output_indexes.process_next")?;
    }

    let new_table = output_table
        .finish()
        .context("extract output from output_table")?;
    let new_indexes = output_indexes
        .finish()
        .context("extract output from output_indexes")?;
    Ok((new_table, new_indexes))
}

/// Strategy of updating indexes column
///
/// When servers update their state, they run batched_update_table_circuit twice swapping roles.
/// For every run you need to provide distinct UpdateIndexesStrategy, otherwise resulting
/// last_upd_tables will be inconsistent.
pub enum UpdateIndexesStrategy {
    A,
    B,
}

struct Signal<I> {
    recipient: BytesBundle<I, INDEX_BYTES>,
    location_share: BytesBundle<I, LOCATION_BYTES>,
    was_handled: I,
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;
    use std::iter;

    use anyhow::Context;
    use itertools::Itertools;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use fancy_garbling::dummy::{Dummy, DummyVal};

    use crate::{encoded, plain, TableSize};

    use super::{batched_update_table_circuit, UpdateIndexesStrategy};
    use crate::byte_array::ByteArray;
    use crate::circuits::output;
    use crate::consts::LOCATION_BYTES;
    use crate::encoded::LazilyEncodedTableExt;

    #[test]
    fn receive_one_signal() {
        let table_size = TableSize { m: 2, l: 2 };
        let state = TestData::empty(table_size);

        let mut signals_entropy = StdRng::seed_from_u64(1_0_1);

        let location = signals_entropy.gen();
        let received_signal = ProcessingSignal::new(&mut signals_entropy, 0, location);
        let (new_table, new_indexes) = state.receive_signals(iter::once(&received_signal));

        assert_eq!(
            new_table[0][0],
            ByteArray::new(received_signal.loc_a)
                ^ state.table_blinding_a[0][0]
                ^ state.table_blinding_b[0][0]
        );

        for (i, j) in (0..2).flat_map(|i| (0..2).map(move |j| (i, j))) {
            if i == 0 && j == 0 {
                continue;
            }
            assert_eq!(
                new_table[i][j],
                state.table_a[i][j] ^ state.table_blinding_a[i][j] ^ state.table_blinding_b[i][j],
                "table[{}][{}]",
                i,
                j
            );
        }

        assert_eq!(
            new_indexes[0],
            ByteArray::new(1u16.to_be_bytes())
                ^ state.indexes_blinding_a[0]
                ^ state.indexes_blinding_b[0]
        );
        assert_eq!(
            new_indexes[1],
            ByteArray::new(0u16.to_be_bytes())
                ^ state.indexes_blinding_a[1]
                ^ state.indexes_blinding_b[1]
        );
    }

    #[test]
    fn two_signals_sent_to_the_same_receiver() {
        let table_size = TableSize { m: 2, l: 2 };
        let state = TestData::empty(table_size);

        let mut signals_entropy = StdRng::seed_from_u64(1_0_1);

        let location1 = signals_entropy.gen();
        let location2 = signals_entropy.gen();
        let received_signal1 = ProcessingSignal::new(&mut signals_entropy, 0, location1);
        let received_signal2 = ProcessingSignal::new(&mut signals_entropy, 0, location2);
        let (new_table, new_indexes) =
            state.receive_signals(vec![&received_signal1, &received_signal2]);

        assert_eq!(
            new_table[0][0],
            ByteArray::new(received_signal1.loc_a)
                ^ state.table_blinding_a[0][0]
                ^ state.table_blinding_b[0][0]
        );
        assert_eq!(
            new_table[0][1],
            ByteArray::new(received_signal2.loc_a)
                ^ state.table_blinding_a[0][1]
                ^ state.table_blinding_b[0][1]
        );

        for j in 0..2 {
            assert_eq!(
                new_table[1][j],
                state.table_a[1][j] ^ state.table_blinding_a[1][j] ^ state.table_blinding_b[1][j],
                "table[1][{}]",
                j
            );
        }

        assert_eq!(
            new_indexes[0],
            ByteArray::new(2u16.to_be_bytes())
                ^ state.indexes_blinding_a[0]
                ^ state.indexes_blinding_b[0]
        );
        assert_eq!(
            new_indexes[1],
            ByteArray::new(0u16.to_be_bytes())
                ^ state.indexes_blinding_a[1]
                ^ state.indexes_blinding_b[1]
        );
    }

    struct TestData {
        table_size: TableSize,
        table_a: plain::LocationTable,

        indexes_a: plain::IndexColumn,
        indexes_b: plain::IndexColumn,

        table_blinding_a: plain::LocationTable,
        table_blinding_b: plain::LocationTable,

        indexes_blinding_a: plain::IndexColumn,
        indexes_blinding_b: plain::IndexColumn,
    }

    impl TestData {
        pub fn empty(table_size: TableSize) -> Self {
            let mut seed_rng = StdRng::from_entropy();
            let table_seed = seed_rng.gen::<u64>();
            let indexes_seed = seed_rng.gen::<u64>();
            let table_blinding_a_seed = seed_rng.gen::<u64>();
            let table_blinding_b_seed = seed_rng.gen::<u64>();
            let indexes_blinding_a_seed = seed_rng.gen::<u64>();
            let indexes_blinding_b_seed = seed_rng.gen::<u64>();
            println!(
                "table_seed = {}, indexes_seed = {}, blinding_a_seed = {}, blinding_b_seed = {} \
                indexes_blinding_a_seed = {}, indexes_blinding_b_seed = {}",
                table_seed,
                indexes_seed,
                table_blinding_a_seed,
                table_blinding_b_seed,
                indexes_blinding_a_seed,
                indexes_blinding_b_seed
            );

            Self {
                table_size,

                table_a: plain::LocationTable::random(
                    &mut StdRng::seed_from_u64(table_seed),
                    table_size,
                )
                .unwrap(),

                indexes_a: plain::IndexColumn::random(
                    &mut StdRng::seed_from_u64(indexes_seed),
                    table_size.m,
                )
                .unwrap(),
                indexes_b: plain::IndexColumn::random(
                    &mut StdRng::seed_from_u64(indexes_seed),
                    table_size.m,
                )
                .unwrap(),

                table_blinding_a: plain::LocationTable::random(
                    &mut StdRng::seed_from_u64(table_blinding_a_seed),
                    table_size,
                )
                .unwrap(),
                table_blinding_b: plain::LocationTable::random(
                    &mut StdRng::seed_from_u64(table_blinding_b_seed),
                    table_size,
                )
                .unwrap(),

                indexes_blinding_a: plain::IndexColumn::random(
                    &mut StdRng::seed_from_u64(indexes_blinding_a_seed),
                    table_size.m,
                )
                .unwrap(),
                indexes_blinding_b: plain::IndexColumn::random(
                    &mut StdRng::seed_from_u64(indexes_blinding_b_seed),
                    table_size.m,
                )
                .unwrap(),
            }
        }

        pub fn receive_signals<'a>(
            &self,
            signals: impl IntoIterator<Item = &'a ProcessingSignal>,
        ) -> (plain::LocationTable, plain::IndexColumn) {
            let mut dummy = Dummy::new();

            let table_a_encoded = encoded::lazily_encode_table(&self.table_a);

            let blinding_a_encoded = encoded::lazily_encode_table(&self.table_blinding_a);
            let blinding_b_encoded = encoded::lazily_encode_table(&self.table_blinding_b);
            let blinding_encoded =
                LazilyEncodedTableExt::<Dummy>::zip(blinding_a_encoded, blinding_b_encoded)
                    .unwrap();

            let indexes_a_encoded =
                encoded::IndexColumn::encode(&mut dummy, &self.indexes_a).unwrap();
            let indexes_b_encoded =
                encoded::IndexColumn::encode(&mut dummy, &self.indexes_b).unwrap();
            let indexes_encoded =
                encoded::IndexColumns::new(indexes_a_encoded, indexes_b_encoded).unwrap();

            let index_blindings_a =
                encoded::IndexColumn::encode(&mut dummy, &self.indexes_blinding_a).unwrap();
            let index_blindings_b =
                encoded::IndexColumn::encode(&mut dummy, &self.indexes_blinding_b).unwrap();
            let index_blindings =
                encoded::IndexColumns::new(index_blindings_a, index_blindings_b).unwrap();

            let signals_encoded: Vec<_> = signals
                .into_iter()
                .map(|s| s.encode_a(&mut dummy))
                .try_collect::<_, _, anyhow::Error>()
                .unwrap();

            let table_builder = output::LocationTableBuilder::new(self.table_size);
            let indexes_builder = output::IndexColumnBuilder::new(self.table_size.m);

            batched_update_table_circuit(
                &mut dummy,
                table_a_encoded,
                blinding_encoded,
                indexes_encoded,
                index_blindings,
                UpdateIndexesStrategy::A,
                signals_encoded,
                table_builder,
                indexes_builder,
            )
            .unwrap()
        }
    }

    struct ProcessingSignal {
        receiver_a: u16,
        receiver_b: u16,
        loc_a: [u8; LOCATION_BYTES],
        _loc_b: [u8; LOCATION_BYTES],
    }

    impl ProcessingSignal {
        pub fn new<R: Rng>(rng: &mut R, receiver: u16, loc: [u8; LOCATION_BYTES]) -> Self {
            let receiver_blinding = rng.gen::<u16>();
            let location_blinding = rng.gen::<[u8; LOCATION_BYTES]>();

            Self {
                receiver_a: receiver ^ receiver_blinding,
                receiver_b: receiver_blinding,
                loc_a: loc
                    .iter()
                    .zip(location_blinding.iter())
                    .map(|(a, b)| a ^ b)
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                _loc_b: location_blinding,
            }
        }

        pub fn encode_a(
            &self,
            circuit: &mut Dummy,
        ) -> anyhow::Result<(
            encoded::Receiver<DummyVal>,
            encoded::LocationShare<DummyVal>,
        )> {
            let receiver_a = encoded::IndexShare::encode(circuit, self.receiver_a)
                .context("encode receiver_a")?;
            let receiver_b = encoded::IndexShare::encode(circuit, self.receiver_b)
                .context("encode receiver_b")?;
            let receiver = encoded::Receiver::new(receiver_a, receiver_b);

            let loc_a =
                encoded::LocationShare::encode(circuit, &self.loc_a).context("encode loc_a")?;

            Ok((receiver, loc_a))
        }
    }
}
