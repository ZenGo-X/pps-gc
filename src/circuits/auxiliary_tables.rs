use std::{fmt, ops};

use anyhow::Result;
use fancy_garbling::{BinaryBundle, BinaryGadgets, BundleGadgets, FancyInput, HasModulus};
use rand::{CryptoRng, Rng};

use super::table::{EncodedTable, LastUpdTable, Table};

pub struct EvaluatorTable<W, const M: usize, const L: usize> {
    table: EncodedTable<W, M, L>,
}

impl<W, const M: usize, const L: usize> EvaluatorTable<W, M, L>
where
    W: Clone + HasModulus,
{
    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(EvaluatorTable {
            table: EncodedTable::receive(input)?,
        })
    }

    pub fn encode<F>(circuit: &mut F, table: &Table<M, L>) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(EvaluatorTable {
            table: EncodedTable::encode(circuit, table)?,
        })
    }
}

impl<W, const M: usize, const L: usize> ops::Deref for EvaluatorTable<W, M, L> {
    type Target = [[BinaryBundle<W>; L]; M];

    fn deref(&self) -> &Self::Target {
        &self.table.encoded
    }
}

pub struct EncodedLastUpdTables<W, const M: usize> {
    pub gb: EncodedLastUpdTable<W, M>,
    pub ev: EncodedLastUpdTable<W, M>,
}

impl<W, const M: usize> EncodedLastUpdTables<W, M> {
    pub fn new(garbler: EncodedLastUpdTable<W, M>, evaluator: EncodedLastUpdTable<W, M>) -> Self {
        Self {
            gb: garbler,
            ev: evaluator,
        }
    }
}

pub struct EncodedLastUpdTable<W, const M: usize> {
    table: EncodedTable<W, M, 1>,
}

impl<W, const M: usize> EncodedLastUpdTable<W, M>
where
    W: Clone + HasModulus,
{
    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(EncodedLastUpdTable {
            table: EncodedTable::receive_last_upd_table(input)?,
        })
    }

    pub fn encode<F>(circuit: &mut F, table: &LastUpdTable<M>) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(EncodedLastUpdTable {
            table: EncodedTable::encode_last_upd_table(circuit, table)?,
        })
    }
}

impl<W, const M: usize> ops::Deref for EncodedLastUpdTable<W, M> {
    type Target = [[BinaryBundle<W>; 1]; M];

    fn deref(&self) -> &Self::Target {
        &self.table.encoded
    }
}

pub struct DeltaTables<W, const M: usize, const L: usize> {
    pub gb: DeltaTable<W, M, L>,
    pub ev: DeltaTable<W, M, L>,
}

impl<W, const M: usize, const L: usize> DeltaTables<W, M, L> {
    pub fn new(garbler: DeltaTable<W, M, L>, evaluator: DeltaTable<W, M, L>) -> Self {
        Self {
            gb: garbler,
            ev: evaluator,
        }
    }
}

pub struct DeltaTable<W, const M: usize, const L: usize> {
    table: EncodedTable<W, M, L>,
}

impl<W, const M: usize, const L: usize> DeltaTable<W, M, L>
where
    W: Clone + HasModulus,
{
    pub fn receive<F>(input: &mut F) -> Result<Self>
    where
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        Ok(DeltaTable {
            table: EncodedTable::receive(input)?,
        })
    }

    pub fn generate_and_encode<R, F>(rng: &mut R, circuit: &mut F) -> Result<Self>
    where
        R: Rng + CryptoRng,
        F: FancyInput<Item = W>,
        F::Error: fmt::Display,
    {
        let table = Table::random(rng);
        Ok(DeltaTable {
            table: EncodedTable::encode(circuit, &table)?,
        })
    }
}

impl<W, const M: usize, const L: usize> ops::Deref for DeltaTable<W, M, L> {
    type Target = [[BinaryBundle<W>; L]; M];

    fn deref(&self) -> &Self::Target {
        &self.table.encoded
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    use fancy_garbling::twopac::semihonest::{Evaluator, Garbler};
    use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
    use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

    use super::*;
    use crate::circuits::utils::u16_to_bits;

    #[test]
    fn delta_tables_xor() {
        let (channel_gb, channel_ev) = unix_channel_pair();
        let handle = std::thread::spawn(move || delta_tables_xor_garbler(channel_gb));
        delta_tables_xor_evaluator(channel_ev);
        handle.join().unwrap();
    }

    fn delta_tables_xor_garbler(channel: UnixChannel) {
        let rng = AesRng::new();
        let mut gb =
            Garbler::<UnixChannel, AesRng, OtSender>::new(channel, rng).expect("garbler init");

        let mut rng = StdRng::seed_from_u64(42);
        let delta_gb = DeltaTable::<_, 4, 4>::generate_and_encode(&mut rng, &mut gb).unwrap();
        let delta_ev = DeltaTable::<_, 4, 4>::receive(&mut gb).unwrap();

        let joint_rows = delta_gb
            .table
            .encoded
            .iter()
            .zip(delta_ev.table.encoded.iter());
        for (row_gb, row_ev) in joint_rows {
            let joint_items = row_gb.iter().zip(row_ev.iter());
            for (item_gb, item_ev) in joint_items {
                let out = gb.bin_xor(item_gb, item_ev).unwrap();
                gb.output_bundle(&out).unwrap();
            }
        }
    }

    fn delta_tables_xor_evaluator(channel: UnixChannel) {
        let rng = AesRng::new();
        let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng)
            .expect("evaluator init");

        println!("Evaluator :: Initialization");

        let mut rng = StdRng::seed_from_u64(43);
        println!("Evaluator :: Receive GB table");
        let delta_gb = DeltaTable::<_, 4, 4>::receive(&mut ev).unwrap();
        println!("Evaluator :: Encode own table");
        let delta_ev = DeltaTable::<_, 4, 4>::generate_and_encode(&mut rng, &mut ev).unwrap();

        println!("Evaluator :: Shamelessly reconstruct both tables");
        let mut rng_gb = StdRng::seed_from_u64(42);
        let mut rng_ev = StdRng::seed_from_u64(43);
        let table_gb = Table::<4, 4>::random(&mut rng_gb);
        let table_ev = Table::<4, 4>::random(&mut rng_ev);

        let joint_rows = delta_gb.iter().zip(delta_ev.iter());
        for (i, (row_gb, row_ev)) in joint_rows.enumerate() {
            println!("Evaluator :: Iterate over {} row", i);
            let joint_items = row_gb.iter().zip(row_ev.iter());
            for (j, (item_gb, item_ev)) in joint_items.enumerate() {
                println!("Evaluator :: Iterate over {} item", j);
                let out = ev.bin_xor(item_gb, item_ev).unwrap();
                let actual: Vec<_> = ev
                    .output_bundle(&out)
                    .unwrap()
                    .unwrap()
                    .into_iter()
                    .map(|x| x == 1)
                    .collect();
                let expected_a = table_gb[i][j];
                let expected_b = table_ev[i][j];
                let expected: Vec<_> = expected_a
                    .iter()
                    .zip(expected_b.iter())
                    .map(|(a, b)| a ^ b)
                    .collect();

                assert_eq!(expected, actual);
            }
        }
    }

    #[test]
    fn last_upd_tables_xor() {
        let (channel_gb, channel_ev) = unix_channel_pair();
        let handle = std::thread::spawn(move || last_upd_tables_xor_garbler(channel_gb));
        last_upd_tables_xor_evaluator(channel_ev);
        handle.join().unwrap();
    }

    fn last_upd_tables_xor_garbler(channel: UnixChannel) {
        let gb_table = LastUpdTable::<4>::random(&mut StdRng::seed_from_u64(1));

        let rng = AesRng::new();
        let mut gb =
            Garbler::<UnixChannel, AesRng, OtSender>::new(channel, rng).expect("garbler init");

        let delta_gb = EncodedLastUpdTable::<_, 4>::encode(&mut gb, &gb_table).unwrap();
        let delta_ev = EncodedLastUpdTable::<_, 4>::receive(&mut gb).unwrap();

        let joint_rows = delta_gb.iter().zip(delta_ev.iter());
        for (row_gb, row_ev) in joint_rows {
            let out = gb.bin_xor(&row_gb[0], &row_ev[0]).unwrap();
            gb.output_bundle(&out).unwrap();
        }
    }

    fn last_upd_tables_xor_evaluator(channel: UnixChannel) {
        let gb_table = LastUpdTable::<4>::random(&mut StdRng::seed_from_u64(1));
        let ev_table = LastUpdTable::<4>::random(&mut StdRng::seed_from_u64(2));
        let expected = gb_table
            .iter()
            .zip(ev_table.iter())
            .map(|(a, b)| u16_to_bits(a ^ b));

        let rng = AesRng::new();
        let mut ev = Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng)
            .expect("evaluator init");

        let delta_gb = EncodedLastUpdTable::<_, 4>::receive(&mut ev).unwrap();
        let delta_ev = EncodedLastUpdTable::<_, 4>::encode(&mut ev, &ev_table).unwrap();

        let joint_rows = delta_gb.iter().zip(delta_ev.iter()).zip(expected);
        for ((row_gb, row_ev), expected) in joint_rows {
            let out = ev.bin_xor(&row_gb[0], &row_ev[0]).unwrap();
            let out = ev.output_bundle(&out).unwrap().unwrap();
            let out: Vec<_> = out.into_iter().map(|x| x == 1).collect();
            assert_eq!(&out, &expected[..])
        }
    }
}
