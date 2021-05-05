use std::convert::{TryFrom, TryInto};
use std::mem;

use anyhow::{anyhow, ensure, Context, Result};
use fancy_garbling::{Fancy, HasModulus};

use super::auxiliary_tables::{EncodedLastUpdTables, EvaluatorTable, LocationDeltaTables};
use super::byte_array::{ByteArray, BytesBundle, BytesGadgets};
use super::consts::LOCATION_BYTES;
use super::shares::{LocationShare, R};
use super::table::{EncodedTable, LocationTable};
use super::utils::join3;

pub fn update_table_circuit<F, const M: usize, const L: usize>(
    circuit: &mut F,
    evaluator_table: EvaluatorTable<F::Item, M, L>,
    last_upd_table: EncodedLastUpdTables<F::Item, M>,
    r: LocationDeltaTables<F::Item, M, L>,
    receiver: R<F::Item>,
    evaluator_loc_share: LocationShare<F::Item>,
) -> Result<UpdatedTable<F::Item, M, L>>
where
    F: Fancy,
{
    let receiver = circuit
        .bytes_xor(&receiver.gb, &receiver.ev)
        .context("construct receiver wires")?;

    let joint_tables = join3(&evaluator_table, &r.gb, &r.ev);
    let last_upd_indexes = last_upd_table.ev.iter().zip(last_upd_table.gb.iter());
    let joint_tables = last_upd_indexes.zip(joint_tables);
    let mut result_table = vec![];
    for (i, ((last_upd_ev, last_upd_gb), row)) in joint_tables.enumerate() {
        let mut result_row = vec![];

        let index = circuit
            .bytes_xor(&last_upd_ev[0], &last_upd_gb[0])
            .context("construct last_upd_index")?;
        for (j, (prev_loc, r_gb, r_ev)) in row.enumerate() {
            let i_bundle = circuit
                .bytes_constant(&ByteArray::new((i as u16).to_be_bytes()))
                .context("convert i to wires")?;
            let j_bundle = circuit
                .bytes_constant(&ByteArray::new((j as u16).to_be_bytes()))
                .context("convert j to wires")?;
            let condition_a = circuit
                .bytes_eq(&i_bundle, &receiver)
                .context("construct condition_a")?;
            let condition_b = circuit
                .bytes_eq(&j_bundle, &index)
                .context("construct condition_b")?;
            let condition = circuit
                .and(&condition_a, &condition_b)
                .map_err(|e| anyhow!("construct condition: {}", e))?;

            let maybe_overridden = circuit
                .bytes_mux(&condition, &prev_loc, &evaluator_loc_share)
                .context("construct maybe_overridden")?;
            let r = circuit.bytes_xor(&r_gb, &r_ev).context("construct r")?;
            let new_value = circuit
                .bytes_xor(&maybe_overridden, &r)
                .context("construct new_value")?;

            result_row.push(new_value);
        }
        result_table.push(
            <[BytesBundle<F::Item, LOCATION_BYTES>; L]>::try_from(result_row)
                .map_err(|_| anyhow!("unreachable: exactly L items are proceeded"))?,
        )
    }
    Ok(UpdatedTable {
        table: EncodedTable {
            encoded: result_table
                .into_boxed_slice()
                .try_into()
                .map_err(|_| anyhow!("unreachable: exactly M rows are proceeded"))?,
        },
    })
}

pub struct UpdatedTable<W, const M: usize, const L: usize> {
    table: EncodedTable<W, M, L, LOCATION_BYTES>,
}

impl<W, const M: usize, const L: usize> UpdatedTable<W, M, L>
where
    W: Clone + HasModulus,
{
    pub fn output<F>(self, circuit: &mut F) -> Result<Option<LocationTable<M, L>>>
    where
        F: Fancy<Item = W>,
    {
        let flat_table = self.table.encoded.iter().flat_map(|row| row.iter());
        let outputs = circuit
            .bytes_output_many(flat_table)
            .context("send/retrieve output")?;
        let mut outputs = match outputs {
            Some(outputs) => outputs,
            None => return Ok(None),
        };
        ensure!(
            outputs.len() == M * L,
            "internal: outputs.len() must be {}, actual length {}",
            M * L,
            outputs.len()
        );

        let mut table: Vec<[ByteArray<LOCATION_BYTES>; L]> = vec![];
        for _ in 0..M {
            let mut row = outputs.split_off(L);
            mem::swap(&mut outputs, &mut row);
            table.push(row.try_into().expect("guaranteed by split_off, ensure"))
        }
        Ok(Some(
            table
                .into_boxed_slice()
                .try_into()
                .map(LocationTable::new)
                .expect("guaranteed by loop, ensure"),
        ))
    }
}
