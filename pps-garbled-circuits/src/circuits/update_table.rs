use anyhow::{anyhow, ensure, Context, Result};
use fancy_garbling::{Fancy, FancyInput};

use super::output::OutputBuilder;
use crate::byte_array::{ByteArray, BytesBundle, BytesGadgets};
use crate::consts::LOCATION_BYTES;
use crate::encoded::{self, LazilyEncodedRow, LazilyEncodedTableExt};

pub fn update_table_circuit<F, O>(
    circuit: &mut F,
    evaluator_table: impl encoded::LazilyEncodedTable<
        F,
        Item = BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
        Error = anyhow::Error,
    >,
    last_upd_table: encoded::IndexColumns<<F as Fancy>::Item>,
    r: impl encoded::LazilyEncodedTable<
        F,
        Item = (
            BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
            BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
        ),
        Error = anyhow::Error,
    >,
    receiver: encoded::Receiver<<F as Fancy>::Item>,
    evaluator_loc_share: encoded::LocationShare<<F as Fancy>::Item>,
    mut output_builder: O,
) -> Result<O::Output>
where
    F: Fancy + FancyInput<Item = <F as Fancy>::Item>,
    O: OutputBuilder<
        F,
        Item = BytesBundle<<F as Fancy>::Item, LOCATION_BYTES>,
        Error = anyhow::Error,
    >,
{
    {
        // Check pre-conditions
        let evaluator_table_size = evaluator_table.size();
        let last_upd_table_size = last_upd_table.size();
        let r_size = r.size();

        ensure!(
            evaluator_table_size.m == last_upd_table_size,
            "evaluator table and last upd tables are differently sized (evaluator table size = {:?}, last upd tables size = {})",
            evaluator_table_size, last_upd_table_size
        );
        ensure!(
            evaluator_table_size == r_size,
            "evaluator table and r table are differently sized (evaluator table size = {:?}, r size = {:?})",
            evaluator_table_size, r_size
        )
    }

    let size = evaluator_table.size();

    let receiver = circuit
        .bytes_xor(&receiver.gb, &receiver.ev)
        .context("construct receiver wires")?;

    let joint_tables = last_upd_table
        .join()
        .zip(evaluator_table.rows_iter())
        .zip(r.rows_iter());
    for (i, (((last_upd_gb, last_upd_ev), mut loc_row), mut blinding_row)) in
        joint_tables.enumerate()
    {
        let index = circuit
            .bytes_xor(last_upd_gb, last_upd_ev)
            .context("construct last_upd_index")?;
        for j in 0..size.l {
            let prev_loc = loc_row
                .next_item(circuit)
                .context("retrieve next item")?
                .context("internal: unexpected end of row")?;
            let (r_gb, r_ev) = blinding_row
                .next_item(circuit)
                .context("retrieve next blinding")?
                .context("internal: unexpected end of row (blindings)")?;

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

            output_builder
                .process_next(circuit, &new_value)
                .context("not processed by output_builder")?;
        }
    }
    output_builder.finish()
}
