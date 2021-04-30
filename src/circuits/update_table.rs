use std::convert::{TryFrom, TryInto};

use anyhow::{anyhow, Context, Result};
use fancy_garbling::{BinaryBundle, BinaryGadgets, BundleGadgets, Fancy, HasModulus};

use super::auxiliary_tables::{DeltaTables, EncodedLastUpdTables, EvaluatorTable};
use super::shares::{LocationShare, R};
use super::table::{EncodedTable, Table};
use super::utils::{constant_binary_wires, join3, u16_to_bits};
use super::SECURITY_BITS;

pub fn update_table_circuit<F, const M: usize, const L: usize>(
    circuit: &mut F,
    evaluator_table: EvaluatorTable<F::Item, M, L>,
    last_upd_table: EncodedLastUpdTables<F::Item, M>,
    r: DeltaTables<F::Item, M, L>,
    receiver: R<F::Item>,
    evaluator_loc_share: LocationShare<F::Item>,
) -> Result<UpdatedTable<F::Item, M, L>>
where
    F: Fancy,
{
    let receiver = circuit
        .bin_xor(&receiver.gb, &receiver.ev)
        .map_err(|e| anyhow!("construct receiver wires: {}", e))?;

    let joint_tables = join3(&evaluator_table, &r.gb, &r.ev);
    let last_upd_indexes = last_upd_table.ev.iter().zip(last_upd_table.gb.iter());
    let joint_tables = last_upd_indexes.zip(joint_tables);
    let mut result_table = vec![];
    for (i, ((last_upd_ev, last_upd_gb), row)) in joint_tables.enumerate() {
        let mut result_row = vec![];

        let index = circuit
            .bin_xor(&last_upd_ev[0], &last_upd_gb[0])
            .map_err(|e| anyhow!("construct last_upd_index: {}", e))?;
        for (j, (prev_loc, r_gb, r_ev)) in row.enumerate() {
            let i_bundle = constant_binary_wires(circuit, &u16_to_bits(i as u16))
                .context("convert i to wires")?;
            let j_bundle = constant_binary_wires(circuit, &u16_to_bits(j as u16))
                .context("convert j to wires")?;
            let condition_a = circuit
                .eq_bundles(&i_bundle, &receiver)
                .map_err(|e| anyhow!("construct condition_a: {}", e))?;
            let condition_b = circuit
                .eq_bundles(&j_bundle, &index)
                .map_err(|e| anyhow!("construct condition_b: {}", e))?;
            let condition = circuit
                .and(&condition_a, &condition_b)
                .map_err(|e| anyhow!("construct condition: {}", e))?;

            let maybe_overridden = circuit
                .multiplex(&condition, &prev_loc, &evaluator_loc_share)
                .map(From::from)
                .map_err(|e| anyhow!("construct maybe_overridden: {}", e))?;
            let r = circuit
                .bin_xor(&r_gb, &r_ev)
                .map_err(|e| anyhow!("construct r: {}", e))?;
            let new_value = circuit
                .bin_xor(&maybe_overridden, &r)
                .map_err(|e| anyhow!("construct new_value: {}", e))?;

            result_row.push(new_value);
        }
        result_table.push(
            <[BinaryBundle<F::Item>; L]>::try_from(result_row)
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
    table: EncodedTable<W, M, L>,
}

impl<W, const M: usize, const L: usize> UpdatedTable<W, M, L>
where
    W: Clone + HasModulus,
{
    pub fn output<F>(self, circuit: &mut F) -> Result<Option<Table<M, L>>>
    where
        F: Fancy<Item = W>,
    {
        let mut resulting_table = vec![];
        let mut output_missing = false;
        for row in self.table.encoded.iter() {
            let mut resulting_row = vec![];
            for loc in row {
                let new_loc = circuit
                    .output_bundle(loc)
                    .map_err(|_e| anyhow!("set output wire"))?;
                if let Some(new_loc) = new_loc {
                    let new_loc: Vec<_> = new_loc.into_iter().map(|x| x == 1).collect();
                    resulting_row.push(<[bool; SECURITY_BITS]>::try_from(new_loc).map_err(
                        |was| {
                            anyhow!(
                                "expected exactly {} length vector, got {} length",
                                SECURITY_BITS,
                                was.len(),
                            )
                        },
                    )?)
                } else {
                    output_missing = true
                }
            }
            if !output_missing {
                resulting_table.push(
                    <[[bool; SECURITY_BITS]; L]>::try_from(resulting_row).map_err(|was| {
                        anyhow!(
                            "expected exactly {} length row, got {} length",
                            L,
                            was.len()
                        )
                    })?,
                )
            }
        }

        if output_missing {
            return Ok(None);
        }

        Ok(Some(Table::new(
            Box::<[[[bool; SECURITY_BITS]; L]; M]>::try_from(resulting_table.into_boxed_slice())
                .map_err(|was| anyhow!("expected {} length vec, got {} length", M, was.len()))?,
        )))
    }
}
