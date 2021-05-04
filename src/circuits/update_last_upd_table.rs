use std::convert::TryInto;
use std::iter;

use anyhow::{anyhow, Context, Result};

use fancy_garbling::Fancy;

use super::auxiliary_tables::{EncodedLastUpdTable, LastUpdDeltaTables};
use super::byte_array::{ByteArray, BytesBundle, BytesGadgets};
use super::shares::R;
use super::table::INDEX_BYTES;

pub fn update_table_circuit<F, const M: usize>(
    circuit: &mut F,
    last_upd_table_gb: Option<EncodedLastUpdTable<F::Item, M>>,
    last_upd_table_ev: EncodedLastUpdTable<F::Item, M>,
    r: LastUpdDeltaTables<F::Item, M, 1>,
    receiver: R<F::Item>,
) -> Result<UpdatedLastUpdTable<F::Item, M>>
where
    F: Fancy,
{
    let receiver = circuit
        .bytes_xor(&receiver.gb, &receiver.ev)
        .context("construct receiver")?;

    let last_upd_table_gb = iterate_over_optional_table(&last_upd_table_gb);
    let last_upd_table_ev = last_upd_table_ev.iter().map(|s| &s[0]);
    let last_upd_table = last_upd_table_gb.zip(last_upd_table_ev);

    let r =
        r.gb.iter()
            .zip(r.ev.iter())
            .map(|(r_gb, r_ev)| (&r_gb[0], &r_ev[0]));

    let zero = circuit
        .bytes_constant(&ByteArray::new(0u16.to_be_bytes()))
        .context("construct constant zero")?;
    let one = circuit
        .bytes_constant(&ByteArray::new(1u16.to_be_bytes()))
        .context("construct constant one")?;

    let mut updated_table = vec![];
    for (i, ((r_gb, r_ev), (last_upd_gb, last_upd_ev))) in r.zip(last_upd_table).enumerate() {
        let i = circuit
            .bytes_constant(&ByteArray::new((i as u16).to_be_bytes()))
            .context("construct i constant")?;
        let r = circuit.bytes_xor(&r_gb, &r_ev).context("construct r")?;
        let index = match last_upd_gb {
            Some(last_upd_gb) => {
                let index_was = circuit
                    .bytes_xor(last_upd_gb, last_upd_ev)
                    .context("construct last_upd_index")?;
                let (index_new, _) = circuit
                    .bytes_add(&index_was, &one)
                    .context("construct new last_upd_index")?;
                index_new
            }
            None => zero.clone(),
        };

        let condition = circuit
            .bytes_eq(&i, &receiver)
            .context("construct receiver")?;

        let maybe_overridden = circuit
            .bytes_mux(&condition, last_upd_ev, &index)
            .context("construct maybe_overridden")?;

        let new_value = circuit
            .bytes_xor(&maybe_overridden, &r)
            .context("construct new value")?;
        updated_table.push(new_value);
    }

    updated_table
        .try_into()
        .map(|table| UpdatedLastUpdTable { table })
        .map_err(|e| {
            anyhow!(
                "internal: expected to proceed {} rows, {} proceeded",
                M,
                e.len()
            )
        })
}

pub struct UpdatedLastUpdTable<W, const M: usize> {
    table: [BytesBundle<W, INDEX_BYTES>; M],
}

fn iterate_over_optional_table<W, const M: usize>(
    table: &Option<EncodedLastUpdTable<W, M>>,
) -> impl Iterator<Item = Option<&BytesBundle<W, INDEX_BYTES>>> {
    use itertools::Either;
    match table {
        Some(table) => Either::Left(table.iter().map(|s| &s[0]).map(Some)),
        None => Either::Right(iter::repeat_with(|| None).take(M)),
    }
}
