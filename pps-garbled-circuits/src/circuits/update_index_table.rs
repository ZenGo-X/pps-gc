use std::iter;

use anyhow::{ensure, Context, Result};

use fancy_garbling::{Fancy, HasModulus};

use crate::byte_array::{ByteArray, BytesBundle, BytesGadgets};
use crate::consts::INDEX_BYTES;
use crate::encoded;
use crate::IndexColumn;

pub fn update_index_table_circuit<F>(
    circuit: &mut F,
    last_upd_table_gb: Option<encoded::IndexColumn<F::Item>>,
    last_upd_table_ev: encoded::IndexColumn<F::Item>,
    r: encoded::IndexBlindingColumns<F::Item>,
    receiver: encoded::Receiver<F::Item>,
) -> Result<UpdatedIndexColumn<F::Item>>
where
    F: Fancy,
{
    {
        // Check pre-conditions
        let last_upd_table_gb_size = last_upd_table_gb.as_ref().map(encoded::IndexColumn::size);
        let last_upd_table_ev_size = last_upd_table_ev.size();
        let r_size = r.size();

        ensure!(
            last_upd_table_gb_size.is_none()
                || last_upd_table_gb_size == Some(last_upd_table_ev_size),
            "last_upd_tables are differently sized (gb size = {:?}, ev size = {:?})",
            last_upd_table_gb_size,
            last_upd_table_ev_size
        );
        ensure!(
            last_upd_table_ev_size == r_size,
            "last_upd_table and r are differently sized (last_upd_table size = {}, r size = {:?}",
            last_upd_table_ev_size,
            r_size
        );
    }

    let m = last_upd_table_ev.size();

    let receiver = circuit
        .bytes_xor(&receiver.gb, &receiver.ev)
        .context("construct receiver")?;

    let last_upd_table_gb = iterate_over_optional_table(&last_upd_table_gb);
    let last_upd_table_ev = last_upd_table_ev.receivers();
    let last_upd_table = last_upd_table_gb.zip(last_upd_table_ev);

    let r = r.join();

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

    Ok(UpdatedIndexColumn {
        table: updated_table.into(),
        m,
    })
}

pub struct UpdatedIndexColumn<W> {
    table: Box<[BytesBundle<W, INDEX_BYTES>]>,
    m: usize,
}

impl<W> UpdatedIndexColumn<W>
where
    W: Clone + HasModulus,
{
    pub fn output<F>(self, circuit: &mut F) -> Result<Option<IndexColumn>>
    where
        F: Fancy<Item = W>,
    {
        let outputs = circuit
            .bytes_output_many(self.table.iter())
            .context("send/retrieve output")?;
        let outputs = match outputs {
            Some(o) => o,
            None => return Ok(None),
        };
        Ok(Some(IndexColumn::new(outputs.into(), self.m)?))
    }
}

fn iterate_over_optional_table<W>(
    table: &Option<encoded::IndexColumn<W>>,
) -> impl Iterator<Item = Option<&BytesBundle<W, INDEX_BYTES>>> {
    use itertools::Either;
    match table {
        Some(table) => Either::Left(table.receivers().map(Some)),
        None => Either::Right(iter::repeat_with(|| None)),
    }
}
