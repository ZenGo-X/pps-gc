#![feature(array_chunks)]

use anyhow::{anyhow, ensure, Context, Result};
use fancy_garbling::twopac::semihonest::{Evaluator, Garbler};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, AesRng};

// Re-export
pub use self::{
    byte_array::ByteArray,
    plain::{IndexColumn, LocationTable, TableSize},
};

use crate::encoded::LazilyEncodedTableExt;

// mod auxiliary_tables;
mod byte_array;
pub mod circuits;
pub mod encoded;
mod plain;
#[cfg(test)]
mod utils;

pub mod consts {
    use std::mem::size_of;

    pub const LOCATION_BYTES: usize = 32; // 256 bits
    pub const INDEX_BYTES: usize = size_of::<u16>(); // 16 bits
}

pub fn update_table_garbler<C, Rnd>(
    delta_rng: &mut Rnd,
    table_size: TableSize,
    last_upd_table: &IndexColumn,
    channel: C,
    receiver_share: u16,
) -> Result<()>
where
    Rnd: Rng + CryptoRng,
    C: AbstractChannel,
{
    {
        // Check pre-conditions
        let last_upd_table = last_upd_table.size();

        ensure!(
            table_size.m == last_upd_table,
            "given table_size doesn't match last_upd_table size (table size = {:?}, last_upd_table size = {})",
            table_size, last_upd_table,
        );
    }

    let size = table_size;

    let rng = AesRng::new();
    let mut gb = Garbler::<C, AesRng, OtSender>::new(channel, rng)
        .map_err(|e| anyhow!("garbler init: {}", e))?;

    let receiver_gb = encoded::IndexShare::encode(&mut gb, receiver_share)
        .context("Garbler encodes his shares and sends to Evaluator")?;
    let receiver_ev = encoded::IndexShare::receive(&mut gb)
        .context("Garbler OT sends encoded Evaluator shares")?;
    let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

    let location_ev =
        encoded::LocationShare::receive(&mut gb).context("Garbler OT sends location share")?;

    let last_upd_table_gb = encoded::IndexColumn::encode(&mut gb, last_upd_table)
        .context("Garbler encodes last_upd_table and sends to Evaluator")?;

    let last_upd_table_ev = encoded::IndexColumn::receive(&mut gb, size.m)
        .context("Garbler OT sends encoded last_upd_table of Evaluator")?;

    let last_upd_table = encoded::IndexColumns::new(last_upd_table_gb, last_upd_table_ev)
        .context("internal: construct encoded::LastUpdTables")?;

    let table_ev = encoded::lazily_receive_table(size);

    let blinding_gb = LocationTable::random(delta_rng, size).context("generate blinding table")?;
    let blinding_gb = encoded::lazily_encode_table(&blinding_gb);
    let blinding_ev = encoded::lazily_receive_table(size);
    let blindings =
        LazilyEncodedTableExt::<Garbler<C, AesRng, OtSender>>::zip(blinding_gb, blinding_ev)
            .context("construct zipped blindings table")?;

    let output_builder = circuits::GarblerOutput::new();

    circuits::update_table_circuit(
        &mut gb,
        table_ev,
        last_upd_table,
        blindings,
        receiver,
        location_ev,
        output_builder,
    )
    .context("execute circuit")?;

    Ok(())
}

pub fn update_table_evaluator<C, Rnd>(
    delta_rng: &mut Rnd,
    table: &LocationTable,
    last_upd_table: &IndexColumn,
    channel: C,
    receiver_share: u16,
    location_share: &[u8],
) -> Result<LocationTable>
where
    Rnd: Rng + CryptoRng,
    C: AbstractChannel,
{
    {
        // Check pre-conditions
        let table_size = table.size();
        let last_upd_table_size = last_upd_table.size();
        let location_share_size = location_share.len();

        ensure!(
            table_size.m == last_upd_table_size,
            "locations table and last upd table are differently sized (locations table size = {:?}, last upd table size = {}",
            table_size.m, last_upd_table_size,
        );
        ensure!(
            location_share_size == consts::LOCATION_BYTES,
            "wrong location_share length (expected {}, actual{})",
            consts::LOCATION_BYTES,
            location_share_size
        );
    }

    let size = table.size();

    let rng = AesRng::new();
    let mut ev = Evaluator::<C, AesRng, OtReceiver>::new(channel, rng)
        .map_err(|e| anyhow!("Evaluator init: {}", e))?;

    let receiver_gb = encoded::IndexShare::receive(&mut ev)
        .context("Evaluator receives encoded Garbler shares")?;
    let receiver_ev = encoded::IndexShare::encode(&mut ev, receiver_share)
        .context("Evaluator OT receives encoded Evaluator shares ")?;
    let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

    let location_ev =
        encoded::LocationShare::encode(&mut ev, location_share).context("encode location_share")?;

    let last_upd_table_gb = encoded::IndexColumn::receive(&mut ev, size.m)
        .context("receive counterparty last_upd_table")?;
    let last_upd_table_ev =
        encoded::IndexColumn::encode(&mut ev, last_upd_table).context("encode last_upd_table")?;
    let last_upd_table = encoded::IndexColumns::new(last_upd_table_gb, last_upd_table_ev)
        .context("internal: construct last_upd_tables")?;

    let table_ev = encoded::lazily_encode_table(&table);

    let blinding_gb = encoded::lazily_receive_table(size);
    let blinding_ev = LocationTable::random(delta_rng, size).context("generate blinding table")?;
    let blinding_ev = encoded::lazily_encode_table(&blinding_ev);
    let blindings =
        LazilyEncodedTableExt::<Evaluator<C, AesRng, OtReceiver>>::zip(blinding_gb, blinding_ev)
            .context("construct zipped blinding table")?;

    let output_builder = circuits::LocationTableBuilder::new(size);

    let table = circuits::update_table_circuit(
        &mut ev,
        table_ev,
        last_upd_table,
        blindings,
        receiver,
        location_ev,
        output_builder,
    )
    .context("execute circuit")?;

    Ok(table)
}

pub fn update_index_garbler<C, Rnd>(
    delta_rng: &mut Rnd,
    last_upd_table_size: usize,
    last_upd_table: Option<&IndexColumn>,
    channel: C,
    receiver_share: u16,
) -> Result<()>
where
    Rnd: Rng + CryptoRng,
    C: AbstractChannel,
{
    {
        // Check pre-conditions
        let last_upd_table_gb_size = last_upd_table.map(IndexColumn::size);

        ensure!(
            last_upd_table.is_none() || Some(last_upd_table_size) == last_upd_table_gb_size,
            "last_upd_table_size doesn't match last_upd_table (last_upd_table_size = {}, last_upd_table size = {:?})",
            last_upd_table_size, last_upd_table_gb_size,
        );
    }

    let size = last_upd_table_size;

    let rng = AesRng::new();
    let mut gb = Garbler::<C, AesRng, OtSender>::new(channel, rng)
        .map_err(|e| anyhow!("garbler init: {}", e))?;

    let receiver_gb = encoded::IndexShare::encode(&mut gb, receiver_share)
        .context("Garbler encodes his shares and sends to Evaluator")?;
    let receiver_ev = encoded::IndexShare::receive(&mut gb)
        .context("Garbler OT sends encoded Evaluator shares")?;
    let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

    let last_upd_table_gb = match last_upd_table {
        Some(table) => Some(
            encoded::IndexColumn::encode(&mut gb, table)
                .context("Garbler encodes last_upd_table and sends to Evaluator")?,
        ),
        None => None,
    };
    let last_upd_table_ev = encoded::IndexColumn::receive(&mut gb, size)
        .context("Garbler OT sends encoded last_upd_table of Evaluator")?;

    let delta_gb = encoded::IndexBlindingColumn::generate_and_encode(delta_rng, size, &mut gb)
        .context("generate and encode delta table")?;
    let delta_ev = encoded::IndexBlindingColumn::receive(&mut gb, size)
        .context("Garbler OT sends Evaluator delta table")?;
    let r = encoded::IndexBlindingColumns::new(delta_gb, delta_ev)
        .context("internal: construct LastUpdDeltaTables")?;

    let out = circuits::update_index_table_circuit(
        &mut gb,
        last_upd_table_gb,
        last_upd_table_ev,
        r,
        receiver,
    )
    .context("execute circuit")?;
    out.output(&mut gb).context("output out")?;

    Ok(())
}

pub fn update_index_evaluator<C, Rnd>(
    delta_rng: &mut Rnd,
    garbler_provides_its_table: bool,
    last_upd_table: &IndexColumn,
    channel: C,
    receiver_share: u16,
) -> Result<IndexColumn>
where
    Rnd: Rng + CryptoRng,
    C: AbstractChannel,
{
    let size = last_upd_table.size();

    let rng = AesRng::new();
    let mut ev = Evaluator::<C, AesRng, OtReceiver>::new(channel, rng)
        .map_err(|e| anyhow!("Evaluator init: {}", e))?;

    let receiver_gb = encoded::IndexShare::receive(&mut ev)
        .context("Evaluator receives encoded Garbler shares")?;
    let receiver_ev = encoded::IndexShare::encode(&mut ev, receiver_share)
        .context("Evaluator OT receives encoded Evaluator shares ")?;
    let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

    let last_upd_table_gb = match garbler_provides_its_table {
        true => Some(
            encoded::IndexColumn::receive(&mut ev, size)
                .context("receive counterparty last_upd_table")?,
        ),
        false => None,
    };
    let last_upd_table_ev =
        encoded::IndexColumn::encode(&mut ev, last_upd_table).context("encode last_upd_table")?;

    let delta_gb = encoded::IndexBlindingColumn::receive(&mut ev, size)
        .context("Evaluator receives Garbler encoded delta table")?;
    let delta_ev = encoded::IndexBlindingColumn::generate_and_encode(delta_rng, size, &mut ev)
        .context("Evaluator OT receives Evaluator encoded delta table")?;
    let r = encoded::IndexBlindingColumns::new(delta_gb, delta_ev)
        .context("internal: construct r table")?;

    let out = circuits::update_index_table_circuit(
        &mut ev,
        last_upd_table_gb,
        last_upd_table_ev,
        r,
        receiver,
    )
    .context("execute circuit")?;
    out.output(&mut ev)
        .context("output error")?
        .context("missing output")
}

pub fn batched_update_table_garbler<R, C>(
    channel: C,
    blinding_rng: &mut R,
    table_size: TableSize,
    index_column: &IndexColumn,
    index_update_strategy: circuits::UpdateIndexesStrategy,
    signals: impl IntoIterator<Item = u16>,
) -> Result<()>
where
    R: Rng + CryptoRng,
    C: AbstractChannel,
{
    {
        // Check pre-conditions
        ensure!(
            table_size.m == index_column.size(),
            "table_size ({:?}) doesn't match index column size ({})",
            table_size,
            index_column.size()
        );
    }

    let rng = AesRng::new();
    let mut gb = Garbler::<C, AesRng, OtSender>::new(channel, rng)
        .map_err(|e| anyhow!("garbler init: {}", e))?;

    let evaluator_table = encoded::lazily_receive_table(table_size);

    let blinding_table_gb =
        LocationTable::random(blinding_rng, table_size).context("generate blinding table")?;
    let blinding_table_gb = encoded::lazily_encode_table(&blinding_table_gb);
    let blinding_table_ev = encoded::lazily_receive_table(table_size);
    let blinding_table = LazilyEncodedTableExt::<Garbler<C, AesRng, OtSender>>::zip(
        blinding_table_gb,
        blinding_table_ev,
    )
    .context("construct zipped blindings table")?;

    let indexes_gb =
        encoded::IndexColumn::encode(&mut gb, &index_column).context("encode index_column")?;
    let indexes_ev =
        encoded::IndexColumn::receive(&mut gb, table_size.m).context("receive index_column")?;
    let indexes =
        encoded::IndexColumns::new(indexes_gb, indexes_ev).context("construct indexes")?;

    let blinding_column_gb = plain::IndexColumn::random(blinding_rng, table_size.m)
        .context("generate blinding column")?;
    let blinding_column_gb = encoded::IndexColumn::encode(&mut gb, &blinding_column_gb)
        .context("encode blinding column")?;
    let blinding_column_ev = encoded::IndexColumn::receive(&mut gb, table_size.m)
        .context("receive blinding_column_ev")?;
    let blinding_column = encoded::IndexColumns::new(blinding_column_gb, blinding_column_ev)
        .context("construct blinding_column")?;

    let mut encoded_signals = vec![];
    for receiver_gb in signals {
        let receiver_gb =
            encoded::IndexShare::encode(&mut gb, receiver_gb).context("encode receiver_gb")?;
        let receiver_ev = encoded::IndexShare::receive(&mut gb).context("receive receiver_ev")?;
        let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

        let location_ev =
            encoded::LocationShare::receive(&mut gb).context("receive location_ev")?;

        encoded_signals.push((receiver, location_ev));
    }

    let output_table = circuits::GarblerOutput::new();
    let output_indexes = circuits::GarblerOutput::new();

    circuits::batched_update_table_circuit(
        &mut gb,
        evaluator_table,
        blinding_table,
        indexes,
        blinding_column,
        index_update_strategy,
        encoded_signals,
        output_table,
        output_indexes,
    )
    .map(|((), ())| ())
}

pub fn batched_update_table_evaluator<'l, R, C>(
    channel: C,
    blinding_rng: &mut R,
    table: &LocationTable,
    index_column: &IndexColumn,
    index_update_strategy: circuits::UpdateIndexesStrategy,
    signals: impl IntoIterator<Item = (u16, &'l [u8])>,
) -> Result<(LocationTable, IndexColumn)>
where
    R: Rng + CryptoRng,
    C: AbstractChannel,
{
    {
        // Check pre-conditions
        ensure!(
            table.size().m == index_column.size(),
            "table_size ({:?}) doesn't match index column size ({})",
            table.size(),
            index_column.size()
        );
    }

    let rng = AesRng::new();
    let mut ev = Evaluator::<C, AesRng, OtReceiver>::new(channel, rng)
        .map_err(|e| anyhow!("garbler init: {}", e))?;

    let evaluator_table = encoded::lazily_encode_table(table);

    let blinding_table_gb = encoded::lazily_receive_table(table.size());
    let blinding_table_ev =
        LocationTable::random(blinding_rng, table.size()).context("generate blinding table")?;
    let blinding_table_ev = encoded::lazily_encode_table(&blinding_table_ev);
    let blinding_table = LazilyEncodedTableExt::<Garbler<C, AesRng, OtSender>>::zip(
        blinding_table_gb,
        blinding_table_ev,
    )
    .context("construct zipped blindings table")?;

    let indexes_gb =
        encoded::IndexColumn::receive(&mut ev, table.size().m).context("receive index_column")?;
    let indexes_ev =
        encoded::IndexColumn::encode(&mut ev, index_column).context("encode index_column")?;
    let indexes =
        encoded::IndexColumns::new(indexes_gb, indexes_ev).context("construct indexes")?;

    let blinding_column_gb = encoded::IndexColumn::receive(&mut ev, table.size().m)
        .context("receive blinding_column_gb")?;
    let blinding_column_ev = plain::IndexColumn::random(blinding_rng, table.size().m)
        .context("generate blinding column")?;
    let blinding_column_ev = encoded::IndexColumn::encode(&mut ev, &blinding_column_ev)
        .context("encode blinding column")?;
    let blinding_column = encoded::IndexColumns::new(blinding_column_gb, blinding_column_ev)
        .context("construct blinding_column")?;

    let mut encoded_signals = vec![];
    for (receiver_ev, location_share) in signals {
        ensure!(
            location_share.len() == consts::LOCATION_BYTES,
            "location share length is {}, expected {}",
            location_share.len(),
            consts::LOCATION_BYTES
        );

        let receiver_gb = encoded::IndexShare::receive(&mut ev).context("receive receiver_gb")?;
        let receiver_ev =
            encoded::IndexShare::encode(&mut ev, receiver_ev).context("encode receiver_ev")?;
        let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

        let location_ev = encoded::LocationShare::encode(&mut ev, location_share)
            .context("encode location_ev")?;

        encoded_signals.push((receiver, location_ev));
    }

    let output_table = circuits::LocationTableBuilder::new(table.size());
    let output_indexes = circuits::IndexColumnBuilder::new(table.size().m);

    circuits::batched_update_table_circuit(
        &mut ev,
        evaluator_table,
        blinding_table,
        indexes,
        blinding_column,
        index_update_strategy,
        encoded_signals,
        output_table,
        output_indexes,
    )
}
