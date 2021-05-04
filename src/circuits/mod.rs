#![allow(dead_code)] // TODO: remove it

use anyhow::{anyhow, ensure, Context, Result};
use rand::{CryptoRng, Rng};

use fancy_garbling::twopac::semihonest::{Evaluator, Garbler};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{AbstractChannel, AesRng};

use auxiliary_tables::{
    EncodedLastUpdTable, EncodedLastUpdTables, EvaluatorTable, LocationDeltaTable,
    LocationDeltaTables,
};
use shares::{IndexShare, LocationShare, R};
use table::{LastUpdTable, LocationTable};
use update_table::update_table_circuit;

mod auxiliary_tables;
mod byte_array;
mod shares;
mod table;
mod update_last_upd_table;
mod update_table;
mod utils;

mod consts {
    use std::mem::size_of;
    pub const LOCATION_BYTES: usize = 32; // 256 bits
    pub const INDEX_BYTES: usize = size_of::<u16>(); // 16 bits
}

pub fn update_table_garbler<C, Rnd, const M: usize, const L: usize>(
    delta_rng: &mut Rnd,
    // _table: &Table<M, L>,
    last_upd_table: &LastUpdTable<M>,
    channel: C,
    receiver_share: u16,
) -> Result<()>
where
    Rnd: Rng + CryptoRng,
    C: AbstractChannel,
{
    let rng = AesRng::new();
    let mut gb = Garbler::<C, AesRng, OtSender>::new(channel, rng)
        .map_err(|e| anyhow!("garbler init: {}", e))?;

    let receiver_gb = IndexShare::encode(&mut gb, receiver_share)
        .context("Garbler encodes his shares and sends to Evaluator")?;
    let receiver_ev =
        IndexShare::receive(&mut gb).context("Garbler OT sends encoded Evaluator shares")?;
    let receiver = R::new(receiver_gb, receiver_ev);

    let location_ev = LocationShare::receive(&mut gb).context("Garbler OT sends location share")?;

    let last_upd_table_gb = EncodedLastUpdTable::encode(&mut gb, last_upd_table)
        .context("Garbler encodes last_upd_table and sends to Evaluator")?;

    let last_upd_table_ev = EncodedLastUpdTable::receive(&mut gb)
        .context("Garbler OT sends encoded last_upd_table of Evaluator")?;

    let last_upd_table = EncodedLastUpdTables::new(last_upd_table_gb, last_upd_table_ev);

    let table_ev = EvaluatorTable::receive(&mut gb).context("receive counterparty table")?;

    let delta_gb = LocationDeltaTable::<_, M, L>::generate_and_encode(delta_rng, &mut gb)
        .context("generate and encode delta table")?;
    let delta_ev = LocationDeltaTable::<_, M, L>::receive(&mut gb)
        .context("Garbler OT sends Evaluator delta table")?;
    let r = LocationDeltaTables::new(delta_gb, delta_ev);

    let out = update_table_circuit(&mut gb, table_ev, last_upd_table, r, receiver, location_ev)
        .context("execute circuit")?;

    out.output(&mut gb).context("output out")?;

    Ok(())
}

pub fn update_table_evaluator<C, Rnd, const M: usize, const L: usize>(
    delta_rng: &mut Rnd,
    table: &LocationTable<M, L>,
    last_upd_table: &LastUpdTable<M>,
    channel: C,
    receiver_share: u16,
    location_share: &[u8],
) -> Result<LocationTable<M, L>>
where
    Rnd: Rng + CryptoRng,
    C: AbstractChannel,
{
    ensure!(
        location_share.len() == consts::LOCATION_BYTES,
        "wrong location_share length (expected {}, actual{})",
        consts::LOCATION_BYTES,
        location_share.len()
    );

    let rng = AesRng::new();
    let mut ev = Evaluator::<C, AesRng, OtReceiver>::new(channel, rng)
        .map_err(|e| anyhow!("Evaluator init: {}", e))?;

    let receiver_gb =
        IndexShare::receive(&mut ev).context("Evaluator receives encoded Garbler shares")?;
    let receiver_ev = IndexShare::encode(&mut ev, receiver_share)
        .context("Evaluator OT receives encoded Evaluator shares ")?;
    let receiver = R::new(receiver_gb, receiver_ev);

    let location_ev =
        LocationShare::encode(&mut ev, location_share).context("encode location_share")?;

    let last_upd_table_gb =
        EncodedLastUpdTable::receive(&mut ev).context("receive counterparty last_upd_table")?;
    let last_upd_table_ev =
        EncodedLastUpdTable::encode(&mut ev, last_upd_table).context("encode last_upd_table")?;
    let last_upd_table = EncodedLastUpdTables::new(last_upd_table_gb, last_upd_table_ev);

    let table_ev = EvaluatorTable::encode(&mut ev, table).context("encode table")?;

    let delta_gb = LocationDeltaTable::<_, M, L>::receive(&mut ev)
        .context("receive counterparty delta table")?;
    let delta_ev = LocationDeltaTable::<_, M, L>::generate_and_encode(delta_rng, &mut ev)
        .context("generate and encode delta table")?;
    let r = LocationDeltaTables::new(delta_gb, delta_ev);

    let out = update_table_circuit(&mut ev, table_ev, last_upd_table, r, receiver, location_ev)
        .context("execute circuit")?;

    let table = out
        .output(&mut ev)
        .context("output out")?
        .context("garbled circuit didn't output the table")?;

    Ok(table)
}

#[cfg(test)]
mod tests {
    use std::iter;

    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use scuttlebutt::unix_channel_pair;

    use super::table::{LastUpdTable, LocationTable};
    use super::{update_table_evaluator, update_table_garbler};

    #[test]
    fn evaluator_updates_table() {
        // just making random source for test reproducibility
        let mut rng = StdRng::seed_from_u64(0xbaddad);

        // We start with both servers (A and B) having equal random state (`table` and `last_upd_table`)
        // which is achieved by providing equal random source.
        let table_a = LocationTable::<3, 4>::random(&mut StdRng::seed_from_u64(1));
        let table_b = LocationTable::<3, 4>::random(&mut StdRng::seed_from_u64(1));
        let last_upd_table_a = LastUpdTable::<3>::random(&mut StdRng::seed_from_u64(2));
        let last_upd_table_b = LastUpdTable::<3>::random(&mut StdRng::seed_from_u64(2));

        // Receiver gets a signal. Server A obtains `receiver_a`, and Server B obtains `receiver_b`,
        // where `receiver_a ^ receiver_b == receiver`
        let receiver = 1;
        let receiver_a = rng.gen::<u16>();
        let receiver_b = receiver_a ^ receiver;

        // Location is any 32 bytes sequence. In the similar way, A receives `loc_a`, B receives `loc_b`,
        // where `loc_a ^ loc_b == loc`
        let loc: &[u8; 32] = b"hi, anonymus signal message here";
        let loc_a: Vec<_> = iter::repeat_with(|| rng.gen::<u8>()).take(32).collect();
        let loc_b: Vec<_> = loc.iter().zip(&loc_a).map(|(a, b)| a ^ b).collect();

        // Each server acts both as garbler and evaluator (as only evaluator learns an output),
        // ie. we need to run the protocol twice swapping servers roles.

        // Establish a channel between the two servers
        let (channel_a, channel_b) = unix_channel_pair();

        // Note: update_table_garbler and update_table_evaluator generate random `r` tables
        // (see the protocol) from given random source. We reuse seed to produce the same tables.
        let seed_a = StdRng::seed_from_u64(0xdead);
        let seed_b = StdRng::seed_from_u64(0xbeaf);

        // Server A acts as garbler
        let (mut s, last_upd_table) = (seed_a.clone(), last_upd_table_a.clone());
        let handle = std::thread::spawn(move || {
            update_table_garbler::<_, _, 3, 4>(&mut s, &last_upd_table, channel_a, receiver_a)
        });

        // Server B is an evaluator
        let new_table_b = update_table_evaluator(
            &mut seed_b.clone(),
            &table_b,
            &last_upd_table_b,
            channel_b,
            receiver_b,
            &loc_b,
        )
        .unwrap();
        handle.join().unwrap().unwrap();

        // Establish channel for the second run
        let (channel_a, channel_b) = unix_channel_pair();

        // Server B acts as garbler
        let handle = std::thread::spawn(move || {
            update_table_garbler::<_, _, 3, 4>(
                &mut seed_b.clone(),
                &last_upd_table_b,
                channel_b,
                receiver_b,
            )
        });

        // Server A is an evaluator
        let new_table_a = update_table_evaluator(
            &mut seed_a.clone(),
            &table_a,
            &last_upd_table_a,
            channel_a,
            receiver_a,
            &loc_a,
        )
        .unwrap();
        handle.join().unwrap().unwrap();

        // Reconstructing signal from servers' tables.
        let loc_a = new_table_a[receiver as usize][0];
        let loc_b = new_table_b[receiver as usize][0];
        let reconstructed_loc: Vec<_> = loc_a
            .as_buffer()
            .iter()
            .zip(loc_b.as_buffer().iter())
            .map(|(a, b)| a ^ b)
            .collect();

        assert_eq!(&loc[..], &reconstructed_loc);
    }
}
