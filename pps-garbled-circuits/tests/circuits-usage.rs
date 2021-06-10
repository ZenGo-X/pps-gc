use std::iter;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use scuttlebutt::unix_channel_pair;

use stealth_address_circuits::circuits::UpdateIndexesStrategy;
use stealth_address_circuits::{
    batched_update_table_evaluator, batched_update_table_garbler, update_index_evaluator,
    update_index_garbler, update_table_evaluator, update_table_garbler, ByteArray, TableSize,
};
use stealth_address_circuits::{IndexColumn, LocationTable};

#[test]
fn update_table() {
    // just making random source for test reproducibility
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    // We start with both servers (A and B) having equal random state (`table` and `last_upd_table`)
    // which is achieved by providing equal random source.
    let table_size = TableSize { m: 3, l: 4 };
    let table_a = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let table_b = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let last_upd_table_a =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();
    let last_upd_table_b =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();

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
        update_table_garbler(&mut s, table_size, &last_upd_table, channel_a, receiver_a)
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
        update_table_garbler(
            &mut seed_b.clone(),
            table_size,
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
    let loc_a = new_table_a[receiver][0];
    let loc_b = new_table_b[receiver][0];
    let reconstructed_loc = loc_a ^ loc_b;

    assert_eq!(loc, reconstructed_loc.as_buffer());
}

#[test]
fn update_index_table() {
    // just making random source for test reproducibility
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    // We assume here that signal as partially handled and main tables are already updated.
    // We still have `last_upd_table` not updated, so both servers A and B have the same
    // `last_upd_table_a` and `last_upd_table_b` which is achieved by providing equal random source.
    let table_size = 3;
    let last_upd_table_a = IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size).unwrap();
    let last_upd_table_b = IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size).unwrap();

    // Receiver gets a signal. Server A obtains `receiver_a`, and Server B obtains `receiver_b`,
    // where `receiver_a ^ receiver_b == receiver`
    let receiver = 1;
    let receiver_a = rng.gen::<u16>();
    let receiver_b = receiver_a ^ receiver;

    // Each server acts both as garbler and evaluator (as only evaluator learns an output),
    // ie. we need to run the protocol twice swapping servers roles.

    // As first run, we run protocol where A is a garbler, and B is evaluator. Unlike updating
    // main table, first run is a bit different from the second (in the second, garbler doesn't
    // encode its `last_upd_table` due to protocol asymmetry)

    // Establish a channel between the two servers
    let (channel_a, channel_b) = unix_channel_pair();

    // Note: garbler and evaluator generate random `r` tables (see the protocol) from given
    // random source. We reuse seed to produce the same tables in both runs.
    let seed_a = StdRng::seed_from_u64(0xdead);
    let seed_b = StdRng::seed_from_u64(0xbeaf);

    // Server A acts as garbler
    let (mut s, last_upd_table) = (seed_a.clone(), last_upd_table_a.clone());
    let handle = std::thread::spawn(move || {
        update_index_garbler(
            &mut s,
            table_size,
            Some(&last_upd_table),
            channel_a,
            receiver_a,
        )
    });

    // Server B is an evaluator
    let new_table_b = update_index_evaluator(
        &mut seed_b.clone(),
        true,
        &last_upd_table_b,
        channel_b,
        receiver_b,
    )
    .unwrap();
    handle.join().unwrap().unwrap();

    // Establish channel for the second run
    let (channel_a, channel_b) = unix_channel_pair();

    // Server B acts as garbler
    let mut s = seed_b.clone();
    let handle = std::thread::spawn(move || {
        update_index_garbler(&mut s, table_size, None, channel_b, receiver_b)
    });

    // Server A is an evaluator
    let new_table_a = update_index_evaluator(
        &mut seed_a.clone(),
        false,
        &last_upd_table_a,
        channel_a,
        receiver_a,
    )
    .unwrap();
    handle.join().unwrap().unwrap();

    // Reconstructing last_upd_index table
    let actual_table: Vec<_> = new_table_a
        .receivers()
        .zip(new_table_b.receivers())
        .map(|(a, b)| (*a ^ *b).as_buffer().clone())
        .collect();
    let expected_table: Vec<_> = vec![0, 1, 0]
        .into_iter()
        .map(|i: u16| i.to_be_bytes())
        .collect();

    assert_eq!(actual_table, expected_table);
}

#[test]
fn batched_update_table() {
    // just making random source for test reproducibility
    let mut rng = StdRng::seed_from_u64(0xea15511);

    // We start with both servers (A and B) having equal random state (`table` and `last_upd_table`)
    // which is achieved by providing equal random source.
    let table_size = TableSize { m: 5, l: 5 };
    let table_a = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let table_b = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let last_upd_table_a =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();
    let last_upd_table_b =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();

    // `n` signals are received. Server A obtains list `receivers_a`, and Server B obtains
    // list `receivers_b`, where `receivers_a[i] ^ receivers_b[i] == receivers[i]`
    let n = table_size.m * 2;

    let receivers =
        // ie. every receiver gets 2 signals
        (0..table_size.m).chain(0..table_size.m);
    let receivers_a: Vec<u16> = iter::repeat_with(|| rng.gen()).take(n).collect();
    let receivers_b: Vec<u16> = receivers
        .zip(&receivers_a)
        .map(|(receiver, blinding)| receiver as u16 ^ blinding)
        .collect();

    // List of received signals. In the similar way, A receives `locs_a`, B receives `locs_b`,
    // where `locs_a[i] ^ locs_b[i] == locs[i]`
    let mut gen_loc = || {
        iter::repeat_with(|| rng.gen())
            .take(32)
            .collect::<Vec<u8>>()
    };
    let locs: Vec<Vec<u8>> = iter::repeat_with(&mut gen_loc).take(n).collect();
    let locs_a: Vec<Vec<u8>> = iter::repeat_with(gen_loc).take(n).collect();
    let locs_b: Vec<Vec<u8>> = locs
        .iter()
        .zip(&locs_a)
        .map(|(loc, blinding)| loc.iter().zip(blinding).map(|(a, b)| a ^ b).collect())
        .collect();

    //
    // Running the Protocol
    //
    // P.S. Each server acts both as garbler and evaluator (as only evaluator learns an output),
    // ie. we need to run the protocol twice swapping servers roles.
    //

    // Establish a channel between the two servers
    let (channel_a, channel_b) = unix_channel_pair();

    // Note: batched_update_table_garbler and batched_update_table_evaluator generate random blinding
    // tables (see the protocol) from given random source. We reuse seed to produce the same tables.
    let seed_a = StdRng::seed_from_u64(0xdead);
    let seed_b = StdRng::seed_from_u64(0xbeaf);

    // Server A acts as garbler
    let (mut s, last_upd_table, receivers) = (
        seed_a.clone(),
        last_upd_table_a.clone(),
        receivers_a.clone(),
    );
    let handle = std::thread::spawn(move || {
        batched_update_table_garbler(
            channel_a,
            &mut s,
            table_size,
            &last_upd_table,
            UpdateIndexesStrategy::A,
            receivers,
        )
    });

    let (new_table_b, new_indexes_b) = batched_update_table_evaluator(
        channel_b,
        &mut seed_b.clone(),
        &table_b,
        &last_upd_table_b,
        UpdateIndexesStrategy::A,
        receivers_b
            .iter()
            .zip(&locs_b)
            .map(|(&r, l)| (r, l.as_slice())),
    )
    .unwrap();
    handle.join().unwrap().unwrap();

    //
    // Servers swap their roles!
    //

    // Establish channel for the second run
    let (channel_a, channel_b) = unix_channel_pair();

    // Server B acts as garbler
    let last_upd_table = last_upd_table_b.clone();
    let handle = std::thread::spawn(move || {
        batched_update_table_garbler(
            channel_b,
            &mut seed_b.clone(),
            table_size,
            &last_upd_table,
            UpdateIndexesStrategy::B,
            receivers_b,
        )
    });

    // Server A is an evaluator
    let (new_table_a, new_indexes_a) = batched_update_table_evaluator(
        channel_a,
        &mut seed_a.clone(),
        &table_a,
        &last_upd_table_a,
        UpdateIndexesStrategy::B,
        receivers_a
            .iter()
            .zip(&locs_a)
            .map(|(&r, l)| (r, l.as_slice())),
    )
    .unwrap();
    handle.join().unwrap().unwrap();

    //
    // Protocol is finished!
    //

    // Reconstructing and asserting last_upd_table
    for i in 0..table_size.m as u16 {
        assert_eq!(
            new_indexes_a[i] ^ new_indexes_b[i],
            ByteArray::new(2u16.to_be_bytes()),
            "every receiver should have got exactly two signals"
        )
    }

    // Reconstructing and asserting the locations table
    for i in 0..table_size.m as u16 {
        // First received signal
        assert_eq!(
            (new_table_a[i][0] ^ new_table_b[i][0]).as_buffer(),
            locs[i as usize].as_slice()
        );
        // Second received signal
        assert_eq!(
            (new_table_a[i][1] ^ new_table_b[i][1]).as_buffer(),
            locs[table_size.m + i as usize].as_slice()
        );

        // Rest of locations are empty (zeros)
        for j in 2..table_size.m {
            assert_eq!(
                new_table_a[i][j] ^ new_table_b[i][j],
                ByteArray::new([0u8; 32])
            );
        }
    }
}
