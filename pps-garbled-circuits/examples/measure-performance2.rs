use std::iter;
use std::time::{Duration, Instant};

use chrono::Utc;
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};

use scuttlebutt::unix_channel_pair;

use stealth_address_circuits::circuits::UpdateIndexesStrategy;
use stealth_address_circuits::{
    batched_update_table_evaluator, batched_update_table_garbler, update_index_evaluator,
    update_index_garbler, update_table_evaluator, update_table_garbler, TableSize,
};
use stealth_address_circuits::{IndexColumn, LocationTable};

fn main() {
    println!("# UpdateTable");
    println!();
    for l in [25, 50, 75] {
        println!("## L={}", l);
        println!();

        for m in 1..=100 {
            let mut average_time = Duration::default();
            let experiments_n = 25;

            for i in 0..experiments_n {
                eprintln!("UpdateTable L={} M={} i={} started={}", l, m, i, Utc::now());
                average_time = average_time
                    .checked_add(update_table(TableSize { l, m }))
                    .unwrap();
            }
            let average_time = average_time.checked_div(experiments_n).unwrap();
            println!("* M={}: {:?}", m, average_time);
        }
        println!();
    }
    println!("# UpdateIndex");
    println!();
    for m in 1..=100 {
        let mut average_time = Duration::default();
        let experiments_n = 25;

        for i in 0..experiments_n {
            eprintln!("UpdateIndex M={} i={} started={}", m, i, Utc::now());
            average_time = average_time.checked_add(update_index_table(m)).unwrap();
        }
        let average_time = average_time.checked_div(experiments_n).unwrap();
        println!("* M={}: {:?}", m, average_time);
    }
    println!();
    println!("# BatchedUpdateTable (L = 50)");
    println!();
    for k in [1, 5, 10] {
        println!("## K={}", k);
        println!();
        let l = 50;

        for m in 1..=100 {
            let mut average_time = Duration::default();
            let experiments_n = 25;

            for i in 0..experiments_n {
                eprintln!(
                    "BatchedUpdateTable L={} M={} K={} i={} started={}",
                    l,
                    m,
                    k,
                    i,
                    Utc::now()
                );
                average_time = average_time
                    .checked_add(batched_update_table(TableSize { l, m }, k))
                    .unwrap();
            }
            let average_time = average_time.checked_div(experiments_n).unwrap();
            println!("* M={}: {:?}", m, average_time);
        }
        println!();
    }
}

fn update_table(table_size: TableSize) -> Duration {
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    let table_b = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let last_upd_table_a =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();
    let last_upd_table_b =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();

    let receiver = rng.gen_range(0, table_size.m as u16);
    let receiver_a = rng.gen::<u16>();
    let receiver_b = receiver_a ^ receiver;

    let loc: &[u8; 32] = b"hi, anonymus signal message here";
    let loc_a: Vec<_> = iter::repeat_with(|| rng.gen::<u8>()).take(32).collect();
    let loc_b: Vec<_> = loc.iter().zip(&loc_a).map(|(a, b)| a ^ b).collect();

    let (channel_a, channel_b) = unix_channel_pair();

    let seed_a = StdRng::seed_from_u64(0xdead);
    let seed_b = StdRng::seed_from_u64(0xbeaf);

    let (mut s, last_upd_table) = (seed_a.clone(), last_upd_table_a.clone());
    let handle = std::thread::spawn(move || {
        update_table_garbler(&mut s, table_size, &last_upd_table, channel_a, receiver_a)
    });

    let start = Instant::now();
    let _new_table_b = update_table_evaluator(
        &mut seed_b.clone(),
        &table_b,
        &last_upd_table_b,
        channel_b,
        receiver_b,
        &loc_b,
    )
    .unwrap();
    handle.join().unwrap().unwrap();
    start.elapsed()
}

fn update_index_table(table_size: usize) -> Duration {
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    let last_upd_table_a = IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size).unwrap();
    let last_upd_table_b = IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size).unwrap();

    let receiver = rng.gen_range(0, table_size as u16);
    let receiver_a = rng.gen::<u16>();
    let receiver_b = receiver_a ^ receiver;

    let (channel_a, channel_b) = unix_channel_pair();

    let mut seed_a = StdRng::seed_from_u64(0xdead);
    let mut seed_b = StdRng::seed_from_u64(0xbeaf);

    let handle = std::thread::spawn(move || {
        update_index_garbler(
            &mut seed_a,
            table_size,
            Some(&last_upd_table_a),
            channel_a,
            receiver_a,
        )
    });

    let start = Instant::now();
    let _new_table_b =
        update_index_evaluator(&mut seed_b, true, &last_upd_table_b, channel_b, receiver_b)
            .unwrap();
    handle.join().unwrap().unwrap();
    start.elapsed()
}

fn batched_update_table(table_size: TableSize, n: usize) -> Duration {
    let mut rng = StdRng::seed_from_u64(0xea15511);

    let table_b = LocationTable::random(&mut rng, table_size).unwrap();
    let last_upd_table_a = IndexColumn::random(&mut rng, table_size.m).unwrap();
    let last_upd_table_b = IndexColumn::random(&mut rng, table_size.m).unwrap();

    let receivers = (0..table_size.m).cycle().take(n);
    let receivers_a: Vec<u16> = iter::repeat_with(|| rng.gen()).take(n).collect();
    let receivers_b: Vec<u16> = receivers
        .zip(&receivers_a)
        .map(|(receiver, blinding)| receiver as u16 ^ blinding)
        .collect();

    let mut gen_loc = || {
        let mut loc = vec![0u8; 32];
        rng.fill_bytes(&mut loc);
        loc
    };
    let locs: Vec<Vec<u8>> = iter::repeat_with(&mut gen_loc).take(n).collect();
    let locs_a: Vec<Vec<u8>> = iter::repeat_with(gen_loc).take(n).collect();
    let locs_b: Vec<Vec<u8>> = locs
        .iter()
        .zip(&locs_a)
        .map(|(loc, blinding)| loc.iter().zip(blinding).map(|(a, b)| a ^ b).collect())
        .collect();

    // Running the Protocol

    // Establish a channel between the two servers
    let (channel_a, channel_b) = unix_channel_pair();

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

    let start = Instant::now();
    let (_new_table_b, _new_indexes_b) = batched_update_table_evaluator(
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
    start.elapsed()
}
