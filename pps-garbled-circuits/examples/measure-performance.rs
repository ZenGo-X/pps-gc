use std::iter;
use std::time::Instant;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use scuttlebutt::unix_channel_pair;

use stealth_address_circuits::circuits::UpdateIndexesStrategy;
use stealth_address_circuits::{
    batched_update_table_evaluator, batched_update_table_garbler, update_index_evaluator,
    update_index_garbler, update_table_evaluator, update_table_garbler, TableSize,
};
use stealth_address_circuits::{IndexColumn, LocationTable};

fn main() {
    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header(vec![
        "".to_string(),
        "M=10".to_string(),
        "M=100".to_string(),
        "M=1000".to_string(),
    ]);

    for &l in &[10, 100, 1000] {
        let mut row = vec![format!("L={}", l)];
        for &m in &[10, 100, 1000] {
            if l == 1000 && m == 1000 {
                // it's too much
                row.push("—".to_string());
                continue;
            }
            let now = Instant::now();
            update_table(TableSize { m, l });
            let elapsed = now.elapsed();
            println!("update_table M={}, l={}, took {:?}", m, l, elapsed);

            row.push(format!("{:?}", elapsed))
        }
    }

    println!("# Performance");
    println!();
    println!("## UpdateTable");
    println!();
    println!("{}", table);
    println!();

    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header((1..=5).map(|e| format!("M=10^{}", e)));

    let mut row = vec![];
    for m in (1..=5).map(|e| 10usize.pow(e)) {
        let now = Instant::now();

        update_index_table(m);

        let elapsed = now.elapsed();
        println!("update_index M={}, took {:?}", m, elapsed);
        row.push(format!("{:?}", elapsed))
    }
    table.add_row(row);

    println!("## UpdateIndex");
    println!();
    println!("{}", table);
    println!();

    let ns = iter::once(1usize).chain((5..=25).step_by(5));
    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header(iter::once("N=".to_string()).chain(ns.clone().map(|n| n.to_string())));

    let table_size = TableSize { m: 10, l: 10 };

    let mut row = vec!["Took=".to_string()];

    for n in ns {
        let now = Instant::now();

        batched_update_table(table_size, n);

        let elapsed = now.elapsed();
        println!("batched_update_table n={}, took {:?}", n, elapsed);
        row.push(format!("{:?}", elapsed))
    }

    table.add_row(row);

    println!("## BatchedUpdateTable");
    println!();
    println!("### M={}, L={}", table_size.m, table_size.l);
    println!();
    println!("{}", table);
    println!();

    let l = 20;
    let ms = [100, 1000, 10000].iter();
    let ks = [5, 10, 20].iter();

    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header(iter::once("".to_string()).chain(ms.clone().map(|m| format!("M={}", m))));

    for &k in ks {
        let mut row = vec![format!("K={}", k)];

        for &m in ms.clone() {
            let now = Instant::now();

            batched_update_table(TableSize { m, l }, k);

            let elapsed = now.elapsed();
            eprintln!(
                "Measure batched_update: M={} L={}, K={}, took={:?}",
                m, l, k, elapsed
            );
            row.push(format!("{:?}", elapsed));
        }

        table.add_row(row);
    }

    println!("### L={}", l);
    println!();
    println!("{}", table);
    println!();
}

fn update_table(table_size: TableSize) {
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
}

fn update_index_table(table_size: usize) {
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

    let _new_table_b =
        update_index_evaluator(&mut seed_b, true, &last_upd_table_b, channel_b, receiver_b)
            .unwrap();
    handle.join().unwrap().unwrap();
}

fn batched_update_table(table_size: TableSize, n: usize) {
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
}
