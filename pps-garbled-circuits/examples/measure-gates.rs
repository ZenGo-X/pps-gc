use std::iter;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use fancy_garbling::dummy::Dummy;
use fancy_garbling::informer::{Informer, InformerStats};

use stealth_address_circuits::circuits::UpdateIndexesStrategy;
use stealth_address_circuits::consts::LOCATION_BYTES;
use stealth_address_circuits::{circuits, encoded};
use stealth_address_circuits::{IndexColumn, LocationTable, TableSize};

fn main() {
    let table_new = || {
        let mut table = comfy_table::Table::new();
        table.load_preset("||  |-|||          ");
        table.set_header(iter::once("".to_string()).chain((1..=10).map(|m| format!("M={}", m))));
        table
    };

    let mut table_xor = table_new();
    let mut table_and = table_new();
    let mut table_proj = table_new();

    eprintln!("Start tiny measurements");
    for l in 1..=10 {
        let mut row_xor = vec![format!("L={}", l)];
        let mut row_and = vec![format!("L={}", l)];
        let mut row_proj = vec![format!("L={}", l)];
        for m in 1..=10 {
            eprintln!("Measure gates m={}, l={}", m, l);
            let stats = update_table_measure_gates(TableSize { m, l });
            row_xor.push((stats.num_adds() + stats.num_subs()).to_string());
            row_and.push(stats.num_muls().to_string());
            row_proj.push(stats.num_projs().to_string());
        }
        table_xor.add_row(row_xor);
        table_and.add_row(row_and);
        table_proj.add_row(row_proj);
    }
    eprintln!("Tiny measurements completed");

    println!("# Number of gates");
    println!();
    println!("## UpdateTable");
    println!();
    println!("### XOR");
    println!();
    println!("{}", table_xor);
    println!();
    println!("### AND");
    println!();
    println!("{}", table_and);
    println!();
    println!("### PROJ");
    println!();
    println!("{}", table_proj);
    println!();

    let m = 30_usize;
    let ls = (&[1000_usize, 10_000, 100_000]).iter().cloned();

    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    let headers = iter::repeat(m)
        .zip(ls.clone())
        .map(|(m, l)| format!("M={} L={}", m, l));
    table.set_header(iter::once("".to_string()).chain(headers));

    let mut row_xor = vec!["XOR".to_string()];
    let mut row_and = vec!["AND".to_string()];
    let mut row_proj = vec!["PROJ".to_string()];

    eprintln!("Start large measurements");
    for l in ls {
        eprintln!("Measure gates M={}, L={}", m, l);
        let stats = update_table_measure_gates(TableSize { m, l });
        row_xor.push((stats.num_adds() + stats.num_subs()).to_string());
        row_and.push(stats.num_muls().to_string());
        row_proj.push(stats.num_projs().to_string());
    }
    eprintln!("Large measurements completed");

    table.add_row(row_xor);
    table.add_row(row_and);
    table.add_row(row_proj);

    println!("### Large M,L");
    println!();
    println!("{}", table);
    println!();

    let ms = (1usize..=5).chain((10..=30).step_by(10));

    let table_new = || {
        let mut table = comfy_table::Table::new();
        table.load_preset("||  |-|||          ");
        table.set_header(iter::once("M=".to_string()).chain(ms.clone().map(|m| format!("{}", m))));
        table
    };

    let mut table_fst = table_new();
    let mut table_snd = table_new();

    let mut row_fst_xor = vec!["XOR".to_string()];
    let mut row_fst_and = vec!["AND".to_string()];
    let mut row_fst_proj = vec!["PROJ".to_string()];

    let mut row_snd_xor = vec!["XOR".to_string()];
    let mut row_snd_and = vec!["AND".to_string()];
    let mut row_snd_proj = vec!["PROJ".to_string()];

    for m in ms {
        let fst = update_index_table_measure_gates(m, true);
        let snd = update_index_table_measure_gates(m, false);

        row_fst_xor.push((fst.num_adds() + fst.num_subs()).to_string());
        row_snd_xor.push((snd.num_adds() + snd.num_subs()).to_string());
        row_fst_and.push(fst.num_muls().to_string());
        row_snd_and.push(snd.num_muls().to_string());
        row_fst_proj.push(fst.num_projs().to_string());
        row_snd_proj.push(snd.num_projs().to_string());
    }

    table_fst.add_row(row_fst_xor);
    table_fst.add_row(row_fst_and);
    table_fst.add_row(row_fst_proj);

    table_snd.add_row(row_snd_xor);
    table_snd.add_row(row_snd_and);
    table_snd.add_row(row_snd_proj);

    println!("## UpdateIndex");
    println!();
    println!("### First run");
    println!();
    println!("{}", table_fst);
    println!();
    println!("### Second run");
    println!();
    println!("{}", table_snd);
    println!();

    let ns = iter::once(1usize).chain((5..=25).step_by(5));
    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header(iter::once("N=".to_string()).chain(ns.clone().map(|n| n.to_string())));

    let table_size = TableSize { m: 5, l: 5 };

    let mut row_xor = vec!["XOR".to_string()];
    let mut row_and = vec!["AND".to_string()];
    let mut row_proj = vec!["PROJ".to_string()];

    for n in ns {
        eprintln!("Measure batched update for n={}", n);
        let stats = batched_update_table_measure_gates(table_size, n);
        row_xor.push((stats.num_adds() + stats.num_subs()).to_string());
        row_and.push(stats.num_muls().to_string());
        row_proj.push(stats.num_projs().to_string());
    }

    table.add_row(row_xor);
    table.add_row(row_and);
    table.add_row(row_proj);

    println!("## BatchedUpdateTable");
    println!();
    println!("### M={}, L={}", table_size.m, table_size.l);
    println!();
    println!("{}", table);
    println!();

    let l = 20;
    let ms = [100, 1000, 10000].iter();
    let ks = [5, 10, 20].iter();

    let new_table = || {
        let mut table = comfy_table::Table::new();
        table.load_preset("||  |-|||          ");
        table.set_header(iter::once("".to_string()).chain(ms.clone().map(|m| format!("M={}", m))));
        table
    };

    let mut table_xor = new_table();
    let mut table_and = new_table();
    let mut table_proj = new_table();

    for &k in ks {
        let mut row_xor = vec![format!("K={}", k)];
        let mut row_and = vec![format!("K={}", k)];
        let mut row_proj = vec![format!("K={}", k)];

        for &m in ms.clone() {
            eprintln!("Measure batched_update M={}, L={}, K={}", m, l, k);
            let stats = batched_update_table_measure_gates(TableSize { m, l }, k);
            row_xor.push((stats.num_adds() + stats.num_subs()).to_string());
            row_and.push(stats.num_muls().to_string());
            row_proj.push(stats.num_projs().to_string());
        }

        table_xor.add_row(row_xor);
        table_and.add_row(row_and);
        table_proj.add_row(row_proj);
    }

    println!("### L={}", l);
    println!();
    println!("#### XOR");
    println!();
    println!("{}", table_xor);
    println!();
    println!("#### AND");
    println!();
    println!("{}", table_and);
    println!();
    println!("#### PROJ");
    println!();
    println!("{}", table_proj);
}

fn update_table_measure_gates(table_size: TableSize) -> InformerStats {
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    let dummy = Dummy::new();
    let mut dummy = Informer::new(dummy);

    let table = LocationTable::random(&mut rng, table_size).unwrap();
    let encoded_table = encoded::lazily_encode_table(&table);

    let last_upd_table_a = IndexColumn::random(&mut rng, table_size.m).unwrap();
    let last_upd_table_b = IndexColumn::random(&mut rng, table_size.m).unwrap();
    let last_upd_table_a_encoded =
        encoded::IndexColumn::encode(&mut dummy, &last_upd_table_a).unwrap();
    let last_upd_table_b_encoded =
        encoded::IndexColumn::encode(&mut dummy, &last_upd_table_b).unwrap();
    let last_upd_table =
        encoded::IndexColumns::new(last_upd_table_a_encoded, last_upd_table_b_encoded).unwrap();

    let blinding_a = LocationTable::random(&mut rng, table_size).unwrap();
    let blinding_a = encoded::lazily_encode_table(&blinding_a);
    let blinding_b = LocationTable::random(&mut rng, table_size).unwrap();
    let blinding_b = encoded::lazily_encode_table(&blinding_b);
    let blindings = encoded::LazilyEncodedTableExt::<Dummy>::zip(blinding_a, blinding_b).unwrap();

    let receiver_a = rng.gen::<u16>();
    let receiver_b = rng.gen::<u16>();
    let receiver_a_encoded = encoded::IndexShare::encode(&mut dummy, receiver_a).unwrap();
    let receiver_b_encoded = encoded::IndexShare::encode(&mut dummy, receiver_b).unwrap();
    let receiver = encoded::Receiver::new(receiver_a_encoded, receiver_b_encoded);

    let loc: Vec<_> = iter::repeat_with(|| rng.gen::<u8>())
        .take(LOCATION_BYTES)
        .collect();
    let loc = encoded::LocationShare::encode(&mut dummy, &loc).unwrap();

    let output_builder = circuits::LocationTableBuilder::new(table_size);

    let _out = circuits::update_table_circuit(
        &mut dummy,
        encoded_table,
        last_upd_table,
        blindings,
        receiver,
        loc,
        output_builder,
    )
    .unwrap();

    dummy.stats()
}

fn update_index_table_measure_gates(m: usize, first_run: bool) -> InformerStats {
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    let dummy = Dummy::new();
    let mut dummy = Informer::new(dummy);

    let last_upd_table_gb = Some(IndexColumn::random(&mut rng, m).unwrap()).filter(|_| first_run);
    let last_upd_table_ev = IndexColumn::random(&mut rng, m).unwrap();
    let last_upd_table_gb =
        last_upd_table_gb.map(|table| encoded::IndexColumn::encode(&mut dummy, &table).unwrap());
    let last_upd_table_ev = encoded::IndexColumn::encode(&mut dummy, &last_upd_table_ev).unwrap();

    let r_gb = encoded::IndexBlindingColumn::generate_and_encode(&mut rng, m, &mut dummy).unwrap();
    let r_ev = encoded::IndexBlindingColumn::generate_and_encode(&mut rng, m, &mut dummy).unwrap();
    let r = encoded::IndexBlindingColumns::new(r_gb, r_ev).unwrap();

    let blinding = rng.gen::<u16>();
    let receiver_gb = 1 ^ blinding;
    let receiver_ev = blinding;
    let receiver_gb = encoded::IndexShare::encode(&mut dummy, receiver_gb).unwrap();
    let receiver_ev = encoded::IndexShare::encode(&mut dummy, receiver_ev).unwrap();
    let receiver = encoded::Receiver::new(receiver_gb, receiver_ev);

    let out = circuits::update_index_table_circuit(
        &mut dummy,
        last_upd_table_gb,
        last_upd_table_ev,
        r,
        receiver,
    )
    .unwrap();
    out.output(&mut dummy).unwrap().unwrap();

    dummy.stats()
}

fn batched_update_table_measure_gates(table_size: TableSize, n: usize) -> InformerStats {
    // just making random source for test reproducibility
    let mut rng = StdRng::seed_from_u64(0xea15511);

    // We start with both servers (A and B) having equal random state (`table` and `last_upd_table`)
    // which is achieved by providing equal random source.
    let table_a = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let _table_b = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let last_upd_table_a =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();
    let last_upd_table_b =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();

    // `n` signals are received. Server A obtains list `receivers_a`, and Server B obtains
    // list `receivers_b`, where `receivers_a[i] ^ receivers_b[i] == receivers[i]`
    let receivers = (0..table_size.m).cycle().take(n);
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
    let _locs_b: Vec<Vec<u8>> = locs
        .iter()
        .zip(&locs_a)
        .map(|(loc, blinding)| loc.iter().zip(blinding).map(|(a, b)| a ^ b).collect())
        .collect();

    // Running the Protocol

    let dummy = Dummy::new();
    let mut dummy = Informer::new(dummy);

    let evaluator_table = encoded::lazily_encode_table(&table_a);

    let blinding_a = LocationTable::random(&mut rng, table_size).unwrap();
    let blinding_b = LocationTable::random(&mut rng, table_size).unwrap();
    let blinding_a = encoded::lazily_encode_table(&blinding_a);
    let blinding_b = encoded::lazily_encode_table(&blinding_b);
    let blinding_table =
        encoded::LazilyEncodedTableExt::<Informer<Dummy>>::zip(blinding_a, blinding_b).unwrap();

    let indexes_a = encoded::IndexColumn::encode(&mut dummy, &last_upd_table_a).unwrap();
    let indexes_b = encoded::IndexColumn::encode(&mut dummy, &last_upd_table_b).unwrap();
    let indexes_column = encoded::IndexColumns::new(indexes_a, indexes_b).unwrap();

    let index_blinding_a = IndexColumn::random(&mut rng, table_size.m).unwrap();
    let index_blinding_b = IndexColumn::random(&mut rng, table_size.m).unwrap();
    let index_blinding_a = encoded::IndexColumn::encode(&mut dummy, &index_blinding_a).unwrap();
    let index_blinding_b = encoded::IndexColumn::encode(&mut dummy, &index_blinding_b).unwrap();
    let index_blinding = encoded::IndexColumns::new(index_blinding_a, index_blinding_b).unwrap();

    let mut encoded_signals = vec![];
    let signals = receivers_a.into_iter().zip(receivers_b).zip(locs_a);
    for ((receiver_a, receiver_b), loc_a) in signals {
        encoded_signals.push((
            encoded::Receiver::new(
                encoded::IndexShare::encode(&mut dummy, receiver_a).unwrap(),
                encoded::IndexShare::encode(&mut dummy, receiver_b).unwrap(),
            ),
            encoded::LocationShare::encode(&mut dummy, &loc_a).unwrap(),
        ))
    }

    let output_table = circuits::LocationTableBuilder::new(table_size);
    let output_indexes = circuits::IndexColumnBuilder::new(table_size.m);

    let (_new_table, _new_indexes) = circuits::batched_update_table_circuit(
        &mut dummy,
        evaluator_table,
        blinding_table,
        indexes_column,
        index_blinding,
        UpdateIndexesStrategy::A,
        encoded_signals,
        output_table,
        output_indexes,
    )
    .unwrap();

    dummy.stats()
}
