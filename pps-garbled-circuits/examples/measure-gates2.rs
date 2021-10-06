use std::iter;

use chrono::Utc;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use fancy_garbling::dummy::Dummy;
use fancy_garbling::informer::{Informer, InformerStats};

use stealth_address_circuits::circuits::UpdateIndexesStrategy;
use stealth_address_circuits::consts::LOCATION_BYTES;
use stealth_address_circuits::{circuits, encoded};
use stealth_address_circuits::{IndexColumn, LocationTable, TableSize};

fn main() {
    println!("# UpdateTable (L=50)");
    println!();
    for m in 1..=100 {
        let l = 50;
        eprintln!("UpdateTable M={}, started={}", m, Utc::now());
        let stats = update_table_measure_gates(TableSize { m, l });
        let xor = stats.num_adds() + stats.num_subs();
        let and = stats.num_muls();
        let proj = stats.num_projs();
        println!("* M={}: XOR={}, AND={}, PROJ={}", m, xor, and, proj);
    }
    println!();
    println!("# UpdateIndex");
    println!();
    for m in 1..=100 {
        eprintln!("UpdateIndex M={}, started={}", m, Utc::now());
        let stats = update_index_table_measure_gates(m, true);
        let xor = stats.num_adds() + stats.num_subs();
        let and = stats.num_muls();
        let proj = stats.num_projs();
        println!("* M={}: XOR={}, AND={}, PROJ={}", m, xor, and, proj);
    }
    println!();
    println!("# BatchedUpdateTable (L=50, K=10)");
    println!();
    for m in 1..=100 {
        eprintln!("BatchedUpdateTable M={}, started={}", m, Utc::now());
        let stats = batched_update_table_measure_gates(TableSize { m, l: 50 }, 10);
        let xor = stats.num_adds() + stats.num_subs();
        let and = stats.num_muls();
        let proj = stats.num_projs();
        println!("* M={}: XOR={}, AND={}, PROJ={}", m, xor, and, proj);
    }
    println!();
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
