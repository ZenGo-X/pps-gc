use std::os::unix::net::UnixStream;
use std::{cell::RefCell, rc::Rc};
use std::{io, iter};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use scuttlebutt::{AbstractChannel, Block, Block512, TrackChannel};

use stealth_address_circuits::circuits::UpdateIndexesStrategy;
use stealth_address_circuits::{
    batched_update_table_evaluator, batched_update_table_garbler, update_index_evaluator,
    update_index_garbler, update_table_evaluator, update_table_garbler, TableSize,
};
use stealth_address_circuits::{IndexColumn, LocationTable};

fn main() {
    let table_new = || {
        let mut table = comfy_table::Table::new();
        table.load_preset("||  |-|||          ");
        table
    };

    let mut table_gb2ev = table_new();
    let mut table_ev2gb = table_new();

    table_gb2ev.set_header(iter::once("".to_string()).chain((1..=10).map(|m| format!("M={}", m))));
    table_ev2gb.set_header(iter::once("".to_string()).chain((1..=10).map(|m| format!("M={}", m))));

    for l in 1..=10 {
        let mut row_gb2ev = vec![format!("L={}", l)];
        let mut row_ev2gb = vec![format!("L={}", l)];

        for m in 1..=10 {
            eprintln!("Measuring communication for M={}, L={}", m, l);
            let size = update_table(TableSize { m, l });
            row_gb2ev.push(format!("{:.2}", size.garbler_to_evaluator_kb));
            row_ev2gb.push(format!("{:.2}", size.evaluator_to_garbler_kb));
        }

        table_gb2ev.add_row(row_gb2ev);
        table_ev2gb.add_row(row_ev2gb);
    }

    println!("# Communication size");
    println!();
    println!("## UpdateTable");
    println!();
    println!("### Garbler to Evaluator");
    println!();
    println!("{}", table_gb2ev);
    println!();
    println!("### Evaluator to Garbler");
    println!();
    println!("{}", table_ev2gb);
    println!();

    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header(iter::once("".to_string()).chain((1..=3).map(|e| format!("M=10^{}", e))));

    for (l_e, l) in (1..=3).map(|e| (e, 10usize.pow(e))) {
        let mut row = vec![format!("L=10^{}", l_e)];
        for (m_e, m) in (1..=3).map(|e| (e, 10usize.pow(e))) {
            if m_e == 3 && l_e == 3 {
                // that's too much
                row.push("—".to_string());
                continue;
            }
            eprintln!("Measuring communication for M={}, L={}", m, l);
            let size = update_table(TableSize { m, l });
            row.push(format!(
                "{:.2}",
                size.garbler_to_evaluator_kb + size.evaluator_to_garbler_kb
            ));
        }
        table.add_row(row);
    }

    println!("### For large M, L");
    println!();
    println!("{}", table);
    println!();

    let mut table = comfy_table::Table::new();
    table.load_preset("||  |-|||          ");
    table.set_header((1..=5).map(|e| format!("M=10^{}", e)));

    let mut row = vec![];
    for m in (1..=5).map(|e| 10usize.pow(e)) {
        let size = update_index_table(m);
        row.push(format!(
            "{:.2}",
            size.garbler_to_evaluator_kb + size.evaluator_to_garbler_kb
        ))
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

    let table_size = TableSize { m: 5, l: 5 };

    let mut row_gb2ev = vec!["Garbler to Evaluator".to_string()];
    let mut row_ev2gb = vec!["Evaluator to Garbler".to_string()];

    for n in ns {
        let comm = batched_update_table(table_size, n);
        row_gb2ev.push(format!("{:.2} KB", comm.garbler_to_evaluator_kb));
        row_ev2gb.push(format!("{:.2} KB", comm.evaluator_to_garbler_kb));
    }

    table.add_row(row_gb2ev);
    table.add_row(row_ev2gb);

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
            eprintln!("Measure batched_update: M={} L={}, K={}", m, l, k);
            let comm = batched_update_table(TableSize { m, l }, k);
            row.push(format!(
                "{} KB",
                comm.garbler_to_evaluator_kb + comm.evaluator_to_garbler_kb
            ));
        }

        table.add_row(row);
    }

    println!("### L={}", l);
    println!();
    println!("{}", table);
    println!();
}

struct CommunicationSize {
    garbler_to_evaluator_kb: f64,
    evaluator_to_garbler_kb: f64,
}

fn update_table(table_size: TableSize) -> CommunicationSize {
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    let _table_a = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let table_b = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let last_upd_table_a =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();
    let last_upd_table_b =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();

    let receiver = 1;
    let receiver_a = rng.gen::<u16>();
    let receiver_b = receiver_a ^ receiver;

    let loc: &[u8; 32] = b"hi, anonymus signal message here";
    let loc_a: Vec<_> = iter::repeat_with(|| rng.gen::<u8>()).take(32).collect();
    let loc_b: Vec<_> = loc.iter().zip(&loc_a).map(|(a, b)| a ^ b).collect();

    let (channel_a, channel_b) = UnixStream::pair().unwrap();
    let channel_b = TrackChannel::new(
        io::BufReader::new(channel_b.try_clone().unwrap()),
        io::BufWriter::new(channel_b),
    );
    let channel_b = Rc::new(RefCell::new(channel_b));

    let seed_a = StdRng::seed_from_u64(0xdead);
    let seed_b = StdRng::seed_from_u64(0xbeaf);

    let (mut s, last_upd_table) = (seed_a.clone(), last_upd_table_a.clone());
    let handle = std::thread::spawn(move || -> anyhow::Result<(f64, f64)> {
        let channel_a = TrackChannel::new(
            io::BufReader::new(channel_a.try_clone().unwrap()),
            io::BufWriter::new(channel_a),
        );
        let channel_a = Rc::new(RefCell::new(channel_a));
        update_table_garbler(
            &mut s,
            table_size,
            &last_upd_table,
            ChannelRef(channel_a.clone()),
            receiver_a,
        )?;
        let channel_a = channel_a.borrow();
        Ok((channel_a.kilobytes_written(), channel_a.kilobytes_read()))
    });

    let _new_table_b = update_table_evaluator(
        &mut seed_b.clone(),
        &table_b,
        &last_upd_table_b,
        ChannelRef(channel_b.clone()),
        receiver_b,
        &loc_b,
    )
    .unwrap();
    let (channel_a_written, channel_a_read) = handle.join().unwrap().unwrap();

    assert!(f64::abs(channel_a_written - channel_b.borrow().kilobytes_read()) < 1e-6);
    assert!(f64::abs(channel_a_read - channel_b.borrow().kilobytes_written()) < 1e-6);

    CommunicationSize {
        garbler_to_evaluator_kb: channel_a_written,
        evaluator_to_garbler_kb: channel_a_read,
    }
}

fn update_index_table(table_size: usize) -> CommunicationSize {
    let mut rng = StdRng::seed_from_u64(0xbaddad);

    let last_upd_table_a = IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size).unwrap();
    let last_upd_table_b = IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size).unwrap();

    let receiver = rng.gen_range(0, table_size as u16);
    let receiver_a = rng.gen::<u16>();
    let receiver_b = receiver_a ^ receiver;

    let (channel_a, channel_b) = UnixStream::pair().unwrap();
    let channel_b = TrackChannel::new(
        io::BufReader::new(channel_b.try_clone().unwrap()),
        io::BufWriter::new(channel_b),
    );
    let channel_b = Rc::new(RefCell::new(channel_b));

    let mut seed_a = StdRng::seed_from_u64(0xdead);
    let mut seed_b = StdRng::seed_from_u64(0xbeaf);

    let handle = std::thread::spawn(move || {
        let channel_a = TrackChannel::new(
            io::BufReader::new(channel_a.try_clone().unwrap()),
            io::BufWriter::new(channel_a),
        );
        let channel_a = Rc::new(RefCell::new(channel_a));
        update_index_garbler(
            &mut seed_a,
            table_size,
            Some(&last_upd_table_a),
            ChannelRef(channel_a.clone()),
            receiver_a,
        )
        .unwrap();
        let channel_a = channel_a.borrow();
        (channel_a.kilobytes_written(), channel_a.kilobytes_read())
    });

    let _new_table_b = update_index_evaluator(
        &mut seed_b,
        true,
        &last_upd_table_b,
        ChannelRef(channel_b.clone()),
        receiver_b,
    )
    .unwrap();
    let (channel_a_written, channel_a_read) = handle.join().unwrap();

    assert!(f64::abs(channel_a_written - channel_b.borrow().kilobytes_read()) < 1e-6);
    assert!(f64::abs(channel_a_read - channel_b.borrow().kilobytes_written()) < 1e-6);

    CommunicationSize {
        garbler_to_evaluator_kb: channel_a_written,
        evaluator_to_garbler_kb: channel_a_read,
    }
}

fn batched_update_table(table_size: TableSize, n: usize) -> CommunicationSize {
    let mut rng = StdRng::seed_from_u64(0xea15511);

    let _table_a = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let table_b = LocationTable::random(&mut StdRng::seed_from_u64(1), table_size).unwrap();
    let last_upd_table_a =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();
    let last_upd_table_b =
        IndexColumn::random(&mut StdRng::seed_from_u64(2), table_size.m).unwrap();

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
    let locs_b: Vec<Vec<u8>> = locs
        .iter()
        .zip(&locs_a)
        .map(|(loc, blinding)| loc.iter().zip(blinding).map(|(a, b)| a ^ b).collect())
        .collect();

    // Running the Protocol

    let (channel_a, channel_b) = UnixStream::pair().unwrap();
    let channel_b = TrackChannel::new(
        io::BufReader::new(channel_b.try_clone().unwrap()),
        io::BufWriter::new(channel_b),
    );
    let channel_b = Rc::new(RefCell::new(channel_b));

    let seed_a = StdRng::seed_from_u64(0xdead);
    let seed_b = StdRng::seed_from_u64(0xbeaf);

    // Server A acts as garbler
    let (mut s, last_upd_table, receivers) = (
        seed_a.clone(),
        last_upd_table_a.clone(),
        receivers_a.clone(),
    );
    let handle = std::thread::spawn(move || -> anyhow::Result<(f64, f64)> {
        let channel_a = TrackChannel::new(
            io::BufReader::new(channel_a.try_clone().unwrap()),
            io::BufWriter::new(channel_a),
        );
        let channel_a = Rc::new(RefCell::new(channel_a));
        batched_update_table_garbler(
            ChannelRef(channel_a.clone()),
            &mut s,
            table_size,
            &last_upd_table,
            UpdateIndexesStrategy::A,
            receivers,
        )?;
        let channel_a = channel_a.borrow();
        Ok((channel_a.kilobytes_written(), channel_a.kilobytes_read()))
    });

    let (_new_table_b, _new_indexes_b) = batched_update_table_evaluator(
        ChannelRef(channel_b.clone()),
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
    let (channel_a_written, channel_a_read) = handle.join().unwrap().unwrap();

    assert!(f64::abs(channel_a_written - channel_b.borrow().kilobytes_read()) < 1e-6);
    assert!(f64::abs(channel_a_read - channel_b.borrow().kilobytes_written()) < 1e-6);

    CommunicationSize {
        garbler_to_evaluator_kb: channel_a_written,
        evaluator_to_garbler_kb: channel_a_read,
    }
}

struct ChannelRef<C>(Rc<RefCell<C>>);

impl<C> AbstractChannel for ChannelRef<C>
where
    C: AbstractChannel,
{
    fn read_bytes(&mut self, bytes: &mut [u8]) -> io::Result<()> {
        self.0.borrow_mut().read_bytes(bytes)
    }

    fn write_bytes(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.borrow_mut().write_bytes(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.borrow_mut().flush()
    }

    fn clone(&self) -> Self
    where
        Self: Sized,
    {
        ChannelRef(self.0.clone())
    }

    fn read_vec(&mut self, nbytes: usize) -> io::Result<Vec<u8>> {
        self.0.borrow_mut().read_vec(nbytes)
    }

    fn write_bool(&mut self, b: bool) -> io::Result<()> {
        self.0.borrow_mut().write_bool(b)
    }

    fn read_bool(&mut self) -> io::Result<bool> {
        self.0.borrow_mut().read_bool()
    }

    fn write_u8(&mut self, s: u8) -> io::Result<()> {
        self.0.borrow_mut().write_u8(s)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        self.0.borrow_mut().read_u8()
    }

    fn write_u16(&mut self, s: u16) -> io::Result<()> {
        self.0.borrow_mut().write_u16(s)
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        self.0.borrow_mut().read_u16()
    }

    fn write_u32(&mut self, s: u32) -> io::Result<()> {
        self.0.borrow_mut().write_u32(s)
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        self.0.borrow_mut().read_u32()
    }

    fn write_u64(&mut self, s: u64) -> io::Result<()> {
        self.0.borrow_mut().write_u64(s)
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        self.0.borrow_mut().read_u64()
    }

    fn write_usize(&mut self, s: usize) -> io::Result<()> {
        self.0.borrow_mut().write_usize(s)
    }

    fn read_usize(&mut self) -> io::Result<usize> {
        self.0.borrow_mut().read_usize()
    }

    fn write_block(&mut self, b: &Block) -> io::Result<()> {
        self.0.borrow_mut().write_block(b)
    }

    fn read_block(&mut self) -> io::Result<Block> {
        self.0.borrow_mut().read_block()
    }

    fn read_blocks(&mut self, n: usize) -> io::Result<Vec<Block>> {
        self.0.borrow_mut().read_blocks(n)
    }

    fn write_block512(&mut self, b: &Block512) -> io::Result<()> {
        self.0.borrow_mut().write_block512(b)
    }

    fn read_block512(&mut self) -> io::Result<Block512> {
        self.0.borrow_mut().read_block512()
    }

    // fn write_pt(&mut self, pt: &RistrettoPoint) -> io::Result<()> {
    //     self.0.write_pt(pt)
    // }
    //
    // fn read_pt(&mut self) -> io::Result<RistrettoPoint> {
    //     self.0.read_pt()
    // }
}
