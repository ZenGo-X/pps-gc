use anyhow::{anyhow, Context};

use fancy_garbling::{
    twopac::semihonest::{Evaluator, Garbler},
    Fancy, FancyInput,
};
use ocelot::ot::{AlszReceiver as OtReceiver, AlszSender as OtSender};
use scuttlebutt::{unix_channel_pair, AesRng, UnixChannel};

const MOD: u16 = 2;

mod circuits;

fn main() -> anyhow::Result<()> {
    let (sender, receiver) = unix_channel_pair();
    let handle = std::thread::spawn(move || party1(0, sender).unwrap());
    party2(1, receiver).context("eval party2")?;
    handle.join().unwrap();
    Ok(())
}

fn adder_circuit<F: Fancy>(
    circuit: &mut F,
    a: &F::Item,
    b: &F::Item,
) -> anyhow::Result<(F::Item, Option<u16>)> {
    let out = circuit
        .add(a, b)
        .map_err(|e| anyhow!("construct out wire: {:?}", e))?;
    let output = circuit
        .output(&out)
        .map_err(|e| anyhow!("set out wire: {:?}", e))?;
    Ok((out, output))
}

fn party1(input: u16, channel: UnixChannel) -> anyhow::Result<()> {
    let rng = AesRng::new();
    let mut gb =
        Garbler::<UnixChannel, AesRng, OtSender>::new(channel, rng).context("garbler init")?;

    println!("Garbler :: Initialization");

    let a = gb.encode(input, MOD).context("encode")?;
    let b = gb.receive(MOD).context("receive")?;
    let (_, outputs) = adder_circuit(&mut gb, &a, &b).context("eval")?;

    println!("Garbler :: Outputs: {:?}", outputs);

    Ok(())
}

fn party2(input: u16, channel: UnixChannel) -> anyhow::Result<()> {
    let rng = AesRng::new();
    let mut ev =
        Evaluator::<UnixChannel, AesRng, OtReceiver>::new(channel, rng).context("evaluator init")?;

    println!("Evaluator :: Initialization");

    let a = ev.receive(MOD).context("receive")?;
    let b = ev.encode(input, MOD).context("encode")?;
    let (_, outputs) = adder_circuit(&mut ev, &a, &b).context("eval")?;

    println!("Evaluator :: Outputs: {:?}", outputs);

    Ok(())
}
