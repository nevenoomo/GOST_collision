//! # Get GOST collision
//! This is a CLI interface for the library module ***gost_collision***, which finds a collision
//! given a state block with symmetric first quater.

use GOST_collision::gost_collision;
use std::env;

fn main() {
    let h = parse_args();

    let mut attacker = gost_collision::GostAttack::new(&h);
    let collision = attacker.generate_collision();

    print_collision(collision);
}

fn parse_args() -> Vec<u8> {
    let mut args = env::args().skip(1); // skipping the name of the program
    let h = collect_block(args.next().expect("State block should be provided"));
    if h.len() != 32 {
        panic!("The state should be of size 32");
    }

    if &h[..4] != &h[4..8] {
        panic!("The first quater of the block is not symmetric, the attack won't work.");
    }
    
    for num in h.iter() {
        if *num > 3 {
            panic!("The elements of the state block should be from 0 to 3");
        }
    }

    h
}

fn collect_block(block: String) -> Vec<u8> {
    block
        .split(' ')
        .map(|x| x.parse::<u8>().expect("Incorrect characters in blocks"))
        .collect()
}

fn print_collision(c: ([u8;32], [u8; 32])){
    println!("M1: {:#?}", c.0);
    println!("M1: {:#?}", c.1);
}


