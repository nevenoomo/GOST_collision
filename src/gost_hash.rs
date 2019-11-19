//! # GOST hash function
//! This module implements a GOST hash function with a constraint that the one "byte" consists of 2 bits.
use crate::magma::Magma;

type Block = u16;
type State = u64;
type Key = State;
type SubState = Block;

#[derive(Default)]
struct IntermediateKeys(Key, Key, Key, Key);

#[derive(Default)]
struct IntermediateState(SubState, SubState, SubState, SubState);

pub struct GostHash {
    _state: State,
}

impl IntermediateState {
    fn to_state(&self) -> State {
        let mut s: State = Default::default();

        s |= self.0 as State;
        s |= (self.1 as State) << 16;
        s |= (self.2 as State) << 32;
        s |= (self.3 as State) << 48;

        s
    }

    fn from_state(&mut self, s: State){
        self.0 = s as SubState;
        self.1 = (s >> 16) as SubState;
        self.2 = (s >> 32) as SubState;
        self.3 = (s >> 48) as SubState;
    }
}

impl GostHash {
    pub fn new() -> GostHash {
        GostHash { _state: 0 }
    }

    /// Gost compression function.
    /// **Takes** a state and a message block as input and **returns** the next state. Both are of size 32 bytes.
    pub fn compress(h: State, m: State) -> State {
        let k = Self::key_gen(h, m);
        let mut s: IntermediateState = Default::default();

        s.from_state(h);
        
        s.0 = Magma::new(k.0).encrypt_block(s.0);
        s.1 = Magma::new(k.1).encrypt_block(s.1);
        s.2 = Magma::new(k.2).encrypt_block(s.2);
        s.3 = Magma::new(k.3).encrypt_block(s.3);

        Self::output_transformation(s.to_state(), h, m)
    }

    fn key_gen(h: State, m: State) -> IntermediateKeys {
        let c = 0b1100111100000011110000110011110000110011001100111100110011001100;
        let mut cur_h = h;
        let mut cur_m = m;

        // Step 1. Here c == 0
        let k0 = Self::p(cur_h ^ cur_m);

        // Step 2. Here c == 0
        cur_h = Self::a(cur_h);
        cur_m = Self::a(Self::a(cur_m));
        let k1 = Self::p(cur_h ^ cur_m);

        // Step 3. Here c == that thig on top (0xff -> 0x03 as we have only 2 bits)
        cur_h = Self::a(cur_h) ^ c;
        cur_m = Self::a(Self::a(cur_m));
        let k2 = Self::p(cur_h ^ cur_m);

        // Step 4. Here c == 0
        cur_h = Self::a(cur_h);
        cur_m = Self::a(Self::a(cur_m));
        let k3 = Self::p(cur_h ^ cur_m);

        IntermediateKeys(k0, k1, k2, k3)
    }

    fn p(x: State) -> Key {
        let mut k = 0;

        for i in 1..32 {
            // k[i - 1] = x[phi(i) - 1]
            k |= ((x >> ((Self::phi(i)-1) << 1)) & 0b11) << ((i-1) << 1);
        }

        k
    }

    pub fn p_rev(k: Key) -> State {
        let mut x = 0;

        for i in 1..32 {
           // x[phi(i) - 1] = k[i - 1];
           x |= ((k >> ((i-1) << 1)) & 0b11) << ((Self::phi(i)-1) << 1);
        }

        x
    }

    // phi(i + 1 + 4*(k-1)) = 8*i + k, i=0..3, k=1..8
    fn phi(x: usize) -> usize {
        let k = ((x - 1) >> 2) + 1; // == (x-1)/4 + 1
        let i = (x - 1) & 0b11; // == x - 1 mod 4 == (i + 4(k-1)) mod 4 == i

        8 * i + k
    }

    fn a(x: State) -> State {
        // x = y4 || y3 || y2 || y1
        let mut s: State = Default::default();

        s |= x >> 16; // y4 || y3 || y2
        s |= ((x & 0xffff) ^ (s & 0xffff)) << 48; // (y1 xor y2) || y4 || y3 || y2

        s
    }

    fn psy(x: State) -> State {
        let mut s: State = Default::default(); 

        s |= x >> 4; // ? || gamma15 || .. || gamma1 
        // gamma0 ^ gamma1 ^ gamma2 ^ gamma3 ^ gamma12 ^ gamma15
        let acc = (x & 0xf) ^ ((x >> 4) & 0xf) ^ ((x >> 8) & 0xf) ^ ((x >> 12) & 0xf) ^ ((x >> 48) & 0xf) ^ ((x >> 60) & 0xf); 
        s |= acc << 60; // (XOR) || gamma15 || .. || gamma1 
        
        s
    }

    fn psy_rev(x: State) -> State {
        let mut s: State = Default::default();

        s |= x << 4; // gamma15 || .. || gamma1
        let sum = x >> 60; // gamma0 ^ gamma1 ^ gamma2 ^ gamma3 ^ gamma12 ^ gamma15
        // gamma1 ^ gamma2 ^ gamma3 ^ gamma12 ^ gamma15
        let gamma0 = sum ^ (x & 0xf) ^ ((x >> 4) & 0xf) ^ ((x >> 8) & 0xf) ^ ((x >> 44) & 0xf) ^ ((x >> 56) & 0xf);
        s |= gamma0;
        
        s
    }

    pub fn psy_pow(x: State, n: i32) -> State {
        let mut tmp = x;

        if n >= 0 {
            for _ in 0..n {
                tmp = Self::psy(tmp);
            }
        } else {
            for _ in 0..(-n) {
                tmp = Self::psy_rev(tmp);
            }
        }

        tmp
    }

    fn output_transformation(s: State, h: State, m: State) -> State {
        // h_i = psy^61(h_i-1 xor psy(m xor psy^12(s)))
        Self::psy_pow(h ^ Self::psy(m ^ Self::psy_pow(s, 12)), 61)
    }
}
