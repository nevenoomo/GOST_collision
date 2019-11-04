//! # GOST hash function
//! This module implements a GOST hash function with a constraint that the one "byte" consists of 2 bits.
use crate::magma::Magma;

type Block = [u8; 8];
type State = [u8; 32];
type Key = State;
type SubState = Block;

#[derive(Default)]
struct IntermediateKeys(Key, Key, Key, Key);
#[derive(Default)]
struct IntermediateState(SubState, SubState, SubState, SubState);

struct GostHash {
    state: State,
}

impl IntermediateState {
    fn to_state(&self) -> State {
        let mut s: State = Default::default();

        (&s[..8]).copy_from_slice(&self.0);
        (&s[8..16]).copy_from_slice(&self.1);
        (&s[16..24]).copy_from_slice(&self.2);
        (&s[24..32]).copy_from_slice(&self.3);

        s
    }
}

impl GostHash {
    pub fn new() -> GostHash {
        GostHash { state: [0u8; 32] }
    }

    pub fn compress(h: &State, m: &Block) -> State {
        let k = Self::key_gen(m);
        let mut s: IntermediateState = Default::default();
        (&s.0).copy_from_slice(&h[..8]);
        (&s.1).copy_from_slice(&h[8..16]);
        (&s.2).copy_from_slice(&h[16..24]);
        (&s.3).copy_from_slice(&h[24..32]);

        s.0 = Magma::new(k.0).encrypt_block(&s.0);
        s.1 = Magma::new(k.1).encrypt_block(&s.1);
        s.2 = Magma::new(k.2).encrypt_block(&s.2);
        s.3 = Magma::new(k.3).encrypt_block(&s.3);

        Self::output_transformation(s.to_state(), h, m)
    }
}
