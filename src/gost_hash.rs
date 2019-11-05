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

fn xor(x: &[u8], y: &[u8]) -> Vec<u8> {
    assert_eq!(x.len(), y.len(), "XOR operands must be of the same size.");
    let mut res = x.to_vec();

    for i in 0..x.len() {
        res[i] ^= y[i];
    }

    res
}

impl IntermediateState {
    fn to_state(&self) -> State {
        let mut s: State = Default::default();

        (&mut s[..8]).copy_from_slice(&self.0);
        (&mut s[8..16]).copy_from_slice(&self.1);
        (&mut s[16..24]).copy_from_slice(&self.2);
        (&mut s[24..32]).copy_from_slice(&self.3);

        s
    }
}

impl GostHash {
    pub fn new() -> GostHash {
        GostHash { state: [0u8; 32] }
    }

    /// Gost compression function.
    /// **Takes** a state and a message block as input and **returns** the next state. Both are of size 32 bytes.
    pub fn compress(h: &State, m: &State) -> State {
        let k = Self::key_gen(h, m);
        let mut s: IntermediateState = Default::default();
        (&mut s.0).copy_from_slice(&h[..8]);
        (&mut s.1).copy_from_slice(&h[8..16]);
        (&mut s.2).copy_from_slice(&h[16..24]);
        (&mut s.3).copy_from_slice(&h[24..32]);

        s.0 = Magma::new(&k.0).encrypt_block(&s.0);
        s.1 = Magma::new(&k.1).encrypt_block(&s.1);
        s.2 = Magma::new(&k.2).encrypt_block(&s.2);
        s.3 = Magma::new(&k.3).encrypt_block(&s.3);

        Self::output_transformation(&s.to_state(), h, m)
    }

    fn key_gen(h: &State, m: &State) -> IntermediateKeys {
        let c = [
            0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00, 0x03, 0x03, 0x00, 0x03, 0x00, 0x03, 0x00,
            0x03, 0x00, 0x00, 0x03, 0x03, 0x00, 0x03, 0x00, 0x00, 0x03, 0x03, 0x00, 0x00, 0x00,
            0x03, 0x03, 0x00, 0x03,
        ];
        let mut cur_h: &[u8] = h;
        let mut cur_m: &[u8] = m;

        // Step 1. Here c == 0
        let k0 = Self::p(xor(cur_h, cur_m).as_slice());

        // Step 2. Here c == 0
        let tmp1 = Self::a(cur_h);
        let tmp2 = Self::a(&Self::a(cur_m)[..]);
        cur_h = &tmp1;
        cur_m = &tmp2;
        let k1 = Self::p(xor(cur_h, cur_m).as_slice());

        // Step 3. Here c == that thig on top (0xff -> 0x03 as we have only 2 bits)
        let tmp1 = xor(&Self::a(cur_h), &c);
        let tmp2 = Self::a(&Self::a(cur_m)[..]);
        cur_h = tmp1.as_slice();
        cur_m = &tmp2;
        let k2 = Self::p(xor(cur_h, cur_m).as_slice());
        // Step 4. Here c == 0
        let tmp1 = Self::a(cur_h);
        let tmp2 = Self::a(&Self::a(cur_m));
        cur_h = &tmp1;
        cur_m = &tmp2;
        let k3 = Self::p(xor(cur_h, cur_m).as_slice());

        IntermediateKeys(k0, k1, k2, k3)
    }

    fn p(x: &[u8]) -> Key {
        let mut k: Key = [0u8; 32];

        for i in 1..32 {
            k[i - 1] = x[Self::phi(i) - 1];
        }

        k
    }

    // phi(i + 1 + 4*(k-1)) = 8*i + k, i=0..3, k=1..8
    fn phi(x: usize) -> usize {
        let k = ((x - 1) >> 2) + 1; // == (x-1)/4 + 1
        let i = (x - 1) & 0b11; // == x - 1 mod 4 == (i + 4(k-1)) mod 4 == i

        8 * i + k
    }

    fn a(x: &[u8]) -> State {
        let mut s: State = [0u8; 32];
        (&mut s[..24]).copy_from_slice(&x[8..]); // y2 || y3 || y4
        (&mut s[24..]).copy_from_slice(xor(&x[..8], &x[8..16]).as_slice()); // (y1 xor y2)

        s
    }

    fn psy(x: &[u8]) -> State {
        let mut s: State = [0u8; 32];
        (&mut s[..30]).copy_from_slice(&x[2..]); // gamma1 || gamma2 || gamma3 || gamma4 || .. || gamma15
        let mut tmp = xor(&x[..2], &x[2..4]); // gamma0 xor gamma1
        tmp = xor(tmp.as_slice(), &x[4..6]); // gamma0 xor gamma1 xor gamma2
        tmp = xor(tmp.as_slice(), &x[6..8]); // gamma0 xor gamma1 xor gamma2 xor gamma3
        tmp = xor(tmp.as_slice(), &x[24..26]); // gamma0 xor gamma1 xor gamma2 xor gamma3 xor gamma12
        tmp = xor(tmp.as_slice(), &x[30..32]); // gamma0 xor gamma1 xor gamma2 xor gamma3 xor gamma12 xor gamma15
        (&mut s[30..]).copy_from_slice(tmp.as_slice());

        s
    }

    fn psy_rev(x: &[u8]) -> State {
        let mut s: State = [0u8; 32];

        (&mut s[2..]).copy_from_slice(&x[..30]); // gamma1 || gamma2 || gamma3 || gamma4 || .. || gamma15
        let mut tmp = xor(&x[30..], &s[30..]); // (gamma0 xor gamma1 xor gamma2 xor gamma3 xor gamma12 xor gamma15) xor gamma15 => gamma15 is gone
        tmp = xor(tmp.as_slice(), &s[24..26]); // (gamma0 xor gamma1 xor gamma2 xor gamma3 xor gamma12) xor gamma12 => gamma12 is gone
        tmp = xor(tmp.as_slice(), &s[6..8]); // (gamma0 xor gamma1 xor gamma2 xor gamma3) xor gamma3 => gamma3 is gone
        tmp = xor(tmp.as_slice(), &s[4..6]); // (gamma0 xor gamma1 xor gamma2) xor gamma2 => gamma2 is gone
        tmp = xor(tmp.as_slice(), &s[2..4]); // (gamma0 xor gamma1) xor gamma1 => gamma1 is gone, only gamma0 is left
        (&mut s[..2]).copy_from_slice(tmp.as_slice()); // push gamma0

        s
    }

    fn psy_pow(x: &[u8], n: i32) -> State {
        let mut tmp = [0u8; 32];
        (&mut tmp[..]).copy_from_slice(x);

        if n >= 0 {
            for i in 0..n {
                tmp = Self::psy(&tmp);
            }
        } else {
            for i in 0..(-n) {
                tmp = Self::psy_rev(&tmp);
            }
        }

        tmp
    }

    fn output_transformation(s: &[u8], h: &[u8], m: &[u8]) -> State {
        let mut res = [0u8; 32];

        // h_i = psy^61(h_i-1 xor psy(m xor psy^12(s)))
        res = Self::psy_pow(s, 12);
        res = Self::psy(xor(m, &res).as_slice());
        let tmp = xor(h, &res);
        res.copy_from_slice(tmp.as_slice());
        res = Self::psy_pow(&res, 61);
        res
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn naive_compression_test() {
        let h = [
            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0,
            1, 2, 3,
        ];
        let m = [
            3, 1, 3, 0, 2, 3, 0, 1, 3, 1, 3, 0, 2, 3, 0, 1, 3, 1, 3, 0, 2, 3, 0, 1, 3, 1, 3, 0, 2,
            3, 0, 1,
        ];

        let res = super::GostHash::compress(&h, &m);
    }
}
