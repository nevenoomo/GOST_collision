//! # Magma
//! This module implements the GOST block cipher Magma, but uses 2 bit bytes in oreder to
//! make the attack feasible on PC

static SBOX: [u8; 4] = [1, 3, 0, 2];

type HalfBlock = [u8; 4];
type Block = [u8; 8];
type MagmaRoundKey = [u8; 4];

macro_rules! half_blk_le {
    ($x:expr) => {{
        // Here we use the fact that our "byte" is only 2 bits in size
        // thus 4 elements take 8 bits => it can be packed in a u8.
        // IDEA This may be then reimplemented to use 64 bit values as in a standard

        let mut tmp = 0u8;
        let mut offset = 0u8;
        for e in $x.iter() {
            tmp |= *e << offset;
            offset += 2;
        }

        tmp
    }};
}

macro_rules! le_to_half_blk {
    ($x:expr, $n:expr) => {{
        let mut offset = 0;
        for i in 0..$x.len() {
            $x[i] = ($n >> offset) & 0b11;
            offset += 2;
        }
    }};
}

struct MagmaKey {
    key: [u8; 32],
}

struct MagmaKeyScheduler<'a> {
    magma_key: &'a MagmaKey,
    round_num: usize,
}

struct MagmaState {
    left: HalfBlock,
    right: HalfBlock,
}

/// A GOST block cipher. Works on 8 byte blocks. In this implementation the "byte" is 2 bits long
struct Magma {
    key: MagmaKey,
    state: MagmaState,
}

// NOTE It is assumed that the array is LE value => carry goes to the greater indexes
fn sum_mod(x: &mut [u8], y: &[u8]) {
    assert_eq!(x.len(), y.len(), "Sum operands must be of the same size");

    let len = x.len();
    let mut c = 0; //carry
    let mut tmp = 0;

    for i in 0..len {
        tmp = x[i] + y[i] + c;
        x[i] = tmp & 0b11; // take the least two bits. Equal to mod 4
        c = tmp >> 2; // everything else is carry
    }
    // mod part is automatic as we are ignoring the carry value in the last iteration
}

fn s_box(x: &mut [u8]) {
    assert_eq!(x.len(), 4, "");

    for i in 0..4 {
        x[i] = SBOX[x[i] as usize];
    }
}

fn rot11(x: &mut [u8]) {
    assert_eq!(x.len(), 4, "Rotation works only for half-block");
    let rotated = half_blk_le!(x).rotate_left(11);

    le_to_half_blk!(x, rotated);
}

fn xor(x: &mut [u8], y: &[u8]) {
    assert_eq!(x.len(), y.len(), "XOR operands must be of the same size.");

    for i in 0..x.len() {
        x[i] ^= y[i];
    }
}

impl<'a> MagmaKey {
    fn new(key: &[u8]) -> MagmaKey {
        assert_eq!(key.len(), 32, "Magma key must be of 32 bytes.");
        let mut key_copy = [0u8; 32];
        (&mut key_copy[..]).copy_from_slice(key);

        MagmaKey { key: key_copy }
    }

    fn scheduler(&'a self) -> MagmaKeyScheduler<'a> {
        MagmaKeyScheduler::new(&self)
    }
}

impl<'a> MagmaKeyScheduler<'a> {
    fn new(key: &MagmaKey) -> MagmaKeyScheduler {
        MagmaKeyScheduler {
            magma_key: key,
            round_num: 0,
        }
    }
}

impl<'a> Iterator for MagmaKeyScheduler<'a> {
    type Item = &'a [u8];

    //NOTE here the order might be broken. Try reordering hands of main
    fn next(&mut self) -> Option<Self::Item> {
        self.round_num += 1;

        match self.round_num {
            1..=24 => Some(
                &self.magma_key.key
                    [4 * (self.round_num - 1 & 0b111)..4 * ((self.round_num - 1 & 0b111) + 1)],
            ),
            25..=32 => Some(
                &self.magma_key.key[4 * (7 - (self.round_num - 1 & 0b111))
                    ..4 * (8 - (self.round_num - 1 & 0b111))],
            ),
            _ => return None,
        }
    }
}

impl<'a> DoubleEndedIterator for MagmaKeyScheduler<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.round_num += 1;

        match self.round_num {
            1..=8 => Some(
                &self.magma_key.key
                    [4 * (self.round_num - 1 & 0b111)..4 * ((self.round_num - 1 & 0b111) + 1)],
            ),
            9..=32 => Some(
                &self.magma_key.key[4 * (7 - (self.round_num - 1 & 0b111))
                    ..4 * (8 - (self.round_num - 1 & 0b111))],
            ),
            _ => return None,
        }
    }
}

impl MagmaState {
    fn new() -> MagmaState {
        MagmaState {
            left: [0u8; 4],
            right: [0u8; 4],
        }
    }
}

impl Magma {
    /// Returns a new instance of a block cipher. Takes a key as an input.
    /// # Panics
    /// Panicks if the length of the key is not 32.
    pub fn new(key: &[u8]) -> Magma {
        let key = MagmaKey::new(key);
        let state = MagmaState::new();

        Magma {
            key: key,
            state: state,
        }
    }

    /// Encrypt a single block of plaintext
    /// # Panics
    /// Panics if the length of the block is not 8 bytes.
    pub fn encrypt_block(&mut self, block: &[u8]) -> Block {
        assert_eq!(block.len(), 8, "Magma processes only 8 byte blocks");

        //NOTE this might be an error. Try switching parts of a block.
        (&mut self.state.left[..]).copy_from_slice(&block[..4]);
        (&mut self.state.right[..]).copy_from_slice(&block[4..]);

        let mut res = [0u8; 8];
        let key_scheduler = self.key.scheduler();
        let mut left = &mut self.state.left;
        let mut right = &mut self.state.right;

        for round_key in key_scheduler {
            Self::round(left, right, round_key);

            // End of the round of Feistel network: swap to halves
            let tmp = left;
            left = right;
            right = tmp;
        }

        // We write this way to undo the swapping in the last round, as it should not be there
        (&mut res[..4]).copy_from_slice(right);
        (&mut res[4..]).copy_from_slice(left);

        res
    }

    pub fn decrypt_block(&mut self, block: &[u8]) -> Block {
        assert_eq!(block.len(), 8, "Magma processes only 8 byte blocks");

        //NOTE this might be an error. Try switching parts of a block.
        (&mut self.state.left[..]).copy_from_slice(&block[..4]);
        (&mut self.state.right[..]).copy_from_slice(&block[4..]);

        let mut res = [0u8; 8];
        let key_scheduler = self.key.scheduler().rev();
        let mut left = &mut self.state.left;
        let mut right = &mut self.state.right;

        for round_key in key_scheduler {
            Self::round(left, right, round_key);

            // End of the round of Feistel network: swap to halves
            let tmp = left;
            left = right;
            right = tmp;
        }

        // We write this way to undo the swapping in the last round, as it should not be there
        (&mut res[..4]).copy_from_slice(right);
        (&mut res[4..]).copy_from_slice(left);

        res
    }

    fn round(left: &mut HalfBlock, right: &mut HalfBlock, key: &[u8]) {
        let mut tmp = right.clone();
        sum_mod(&mut tmp, key);
        s_box(&mut tmp);
        rot11(&mut tmp);
        xor(left, &tmp);
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn ecryption_decryption_test() {
        let key = [
            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 3,
            2, 1, 0,
        ];
        let block = [1, 2, 3, 0, 0, 1, 3, 2];

        let mut magma = super::Magma::new(&key);
        let ecrypted = magma.encrypt_block(&block);

        let decrypted = magma.decrypt_block(&ecrypted);

        assert_eq!(&block, &decrypted, "Initial and decrypted blocks does not match.");
    }

    #[test]
    fn key_schedule_test() {
        let key = super::MagmaKey::new(&[
            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 3,
            2, 1, 0,
        ]);
        let expected = [
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [3, 2, 1, 0],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [3, 2, 1, 0],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [3, 2, 1, 0],
            [3, 2, 1, 0],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
        ];

        let key_schedule = super::MagmaKeyScheduler::new(&key);

        for (i, roundkey) in key_schedule.enumerate() {
            assert_eq!(roundkey, &(expected[i]), "Key schedule is broken");
        }
    }

    #[test]
    fn key_schedule_rev_test() {
        let key = super::MagmaKey::new(&[
            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 3,
            2, 1, 0,
        ]);
        let expected = [
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [3, 2, 1, 0],
            [3, 2, 1, 0],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [3, 2, 1, 0],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [3, 2, 1, 0],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
            [0, 1, 2, 3],
        ];

        let key_schedule = super::MagmaKeyScheduler::new(&key).rev();

        for (i, roundkey) in key_schedule.enumerate() {
            assert_eq!(roundkey, &(expected[i]), "Key schedule is broken");
        }
    }

    #[test]
    fn sum_mod_test() {
        let mut x = [3u8, 1u8];
        let y = [1u8, 3u8];
        let expected = [0u8, 1u8];

        super::sum_mod(&mut x, &y);

        assert_eq!(&x, &expected, "Sum_mod is not working");
    }

    #[test]
    fn sbox_test() {
        let mut x = [0, 1, 2, 3];
        let expected = [1, 3, 0, 2];

        super::s_box(&mut x);

        assert_eq!(&x, &expected, "SBOX transformation does not work.");
    }

    #[test]
    fn rot11_test() {
        let mut x = [0b11, 0b10, 0b01, 0b00];
        let expected = [0b00, 0b10, 0b01, 0b11];

        super::rot11(&mut x);

        assert_eq!(&x, &expected, "Rotation does not work.");
    }

    #[test]
    fn xor_test() {
        let mut x = [0b11, 0b10, 0b01, 0b00];
        let y = [0b11, 0b00, 0b10, 0b01];
        let expected = [0b00, 0b10, 0b11, 0b01];

        super::xor(&mut x, &y);

        assert_eq!(&x, &expected, "XOR does not work.");
    }
}
