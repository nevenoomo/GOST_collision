//! # Magma
//! This module implements the GOST block cipher Magma, but uses 2 bit bytes in oreder to
//! make the attack feasible on PC

static SBOX: [u8; 4] = [1, 3, 0, 2];

type HalfBlock = u8;
type Block = u16;
type Key = u64;
type RoundKey = u8;

struct MagmaKey {
    key: Key,
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
pub struct Magma {
    key: MagmaKey,
    state: MagmaState,
}

pub mod utils {
    use super::*;

    pub fn s_box(x: HalfBlock) -> HalfBlock {
        let mut ret = 0;
        for i in 0..4 {
            let twice = i << 1;
            ret |= SBOX[((x >> twice) & 0b11) as usize] << twice;
        }

        ret
    }
}

impl<'a> MagmaKey {
    fn new(key: u64) -> MagmaKey {
        MagmaKey { key }
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
    type Item = HalfBlock;

    //NOTE here the order might be broken. Try reordering hands of main
    fn next(&mut self) -> Option<Self::Item> {
        let res = match self.round_num {
            1..=24 => Some(
                // (key >> ((round_num % 8) * 8))
                (self.magma_key.key >> ((self.round_num & 0b111) << 3)) as u8,
            ),
            25..=32 => Some(
                // reverse
                (self.magma_key.key >> ((7 - (self.round_num & 0b111)) << 3)) as u8,
            ),
            _ => None,
        };

        self.round_num += 1;

        res
    }
}

impl<'a> DoubleEndedIterator for MagmaKeyScheduler<'a> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let res = match self.round_num {
            1..=8 => Some(
                ((self.magma_key.key >> (7 - (self.round_num & 0b111)) << 3) & 0b11111111) as u8,
            ),
            9..=32 => {
                Some(((self.magma_key.key >> (self.round_num & 0b111) << 3) & 0b11111111) as u8)
            }
            _ => return None,
        };

        self.round_num += 1;

        res
    }
}

impl MagmaState {
    fn new() -> MagmaState {
        MagmaState {
            left: 0u8,
            right: 0u8,
        }
    }
}

impl Magma {
    /// Returns a new instance of a block cipher. Takes a key as an input.
    /// # Panics
    /// Panicks if the length of the key is not 32.
    pub fn new(key: u64) -> Magma {
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
    pub fn encrypt_block(&mut self, block: Block) -> Block {
        self.state.left = (block & 0xff) as u8;
        self.state.right = ((block & 0xff00) >> 8) as u8;

        let key_scheduler = self.key.scheduler();
        let left = &mut self.state.left;
        let right = &mut self.state.right;

        for round_key in key_scheduler {
            Self::round(left, right, round_key);
        }

        ((*left as u16) << 8) | (*right as u16)
    }

    /// Decrypt a single block of plaintext
    /// # Panics
    /// Panics if the length of the block is not 8 bytes.
    pub fn decrypt_block(&mut self, block: Block) -> Block {
        self.state.left = (block & 0xff) as u8;
        self.state.right = ((block & 0xff00) >> 8) as u8;

        let key_scheduler = self.key.scheduler().rev();
        let left = &mut self.state.left;
        let right = &mut self.state.right;

        for round_key in key_scheduler {
            Self::round(left, right, round_key);
        }

        // This order undos swaping on the last round
        ((*left as u16) << 8) | (*right as u16)
    }

    /// *Left* is lower bytes
    /// *Right* is upper bytes 
    pub fn round(left: &mut HalfBlock, right: &mut HalfBlock, key: RoundKey) {
        *left ^= utils::s_box(right.wrapping_add(key)).rotate_left(3); 
        std::mem::swap(left, right);
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn ecryption_decryption_test() {
        let key = 0b0001101100011011000110110001101100011011000110110001101111100100;
        let block = 0b0110110000011110;

        let mut magma = super::Magma::new(key);
        let ecrypted = magma.encrypt_block(block);

        let decrypted = magma.decrypt_block(ecrypted);

        assert_eq!(
            block, decrypted,
            "Initial and decrypted blocks does not match."
        );
    }

    #[test]
    fn key_schedule_test() {
        let key = super::MagmaKey::new(0b0001101100011011000110110001101100011011000110110001101111100100);
        let expected = [
            0b11100100, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011,
            0b11100100, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011,
            0b11100100, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011,
            0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b11100100,
        ];

        let key_schedule = super::MagmaKeyScheduler::new(&key);

        for (i, roundkey) in key_schedule.enumerate() {
            assert_eq!(roundkey, expected[i], "Key schedule is broken");
        }
    }

    #[test]
    fn key_schedule_rev_test() {
        let key = super::MagmaKey::new(0b0001101100011011000110110001101100011011000110110001101111100100);
        let expected = [
            0b11100100, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011,
            0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b11100100,
            0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b11100100,
            0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b00011011, 0b11100100,
        ];

        let key_schedule = super::MagmaKeyScheduler::new(&key).rev();

        for (i, roundkey) in key_schedule.enumerate() {
            assert_eq!(roundkey, expected[i], "Key schedule is broken");
        }
    }

    #[test]
    fn sbox_test() {
        let x = 0b00011011;
        let expected = 0b01110010;

        let res = super::utils::s_box(x);

        assert_eq!(res, expected, "SBOX transformation does not work.");
    }
}
