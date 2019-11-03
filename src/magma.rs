//! # Magma
//! This module implements the GOST block cipher Magma, but uses 2 bit bytes in oreder to
//! make the attack feasible on PC

static SBOX: [u8; 4] = [1, 3, 0, 2];

type HalfBlock = [u8; 4];
type Block = [u8; 8];
type MagmaKey = [u8; 32];
type MagmaRoundKey = [u8; 4];

struct MagmaKeySchedule {
    key: MagmaKey,
    round_num: usize,
}

struct MagmaState {
    left: HalfBlock,
    right: HalfBlock,
}

struct Magma {
    state: MagmaState,
    key_schedule: MagmaKeySchedule,
}

impl MagmaKeySchedule {
    fn new(key: &MagmaKey) -> MagmaKeySchedule {
        let mut key_copy = [0u8; 32];
        (&mut key_copy[..]).copy_from_slice(key);

        MagmaKeySchedule {
            key: key_copy,
            round_num: 0,
        }
    }
}

//UGLY it should return a slice of the key field
impl Iterator for MagmaKeySchedule {
    type Item = MagmaRoundKey;

    //NOTE here the order might be broken. Try reordering hands of main
    fn next(&mut self) -> Option<Self::Item> {
        let mut res = [0u8; 4];

        match self.round_num {
            0..=23 => (&mut res[..]).copy_from_slice(
                &self.key[4 * (self.round_num & 0b111)..4 * ((self.round_num & 0b111) + 1)],
            ),
            24..=31 => (&mut res[..]).copy_from_slice(
                &self.key[4 * (7 - (self.round_num & 0b111))..4 * ((7 - (self.round_num & 0b111)) + 1)],
            ),
            _ => return None,
        }

        self.round_num += 1;
        Some(res)
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn key_schedule_test() {
        let key = [
            0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 3,
            2, 1, 0,
        ];
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

        let key_schedule = super::MagmaKeySchedule::new(&key);

        for (i, roundkey) in key_schedule.enumerate() {
            assert_eq!(&roundkey, &(expected[i]), "Key schedule is broken");
        }
    }
}
