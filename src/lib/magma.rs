//! # Magma
//! This module implements the GOST block cipher Magma, but uses 2 bit bytes in oreder to
//! make the attack feasible on PC

static SBOX: [u8;4] = [1, 3, 0, 2];

type HalfBlock = [u8; 4];
type Block = [u8; 8];
type MagmaKey = [u8; 32];
type MagmaRoundKey = [u8; 4];

struct MagmaKeySchedule {
    key: MagmaKey,
    round_num: u8,
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
    fn new(key: &MagmaKey[..]) -> MagmaKeySchedule {
        let mut key = [0u8; 32];
        &key[..].clone_from_slice(key);
        
        MagmaKeySchedule{
            key: key,
            round_num: 0,
        }
    }
}

impl Iterator for MagmaKeySchedule {
    type Item = &MagmaRoundKey;

    // DEBUG this might be the source of errors, because it is not clear, which order to use.
    fn next(&mut self) -> Option<Self::Item> {
        let roundkey_num = match self.round_num { 
            0...23 => self.round_num & 0b111u8, // round_num mod 8
            24...31 => 7 - self.round_num & 0b111u8,
            _ => {return None}
        };

        &self.key[4*roundkey_num..4*(roundkey_num+1)]
    }  
}

#[cfg(test)]
mod test {

    #[test]
    fn key_schedule_test() {
        let test_key = [0u8..32u8];
        let roundkeys: [super::MagmaRoundKey, 32] = [
            
        ];
        let mut key_schedule = super::MagmaKeySchedule::new(&key);
        
        for roundkey in key_schedule {
            assert_eq!();
        }
    }

}