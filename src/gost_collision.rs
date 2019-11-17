//! # GOST Collission
//! Finds a pair of message blocks, which both result in the same value after applying the GOST hash compersstion function.
//! This works with the constraint that one "byte" is 2 bits long.
use crate::gost_hash;
use crate::magma;
use rand::Rng;
use std::collections::{HashMap, HashSet};

macro_rules! le_to_blk {
    ($x:expr, $n:expr) => {{
        let mut offset = 0;
        for i in 0..$x.len() {
            $x[i] = (($n >> offset) & 0b11) as u8;
            offset += 2;
        }
    }};
}

struct GostAttackContext {
    h: Box<[u8; 32]>,
    d: Box<[u8; 8]>,
    fixed_points: Box<HashSet<[u8; 32]>>,
}

pub struct GostAttack {
    ctx: Box<GostAttackContext>,
}

impl GostAttack {
    pub fn new(h: &[u8]) -> GostAttack {
        assert_eq!(h.len(), 32, "State argument must be of 32 bytes");
        let mut tmp = [0u8; 32];
        (&mut tmp[..]).copy_from_slice(h);

        let mut res = GostAttack {
            ctx: Box::new(GostAttackContext {
                h: Box::new(tmp),
                d: Box::new([0u8; 8]),
                fixed_points: Box::new(HashSet::new()),
            }),
        };

        res.calculate_d();

        res
    }
    pub fn generate_collision(&mut self) -> ([u8; 32], [u8; 32]) {
        loop {
            self.find_fixed_points();
            if let Some(collision) = self.get_collision() {
                return collision;
            }
        }
    }

    fn fill_rnd(c: &mut [u8]) {
        let mut rnd_gen = rand::thread_rng();
        let rnd = rnd_gen.gen::<u16>();
        le_to_blk!(c, rnd);
    }

    fn calculate_d(&mut self) {
        let mut c = [0u8; 8];

        Self::fill_rnd(&mut c);
        let y = gost_hash::GostHash::psy_pow(&self.ctx.h[..], -12);
        magma::utils::xor(&mut c, &y[..8]); // c xor psy^-12(h), this comes from the z0
        let y = gost_hash::GostHash::psy_pow(&y, -1);
        magma::utils::xor(&mut c, &y[..8]); // d1 xor psy^-13(h), this is y0 actually

        self.ctx.d = Box::new(c);
    }

    fn find_fixed_points(&mut self) {
        let mut i = 0;

        while self.ctx.fixed_points.len() < 16777216 {
            // (2^24)
            self.find_fixed_points_round(i);
            i += 1;
        }
    }

    fn find_fixed_points_round(&mut self, i: usize) {
        let mut d1 = [0u8; 8];
        le_to_blk!(&mut d1, i);
        let mut d2 = d1;

        magma::utils::xor(&mut d2, &self.ctx.d[..]);
        let l = self.seek_forward(&d1);
        self.seek_backward(l, &d2);
    }

    fn seek_forward(&self, d1: &[u8]) -> Box<HashMap<[u8; 8], [u8; 16]>> {
        let mut half_key = [0u8; 16];
        let mut l = Box::new(HashMap::new()); // 2^16

        for half_key_num in 0..std::u32::MAX {
            le_to_blk!(half_key, half_key_num);

            if !Self::check_equasion(&half_key, d1, true) {
                let mut block = [0u8; 8];
                let mut left = [0u8; 4];
                let mut right = [0u8; 4];

                (&mut left).copy_from_slice(&self.ctx.h[..4]);
                (&mut right).copy_from_slice(&self.ctx.h[4..8]);

                magma::Magma::round(&mut left, &mut right, &half_key[..4]);
                magma::Magma::round(&mut left, &mut right, &half_key[4..8]);
                magma::Magma::round(&mut left, &mut right, &half_key[8..12]);
                magma::Magma::round(&mut left, &mut right, &half_key[12..16]);

                (&mut block[..4]).copy_from_slice(&left);
                (&mut block[4..]).copy_from_slice(&right);

                l.insert(block, half_key);
            }
        }

        l
    }

    fn seek_backward(&mut self, l: Box<HashMap<[u8; 8], [u8; 16]>>, d2: &[u8]) {
        let mut half_key = [0u8; 16]; // sk4 .. sk7

        for half_key_num in 0..std::u32::MAX {
            le_to_blk!(half_key, half_key_num);

            if !Self::check_equasion(&half_key, d2, false) {
                let mut block = [0u8; 8];
                let mut left = [0u8; 4];
                let mut right = [0u8; 4];

                (&mut left).copy_from_slice(&self.ctx.h[..4]);
                (&mut right).copy_from_slice(&self.ctx.h[4..8]);

                magma::Magma::round(&mut left,&mut right, &half_key[..4]);
                magma::Magma::round(&mut left,&mut right, &half_key[4..8]);
                magma::Magma::round(&mut left,&mut right, &half_key[8..12]);
                magma::Magma::round(&mut left,&mut right, &half_key[12..16]);

                (&mut block[..4]).copy_from_slice(&left);
                (&mut block[4..]).copy_from_slice(&right);

                if l.contains_key(&block) {
                    let mut key = [0u8; 32];
                    (&mut key[..16]).copy_from_slice(l.get(&block).unwrap());
                    (&mut key[16..]).copy_from_slice(&half_key);

                    self.ctx.fixed_points.insert(self.convert_to_message(key));
                }
            }
        }
    }

    fn convert_to_message(&self, key: [u8; 32]) -> [u8; 32] {
        let mut tmp = gost_hash::GostHash::p_rev(&key);
        magma::utils::xor(&mut tmp, &self.ctx.h[..]);

        tmp
    }

    /// Check, whether equasion A_i * k = d_i holds for a given k, d_i and i
    /// if first_half is true, then equasion for A_1 is computed
    /// else equasion for A_2 is computed
    fn check_equasion(half_key: &[u8], d: &[u8], first_half: bool) -> bool {
        let mut mock_key = [0u8; 32];
        if first_half {
            (&mut mock_key[..16]).copy_from_slice(half_key);
        } else {
            (&mut mock_key[16..]).copy_from_slice(half_key);
        }

        (&Self::apply_operator(&mock_key)) == d
    }

    fn apply_operator(k0: &[u8]) -> [u8; 8] {
        assert_eq!(k0.len(), 32, "apply_operator argument must be of 32 bytes");

        let ret_tmp = gost_hash::GostHash::psy_pow(&gost_hash::GostHash::p_rev(&k0[..]), -12);
        let mut ret = [0u8; 8];
        (&mut ret[..]).copy_from_slice(&ret_tmp[..8]);

        ret
    }

    fn get_collision(&self) -> Option<([u8; 32], [u8; 32])> {
        for (i, m1) in self.ctx.fixed_points.iter().enumerate() {
            for m2 in self.ctx.fixed_points.iter().skip(i + 1) {
                if gost_hash::GostHash::compress(&self.ctx.h, m1)
                    == gost_hash::GostHash::compress(&self.ctx.h, m2)
                {
                    return Some((m1.clone(), m2.clone()));
                }
            }
        }
        None
    }
}
