//! # GOST Collission
//! Finds a pair of message blocks, which both result in the same value after applying the GOST hash compersstion function.
//! This works with the constraint that one "byte" is 2 bits long.
use crate::gost_hash;
use crate::magma;
use indicatif::{MultiProgress, ProgressBar};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::thread;

static SEEKERS: u32 = 8;

pub mod utils {
    use std::convert::TryInto;

    pub fn pack<T>(x: &[u8]) -> T
    where
        T: From<u8> + std::ops::BitOrAssign + Default,
    {
        let mut tmp: T = Default::default();
        let mut offset = 0;

        for e in x.iter() {
            tmp |= (*e << offset)
                .try_into()
                .expect("Cannot pack into this type.");
            offset += 2;
        }

        tmp
    }

    pub fn unpack<T>(x: &mut [u8], y: T)
    where
        T: std::ops::Shr + Default + std::ops::BitAnd + std::ops::AddAssign + TryInto<u64>,
    {
        let mut offset: u64 = Default::default();
        if let Ok(val) = y.try_into() {
            for elem in x.iter_mut() {
                *elem = ((val >> offset) & 0b11u64) as u8;
                offset += 2;
            }
        }
    }
}

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
    h: Arc<[u8; 32]>,
    d: Box<[u8; 8]>,
    fixed_points: Arc<RwLock<HashSet<u64>>>,
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
                h: Arc::new(tmp),
                d: Box::new([0u8; 8]),
                fixed_points: Arc::new(RwLock::new(HashSet::new())),
            }),
        };

        res.calculate_d();

        res
    }

    pub fn generate_collision(&mut self) -> ([u8; 32], [u8; 32]) {
        loop {
            println!("Generating collision"); // DEBUG
            self.find_fixed_points();
            if let Some(collision) = self.get_collision() {
                return collision;
            }
            self.ctx.fixed_points.write().unwrap().clear();
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
        println!("Finding fixed points"); // DEBUG
        let mut i = 0;

        while self.ctx.fixed_points.read().unwrap().len() < 16777216 {
            // (2^24)
            println!("Round {}", i); // DEBUG
            self.find_fixed_points_round(i);
            i += 1;
        }
        println!("Fixed points found"); // DEBUG
    }

    fn find_fixed_points_round(&mut self, i: usize) {
        let mut d1 = [0u8; 8];
        le_to_blk!(&mut d1, i);
        let mut d2 = d1;

        magma::utils::xor(&mut d2, &self.ctx.d[..]);
        let l = self.seek_forward(&d1);
        self.seek_backward(l, &d2);
    }

    fn seek_forward(&self, d1: &[u8]) -> Arc<RwLock<HashMap<u16, u32>>> {
        let l = Arc::new(RwLock::new(HashMap::new()));
        let mut seekers = Vec::with_capacity(SEEKERS as usize);
        let mut d1_tmp = [0u8; 8];
        (&mut d1_tmp).copy_from_slice(d1);
        let d1_arc = Arc::new(d1_tmp);

        for i in 0..SEEKERS {
            let l_copy = l.clone();
            let d1 = d1_arc.clone();
            let h = self.ctx.h.clone();

            // UGLY should write it into a separate function
            seekers.push(thread::spawn(move || {
                let mut half_key = [0u8; 16];
                let step = std::u32::MAX / SEEKERS as u32;
                let first = i * step;
                let second = if i == SEEKERS - 1 {
                    std::u32::MAX
                } else {
                    (i + 1) * step
                };

                for half_key_num in first..second {
                    le_to_blk!(half_key, half_key_num);
                    if !Self::check_equasion(&half_key, &(*d1), true) {
                        let mut block = [0u8; 8];
                        let mut left = [0u8; 4];
                        let mut right = [0u8; 4];
                        (&mut left).copy_from_slice(&h[..4]);
                        (&mut right).copy_from_slice(&h[4..8]);
                        magma::Magma::round(&mut left, &mut right, &half_key[..4]);
                        magma::Magma::round(&mut left, &mut right, &half_key[4..8]);
                        magma::Magma::round(&mut left, &mut right, &half_key[8..12]);
                        magma::Magma::round(&mut left, &mut right, &half_key[12..16]);
                        (&mut block[..4]).copy_from_slice(&left);
                        (&mut block[4..]).copy_from_slice(&right);

                        l_copy
                            .write()
                            .expect("Cannot acquire the lock")
                            .insert(utils::pack(&block), utils::pack(&half_key));
                    }
                }
            }));
        }

        for hnd in seekers {
            hnd.join().unwrap();
        }

        l
    }

    fn seek_backward(&mut self, l: Arc<RwLock<HashMap<u16, u32>>>, d2: &[u8]) {
        let mut seekers = Vec::with_capacity(SEEKERS as usize);
        let mut d2_tmp = [0u8; 8];
        (&mut d2_tmp).copy_from_slice(d2);
        let d2_arc = Arc::new(d2_tmp);

        for i in 0..SEEKERS {
            let h = self.ctx.h.clone();
            let d2 = d2_arc.clone();
            let fixed_points = self.ctx.fixed_points.clone();
            let l_copy = l.clone();

            seekers.push(thread::spawn(move || {
                // sk4 .. sk7
                let mut half_key = [0u8; 16];
                let step = std::u32::MAX / SEEKERS as u32;
                let first = i * step;
                let second = if i == SEEKERS - 1 {
                    std::u32::MAX
                } else {
                    (i + 1) * step
                };

                for half_key_num in first..second {
                    le_to_blk!(half_key, half_key_num);

                    if !Self::check_equasion(&half_key, &(*d2), false) {
                        let mut block = [0u8; 8];
                        let mut left = [0u8; 4];
                        let mut right = [0u8; 4];

                        (&mut left).copy_from_slice(&h[..4]);
                        (&mut right).copy_from_slice(&h[4..8]);

                        magma::Magma::round(&mut left, &mut right, &half_key[..4]);
                        magma::Magma::round(&mut left, &mut right, &half_key[4..8]);
                        magma::Magma::round(&mut left, &mut right, &half_key[8..12]);
                        magma::Magma::round(&mut left, &mut right, &half_key[12..16]);

                        (&mut block[..4]).copy_from_slice(&left);
                        (&mut block[4..]).copy_from_slice(&right);

                        let packed_block = utils::pack(&block);

                        let read_lock = l_copy.read().expect("Cannot acquire read lock");
                        if read_lock.contains_key(&packed_block) {
                            let mut key = [0u8; 32];
                            let packed_key = read_lock.get(&packed_block).unwrap();
                            let first_half = &mut key[..16];

                            utils::unpack(first_half, *packed_key); // unpack the key
                            (&mut key[16..]).copy_from_slice(&half_key);

                            fixed_points
                                .write()
                                .expect("Cannot acquire write lock")
                                .insert(utils::pack(&Self::convert_to_message(&(*h), &key)));
                        }
                    }
                }
            }));
        }

        for hnd in seekers {
            hnd.join().unwrap();
        }
    }

    fn convert_to_message(h: &[u8], key: &[u8]) -> [u8; 32] {
        let mut tmp = gost_hash::GostHash::p_rev(key);
        magma::utils::xor(&mut tmp, h);

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

        let ret_tmp = gost_hash::GostHash::psy_pow(&gost_hash::GostHash::p_rev(k0), -12);
        let mut ret = [0u8; 8];
        (&mut ret[..]).copy_from_slice(&ret_tmp[..8]);

        ret
    }

    fn get_collision(&self) -> Option<([u8; 32], [u8; 32])> {
        println!("Finding collision in fixed points"); // DEBUG
        let mut m1 = [0u8; 32];
        let mut m2 = [0u8; 32];
        let read_lock = self.ctx.fixed_points.read().unwrap();

        for (i, m1_packed) in read_lock.iter().enumerate() {
            for m2_packed in read_lock.iter().skip(i + 1) {
                utils::unpack(&mut m1, *m1_packed);
                utils::unpack(&mut m2, *m2_packed);

                if gost_hash::GostHash::compress(&self.ctx.h, &m1)
                    == gost_hash::GostHash::compress(&self.ctx.h, &m2)
                {
                    return Some((m1, m2));
                }
            }
        }
        None
    }
}
