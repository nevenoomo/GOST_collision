//! # GOST Collission
//! Finds a pair of message blocks, which both result in the same value after applying the GOST hash compersstion function.
//! This works with the constraint that one "byte" is 2 bits long.
use crate::gost_hash;
use crate::magma;
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::thread;

type State = u64;
type Key = State;
type HalfKey = u32;
type Block = u16;
type Message = State;

static SEEKERS: u32 = 16;

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

struct GostAttackContext {
    h: Arc<State>,
    d: Box<Block>,
    fixed_points: Arc<RwLock<HashSet<Message>>>,
}

pub struct GostAttack {
    ctx: Box<GostAttackContext>,
    operator_on_base_vectors: Arc<[Block; 64]>,
}

impl GostAttack {
    pub fn new(h: &[u8]) -> GostAttack {
        let h_state = utils::pack(h);

        let mut res = GostAttack {
            ctx: Box::new(GostAttackContext {
                h: Arc::new(h_state),
                d: Box::new(Default::default()),
                fixed_points: Arc::new(RwLock::new(HashSet::new())),
            }),
            operator_on_base_vectors: Arc::new(Self::get_operator_values()),
        };

        res.calculate_d();

        res
    }

    pub fn generate_collision(&mut self) -> ([u8; 32], [u8; 32]) {
        loop {
            self.find_fixed_points();
            if let Some(collision) = self.get_collision() {
                let mut first = [0u8; 32];
                let mut second = [0u8; 32];
                utils::unpack(&mut first, collision.0);
                utils::unpack(&mut second, collision.1);

                return (first, second);
            }
            self.ctx.fixed_points.write().unwrap().clear();
        }
    }

    fn calculate_d(&mut self) {
        let mut c = rand::thread_rng().gen::<Block>();

        let y = gost_hash::GostHash::psy_pow(*self.ctx.h, -12);
        c ^= (y & 0xffff) as Block; // c xor psy^-12(h), this comes from the z0
        let y = gost_hash::GostHash::psy_pow(y, -1);
        c ^= (y & 0xffff) as Block; // d1 xor psy^-13(h), this is y0 actually

        self.ctx.d = Box::new(c);
    }

    fn find_fixed_points(&mut self) {
        let mut i = 0;
        let pb = ProgressBar::new(16777216);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{bar:50.green/green}] {pos}/{len} {msg}")
                .progress_chars("#>-"),
        );
        pb.set_message("Fixed Points");

        while self.ctx.fixed_points.read().unwrap().len() < 16777216 {
            // (2^24)
            pb.set_position(self.ctx.fixed_points.read().unwrap().len() as u64);
            self.find_fixed_points_round(i);
            i += 1;
        }

        pb.finish_and_clear();
    }

    fn find_fixed_points_round(&mut self, i: usize) {
        let d1 = i as Block;
        let d2 = d1 ^ *self.ctx.d;

        let l = self.seek_forward(d1);
        self.seek_backward(l, d2);
    }

    fn seek_forward(&self, d1: Block) -> Arc<RwLock<HashMap<Block, HalfKey>>> {
        let l = Arc::new(RwLock::new(HashMap::new()));
        let mut seekers = Vec::with_capacity(SEEKERS as usize);
        let pb = ProgressBar::new(std::u32::MAX as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:50.cyan/blue}] {pos}/{len} {msg}")
                .progress_chars("#>-"),
        );
        pb.set_message("Keys probed");

        for i in 0..SEEKERS {
            let l_copy = l.clone();
            let h = self.ctx.h.clone();
            let pb = pb.clone();
            let b = self.operator_on_base_vectors.clone();

            // UGLY should write it into a separate function
            seekers.push(thread::spawn(move || {
                let step = std::u32::MAX / SEEKERS as u32;
                let first = i * step;
                let second = if i == SEEKERS - 1 {
                    std::u32::MAX
                } else {
                    (i + 1) * step
                };

                let _left = (*h & 0xff) as u8;
                let _right = ((*h >> 8) & 0xff) as u8;

                for half_key in first..second {
                    pb.inc(1);

                    if Self::check_equasion(b.clone(), half_key, d1, true) {
                        let mut left = _left;
                        let mut right = _right;

                        magma::Magma::round(&mut left, &mut right, (half_key & 0xff) as u8);
                        magma::Magma::round(&mut left, &mut right, ((half_key >> 8) & 0xff) as u8);
                        magma::Magma::round(&mut left, &mut right, ((half_key >> 16) & 0xff) as u8);
                        magma::Magma::round(&mut left, &mut right, ((half_key >> 24) & 0xff) as u8);

                        let block = ((right as u16) << 8) | left as u16;

                        l_copy
                            .write()
                            .expect("Cannot acquire the lock")
                            .insert(block, half_key);
                    }
                }
            }));
        }

        for hnd in seekers {
            hnd.join().unwrap();
        }

        pb.finish_and_clear();

        l
    }

    fn seek_backward(&mut self, l: Arc<RwLock<HashMap<Block, HalfKey>>>, d2: Block) {
        let mut seekers = Vec::with_capacity(SEEKERS as usize);
        let pb = ProgressBar::new(std::u32::MAX as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] [{bar:50.cyan/blue}] {pos}/{len} {msg}")
                .progress_chars("#>-"),
        );
        pb.set_message("Keys probed backwards");

        for i in 0..SEEKERS {
            let h = self.ctx.h.clone();
            let fixed_points = self.ctx.fixed_points.clone();
            let l_copy = l.clone();
            let pb = pb.clone();
            let b = self.operator_on_base_vectors.clone();

            seekers.push(thread::spawn(move || {
                let step = std::u32::MAX / SEEKERS as u32;
                let first = i * step;
                let second = if i == SEEKERS - 1 {
                    std::u32::MAX
                } else {
                    (i + 1) * step
                };

                let _right = (*h & 0xff) as u8;
                let _left = ((*h >> 8) & 0xff) as u8;

                for half_key in first..second {
                    pb.inc(1);

                    if Self::check_equasion(b.clone(), half_key, d2, false) {
                        let mut left = _left;
                        let mut right = _right;

                        // Those are reversed
                        magma::Magma::round(&mut left, &mut right, ((half_key >> 24) & 0xff) as u8);
                        magma::Magma::round(&mut left, &mut right, ((half_key >> 16) & 0xff) as u8);
                        magma::Magma::round(&mut left, &mut right, ((half_key >> 8) & 0xff) as u8);
                        magma::Magma::round(&mut left, &mut right, (half_key & 0xff) as u8);

                        // In this case the upper bits are in the left part
                        let block = ((left as u16) << 8) | right as u16;
                        let read_lock = l_copy.read().expect("Cannot acquire read lock");
                        if read_lock.contains_key(&block) {
                            // sk3||sk2||sk1||sk0
                            let first_key_half = read_lock.get(&block).unwrap();
                            // sk7||...||sk0
                            let key = ((half_key as Key) << 32) | *first_key_half as u64;

                            fixed_points
                                .write()
                                .expect("Cannot acquire write lock")
                                .insert(Self::convert_to_message(*h, key));
                        }
                    }
                }
            }));
        }

        for hnd in seekers {
            hnd.join().unwrap();
        }

        pb.finish_and_clear();
    }

    fn convert_to_message(h: State, key: Key) -> Message {
        gost_hash::GostHash::p_rev(key) ^ h
    }

    /// Check, whether equasion A_i * k = d_i holds for a given k, d_i and i
    /// if first_half is true, then equasion for A_1 is computed
    /// else equasion for A_2 is computed
    fn check_equasion(b: Arc<[Block; 64]>, half_key: HalfKey, d: Block, first_half: bool) -> bool {
        let mut mock_key = half_key as Key; // Placed sk0 .. sk3
        if !first_half {
            mock_key <<= 32; // Placed sk4 .. sk7
        }

        Self::apply_operator(b, mock_key) == d
    }

    fn _apply_operator(k0: Key) -> Block {
        (gost_hash::GostHash::psy_pow(gost_hash::GostHash::p_rev(k0), -12) & 0xffff) as u16
    }

    fn get_collision(&self) -> Option<(Message, Message)> {
        let read_lock = self.ctx.fixed_points.read().unwrap();

        for (i, m1) in read_lock.iter().enumerate() {
            for m2 in read_lock.iter().skip(i + 1) {
                if gost_hash::GostHash::compress(*self.ctx.h, *m1)
                    == gost_hash::GostHash::compress(*self.ctx.h, *m2)
                {
                    return Some((*m1, *m2));
                }
            }
        }
        None
    }

    fn get_operator_values() -> [Block; 64] {
        let mut ret = [0u16; 64];
        let mut n = 1u64;

        for a in (&mut ret).iter_mut() {
            *a = Self::_apply_operator(n);
            n <<= 1;
        }

        ret
    }

    fn apply_operator(b: Arc<[Block; 64]>, k: Key) -> Block {
        let mut acc = Default::default();

        for i in 0..64 {
            if (k >> i) & 0b1 == 1 {
                acc ^= b[i];
            }
        }

        acc
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;
    use rand::Rng;

    #[test]
    fn operator_application_methods() {
        let a = Arc::new(super::GostAttack::get_operator_values());
        let mut k;
        let mut rand_gen = rand::thread_rng();

        for _ in 0..1280 {
            k = rand_gen.gen();
            assert_eq!(
                super::GostAttack::_apply_operator(k),
                super::GostAttack::apply_operator(a.clone(), k)
            );
        }
    }
}
