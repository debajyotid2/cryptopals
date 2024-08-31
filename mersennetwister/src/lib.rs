/// mersennetwister library
// 
// 
//                     GNU AFFERO GENERAL PUBLIC LICENSE
//                     Version 3, 19 November 2007


//  Copyright (C) 2024 Debajyoti Debnath

//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published
//  by the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.

//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU Affero General Public License for more details.

//  You should have received a copy of the GNU Affero General Public License
//  along with this program.  If not, see <https://www.gnu.org/licenses/>.
// 

pub struct MT19937Gen {
    pub seed: u32,
    mt: Vec<u32>,
    pos_idx: usize,
    w: usize,
    n: usize,
    m: usize,
    u: usize,
    s: usize,
    t: usize,
    l: usize,
    a: u32,
    b: u32,
    c: u32,
    d: u32,
    lower: u32,
    upper: u32,
}

impl MT19937Gen {
    pub fn new(seed_arg: u32) -> MT19937Gen {
        let mut gen = MT19937Gen{ 
                    seed: seed_arg, w: 32, n: 624, m: 397, 
                    u: 11, s: 7, t: 15, l: 18, a: 0x9908B0DF, 
                    b: 0x9D2C5680, c: 0xEFC60000, d: 0xFFFFFFFF, 
                    lower: 0x7FFFFFFF, upper: 0x80000000, pos_idx: 0,
                    mt: Vec::<u32>::new() };
        gen.mt.push(gen.seed);
        gen.initialize();
        gen
    }

    pub fn new_from(state: &Vec<u32>) -> MT19937Gen {
        if state.len() != 624 {
            panic!("State does not have 624 values.");
        }
        MT19937Gen{ 
           seed: state[0], w: 32, n: 624, m: 397, 
           u: 11, s: 7, t: 15, l: 18, a: 0x9908B0DF, 
           b: 0x9D2C5680, c: 0xEFC60000, d: 0xFFFFFFFF, 
           lower: 0x7FFFFFFF, upper: 0x80000000, pos_idx: 624,
           mt: state.clone() 
        }
    }

    // Generate random number
    pub fn gen(&mut self) -> u32 {
        if self.pos_idx >= self.n {
            self.twist();
            self.pos_idx = 0;
        }
        let result = self.temper();
        self.pos_idx += 1;
        result
    }

    // Generate random float from [0, 1)
    pub fn randfloat(&mut self) -> f32 {
        (self.gen() as f32) / (u32::MAX as f32)
    }

    // Initialize the state vector
    fn initialize(&mut self) {
        let f: u32 = 1812433253;
        
        for ctr in 1..self.n {
            let res: u64 = (f as u64 * (self.mt[ctr-1] ^ (self.mt[ctr-1] >> (self.w - 2))) as u64) + ctr as u64;
            self.mt.push((res & 0xFFFFFFFF) as u32);
        }
    }
    
    // Perform the twist operation
    fn twist(&mut self) {
        for ctr in 0..self.n {
            let x: u32 = (((self.mt[ctr] & self.upper) as u64 + (self.mt[(ctr + 1) % self.n] & self.lower) as u64) & 0xFFFFFFFF).try_into().unwrap();
            let mut x_a: u32 = x >> 1;
            if (x % 2) != 0 {
                x_a ^= self.a;
            }
            self.mt[ctr] = self.mt[(ctr + self.m) % self.n] ^ x_a;
        }
        self.pos_idx = 0;
    }

    // Perform the temper operation
    fn temper(&self) -> u32 {
        let y1 = self.mt[self.pos_idx];
        let y2 = y1 ^ ((y1 >> self.u) & self.d);
        let y3 = y2 ^ ((y2 << self.s) & self.b);
        let y4 = y3 ^ ((y3 << self.t) & self.c);
        let y5 = y4 ^ (y4 >> self.l);
        y5 & self.d
    }
}

// Reverse the temper operation for a 32 bit MT19937
pub fn mt19937_32_untemper(number: &u32) -> u32 {
    let mut res = number ^ (number >> 18);
    res ^= (res << 15) & 0xEFC60000;
    for count in 0..4 {
        res ^= (res << 7 & (0x7F << (7 * (count + 1)))) & 0x9D2C5680;
    }
    for _ in 0..3 {
        res ^= res >> 11;
    }
    res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_rng_uniformity() {
        let mut rng = MT19937Gen::new(42);
        let num_floats: usize = 10000000;
        let rand_floats: Vec<f32> = (0..num_floats).map(|_| rng.randfloat()).collect();
        let lower_count: f32 = rand_floats.iter().map(|&x| if x < 0.5 { 1.0f32 } else { 0.0f32 }).sum();
        let upper_count: f32 = rand_floats.iter().map(|&x| if x >= 0.5 { 1.0f32 } else { 0.0f32 }).sum();
        assert_eq!((lower_count / (num_floats / 100) as f32).round(), (upper_count / (num_floats / 100) as f32).round());
    }

    #[test]
    fn test_mt19937_rng_seed() {
        let mut rng = MT19937Gen::new(42);
        let mut rng_2 = MT19937Gen::new(42);
        let rand_floats: Vec<f32> = (0..1000).map(|_| rng.randfloat()).collect();
        let rand_floats_2: Vec<f32> = (0..1000).map(|_| rng_2.randfloat()).collect();
        assert_eq!(rand_floats, rand_floats_2);
    }

    #[test]
    fn test_mt19937_rng_untemper() {
        let seed: u32 = 42;
        let mut rng = MT19937Gen::new(seed);
        let randint: u32 = rng.gen();
        assert_eq!(mt19937_32_untemper(&randint), seed);
    }
}
