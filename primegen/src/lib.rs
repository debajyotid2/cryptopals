/// primegen library
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

use num::{BigInt, FromPrimitive};
use primes::{Sieve, PrimeSet};
use bigintops::{bigint, bytearray, modpow_bytes};
use aescipher::generate_random_bytevec;

pub fn is_rabin_miller_prime(num: &BigInt, k: usize) -> bool {
    let mut d: BigInt = num.clone() - 1;
    let mut s: usize = 0;

    let one = BigInt::from_u32(1).unwrap();

    while d.clone() % 2 == BigInt::ZERO {
        d /= 2;
        s += 1;
    }
    for _ in 0..k {
        let a = 2 + bigint(&generate_random_bytevec(bytearray(&num).len())) % (num.clone() - 4);
        let mut x = bigint(&modpow_bytes(&bytearray(&a), &bytearray(&d), &bytearray(&num)));
        let mut y = BigInt::ZERO;

        for _ in 0..s {
            y = bigint(&modpow_bytes(&bytearray(&x), &vec![2u8], &bytearray(&num)));
            if y == one && x != one && x != num.clone() - 1 {
                return false;
            }
            x = y.clone();
        }
        if y != one {
            return false;
        }
    }
    true
}

pub fn generate_large_prime(num_bits: usize, primes: &Vec<u32>) -> BigInt {
    let two = BigInt::from_i32(2).unwrap();

    let low: BigInt = two.pow(num_bits as u32 - 1) + 1;
    let high: BigInt = two.pow(num_bits as u32) - 1;

    loop {
        // Generate large odd random number
        let mut randnum_bytes =  bytearray(&(low.clone() + bigint(&generate_random_bytevec(num_bits / 8)) % (high.clone() - low.clone())));
        if randnum_bytes.last().unwrap() % 2 == 0 {
            *randnum_bytes.last_mut().unwrap() &= 0xFE;
        }
        let randnum = bigint(&randnum_bytes);
        
        // Ensure number is not divisible by stored primes
        if primes.iter().any(|prime| randnum.clone() % prime == BigInt::ZERO) {
            continue;
        }

        // Perform Rabin-Miller primality test
        if is_rabin_miller_prime(&randnum, 20) {
            return randnum;
        }
    }
}

pub fn get_first_n_primes(n: usize) -> Vec<u32> {
    let mut pset = Sieve::new();
    pset.iter().take(n).map(|x| x as u32).collect()
}
