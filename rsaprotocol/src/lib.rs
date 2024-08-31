/// rsaprotocol library
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
use bigintops::{bytearray, modpow_bytes, modinv_bytes};
use primegen::{get_first_n_primes, generate_large_prime};

pub struct RSA {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>,
    keysize: u16
}

impl RSA {
    pub fn new(keysize: &u16) -> RSA {
        if keysize % 1024 != 0 {
            panic!("Keysize must be a multiple of 1024.")
        }
        // Pre-generate first 900 primes for later use
        let primes: Vec<u32> = get_first_n_primes(900);

        let (n, e, d) = loop {
            let prime_p = generate_large_prime(*keysize as usize / 4 * 3, &primes);
            let prime_q = generate_large_prime(*keysize as usize / 4, &primes);
            let n_val = prime_p.clone() * prime_q.clone();
            let e_t = (prime_p - 1) * (prime_q - 1);
            let e_val = BigInt::from_i32(3).unwrap();
            match modinv_bytes(&bytearray(&e_val), &bytearray(&e_t)) {
                Ok(sth) => break (n_val, e_val, sth),
                Err(_) => continue,
            }
        };
        
        RSA { n: bytearray(&n), e: bytearray(&e), d: bytearray(&d), keysize: *keysize }
    }
    
    pub fn get_public_key(&self) -> (Vec<u8>, Vec<u8>) {
        (self.e.clone(), self.n.clone())
    }

    pub fn get_keysize(&self) -> u16 {
        self.keysize.clone()
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        modpow_bytes(msg, &self.e, &self.n)
    }

    pub fn decrypt(&self, ciphertxt: &[u8]) -> Vec<u8> {
        modpow_bytes(ciphertxt, &self.d, &self.n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rsa() {
        let rsa = RSA::new(&2048u16);
        let msg = vec![42u8];
        assert_eq!(rsa.decrypt(&rsa.encrypt(&msg)), msg);
    }
}
