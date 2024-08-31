/// dsaprotocol library
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

use num::BigInt;
use vecofbits::BitVec;
use bytearrayconversion::hextobytearray;
use aescipher::generate_random_bytevec;
use bigintops::{bigint, bytearray, modpow_bytes, modinv_bytes};
use sha1hash::sha1;

#[derive(Debug, PartialEq)]
pub enum Error {
    InvalidDSASignature,
}

pub fn hash_sha1(msg: &[u8]) -> Vec<u8> {
    hextobytearray(&sha1(&BitVec::new_from_bytearray(&msg.to_vec())))
}

pub struct DSA {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl DSA {
    pub fn new() -> DSA {
        let p = hextobytearray(&"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1".to_string());
        let q = hextobytearray(&"f4f47f05794b256174bba6e9b396a7707e563c5b".to_string());
        let g = hextobytearray(&"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291".to_string());
        let mut res = DSA { p: p, q: q, g: g, x: Vec::<u8>::new(), y: Vec::<u8>::new() };
        res.generate_user_keys();
        res
    }

    pub fn new_from_params(p: &[u8], q: &[u8], g: &[u8], x: &[u8], y: &[u8]) -> DSA {
        DSA { p: p.to_vec(), q: q.to_vec(), g: g.to_vec(), x: x.to_vec(), y: y.to_vec() }
    }

    pub fn get_keysize(&self) -> usize {
        self.p.len()
    }

    pub fn get_modulus_length(&self) -> usize {
        self.q.len()
    }

    fn pick_randint(&self) -> Vec<u8> {
        let randbytes = generate_random_bytevec(self.q.len());
        bytearray(&(1 + bigint(&randbytes) % bigint(&self.q)))
    }

    pub fn generate_user_keys(&mut self) -> Vec<u8> {
        self.x = self.pick_randint();
        self.y = modpow_bytes(&self.g, &self.x, &self.p);
        self.y.clone()
    }

    pub fn sign(&self, msg: &[u8], k_arg: Option<&[u8]>) -> (Vec<u8>, Vec<u8>) {
        let mut k: Vec<u8>;
        let mut r: Vec<u8>;
        
        loop {
            loop {
                k = if let Some(val) = k_arg {
                    val.to_vec()
                } else {
                    self.pick_randint()
                };
                r = bytearray(&(bigint(&modpow_bytes(&self.g, &k, &self.p)) % bigint(&self.q)));
                if bigint(&r) == BigInt::ZERO {
                    continue;
                }
                break;
            }
            let s = (modinv_bytes(&k, &self.q).expect("Signing error") * 
                            (bigint(&self.hash(&msg)) + bigint(&self.x) * bigint(&r)) % bigint(&self.q)) % bigint(&self.q);
            if s == BigInt::ZERO {
                continue;
            }
            return (r, bytearray(&s));
        }
    }

    pub fn verify(&self, msg: &[u8], signature: (&[u8], &[u8])) -> Result<(), Error> {
        let (r, s) = signature;
        if BigInt::ZERO >= bigint(r) || bigint(r) >= bigint(&self.q) {
            return Err(Error::InvalidDSASignature);
        }
        if BigInt::ZERO >= bigint(s) || bigint(s) >= bigint(&self.q) {
            return Err(Error::InvalidDSASignature);
        }
        let w = modinv_bytes(s, &self.q).expect("Verification error");
        let u1 = (bigint(&self.hash(&msg)) * w.clone()) % bigint(&self.q);
        let u2 = (bigint(r) * w) % bigint(&self.q);
        let mut v = bigint(&modpow_bytes(&self.g, &bytearray(&u1), &self.p)) * bigint(&(modpow_bytes(&self.y, &bytearray(&u2), &self.p)));
        v = (v % bigint(&self.p)) % bigint(&self.q);

        if v != bigint(r) {
            return Err(Error::InvalidDSASignature);
        }
        Ok(())
    }

    fn hash(&self, msg: &[u8]) -> [u8; 20] {
        hash_sha1(msg).try_into().unwrap()
    }
}
