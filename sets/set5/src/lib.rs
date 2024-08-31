/// Set 5 library functions
// 
//                     GNU AFFERO GENERAL PUBLIC LICENSE
//                        Version 3, 19 November 2007
// 
//     Copyright (C) 2024 Debajyoti Debnath
// 
//     This program is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published
//     by the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.
// 
//     This program is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.
// 
//     You should have received a copy of the GNU Affero General Public License
//     along with this program.  If not, see <https://www.gnu.org/licenses/>.
// 



use rand::prelude::*;
use sha256;
use num::{bigint::Sign, BigInt};
use bytearrayconversion::{ hextobytearray, bytearraytohex };
use aescipher::{ aes_cbc_decrypt, aes_cbc_encrypt, generate_random_bytevec, strip_pkcs7_padding };
use set4::{ compute_blocksized_key, xor_bytearrays };
use vecofbits::BitVec;
use sha1hash::sha1;
use bigintops::{bigint, bytearray, modpow_bytes};

// Error types
#[derive(Debug)]
pub enum Error {
    HMACMismatch(String, String),
}

pub fn hmac_sha256(message: &Vec<u8>, key: &Vec<u8>) -> String {
    let blocksize: usize = 256;
    let hashfunc = |arg: &BitVec| -> String {
        sha256::digest(arg.to_bytearray())
    };  
    let blocksized_key = compute_blocksized_key(key, &blocksize, &hashfunc);
    let mut o_key_pad = xor_bytearrays(&blocksized_key, &b"\x5c".repeat(blocksize / 8)).unwrap();
    let mut i_key_pad = xor_bytearrays(&blocksized_key, &b"\x36".repeat(blocksize / 8)).unwrap();

    i_key_pad.extend(message.clone());
    let res1 = hextobytearray(&hashfunc(&BitVec::new_from_bytearray(&i_key_pad)));
    o_key_pad.extend(res1);
    hashfunc(&BitVec::new_from_bytearray(&o_key_pad))
}

// Echo bot for challenge 34
pub struct EchoBotA {
    a: Vec<u8>,
    g: Vec<u8>,
    p: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    message: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>
}

// Echo bot for challenge 34
pub struct EchoBotB {
    b: Vec<u8>,
    g: Vec<u8>,
    p: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    message: Vec<u8>,
    key: Vec<u8>,
    iv: Vec<u8>
}

impl EchoBotA {
    pub fn new(p_be_bytes: &[u8], g: u32, a_be_bytes: &[u8], message: &[u8]) -> EchoBotA {
        EchoBotA { 
                 a: a_be_bytes.to_vec(),
                 g: BitVec::new_from_num(32, &g).to_bytearray(),
                 p: p_be_bytes.to_vec(),
                 a_power: Vec::<u8>::new(),
                 b_power: Vec::<u8>::new(),
                 message: message.to_vec(),
                 key: Vec::<u8>::new(),
                 iv: Vec::<u8>::new()
            }
    }

    pub fn step1(&mut self) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        self.a_power = modpow_bytes(&self.g[..], &self.a[..], &self.p[..]);
        (self.p.clone(), self.g.clone(), self.a_power.clone())
    }

    pub fn step2(&mut self, b_power_be_bytes: &[u8]) -> Vec<u8> {
        self.b_power = b_power_be_bytes.to_vec();
        let s = modpow_bytes(b_power_be_bytes, &self.a[..], &self.p[..]);
        self.key = hextobytearray(&sha1(&BitVec::new_from_bytearray(&s)))[..16].to_vec();
        self.iv = generate_random_bytevec(16);
        let mut res = aes_cbc_encrypt(&self.message, &self.iv, &self.key);
        res.extend(self.iv.clone());
        res
    }
}

impl EchoBotB {
    pub fn new(b_be_bytes: &[u8]) -> EchoBotB {
        EchoBotB { 
                 b: b_be_bytes.to_vec(),
                 g: Vec::<u8>::new(),
                 p: Vec::<u8>::new(),
                 a_power: Vec::<u8>::new(),
                 b_power: Vec::<u8>::new(),
                 message: Vec::<u8>::new(),
                 key: Vec::<u8>::new(),
                 iv: Vec::<u8>::new()
            }
    }

    pub fn step1(&mut self, p_be_bytes: &[u8], g_be_bytes: &[u8], a_power_be_bytes: &[u8]) -> Vec<u8> {
        self.g = g_be_bytes.to_vec();
        self.p = p_be_bytes.to_vec();
        self.a_power = a_power_be_bytes.to_vec();
        self.b_power = modpow_bytes(g_be_bytes, &self.b[..], p_be_bytes);
        self.b_power.clone()
    }

    pub fn step2(&mut self, a_enc_msg: Vec<u8>) -> Vec<u8> {
        let s = modpow_bytes(&self.a_power[..], &self.b[..], &self.p[..]);
        self.key = hextobytearray(&sha1(&BitVec::new_from_bytearray(&s)))[..16].to_vec();
        self.iv = a_enc_msg[a_enc_msg.len()-16..a_enc_msg.len()].to_vec();
        self.message = aes_cbc_decrypt(&a_enc_msg[..a_enc_msg.len()-16].to_vec(), &self.iv, &self.key);
        let mut res = aes_cbc_encrypt(&self.message, &self.iv, &self.key);
        res.extend(self.iv.clone());
        res
    }
}

fn join_bytearrays(arr1: &Vec<u8>, arr2: &Vec<u8>) -> Vec<u8> {
    arr1.clone()
        .into_iter()
        .chain(arr2.clone().into_iter()).collect()
}

pub struct SRPClient {
    a: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    n_prime: Vec<u8>,
    g: Vec<u8>,
    k: Vec<u8>,
    email: Vec<u8>,
    password: Vec<u8>,
    u_h: Vec<u8>,
    salt: Vec<u8>,
    big_s: Vec<u8>,
    big_k: Vec<u8>
}

pub struct SRPServer {
    b: Vec<u8>,
    n_prime: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    g: Vec<u8>,
    k: Vec<u8>,
    email: Vec<u8>,
    rng: ThreadRng,
    salt: Vec<u8>,
    v: Vec<u8>,
    u_h: Vec<u8>,
    big_s: Vec<u8>,
    big_k: Vec<u8>
}

pub struct MalSRPClient {
    _a: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    _n_prime: Vec<u8>,
    _g: Vec<u8>,
    _k: Vec<u8>,
    email: Vec<u8>,
    _password: Vec<u8>,
    u_h: Vec<u8>,
    salt: Vec<u8>,
    big_s: Vec<u8>,
    big_k: Vec<u8>
}

impl SRPClient {
    pub fn new(a: &[u8], n_prime: &[u8], g: &[u8], k: &[u8], email: &[u8], password: &[u8]) -> SRPClient {
        SRPClient { 
            a: a.to_vec(),
            n_prime: n_prime.to_vec(),
            g: g.to_vec(),
            k: k.to_vec(),
            salt: Vec::<u8>::new(),
            email: email.to_vec(),
            password: password.to_vec(),
            u_h: Vec::<u8>::new(),
            a_power: Vec::<u8>::new(),
            b_power: Vec::<u8>::new(),
            big_s: Vec::<u8>::new(),
            big_k: Vec::<u8>::new()
        }
    }
    
    pub fn step1(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.a_power = modpow_bytes(&self.g[..], &self.a[..], &self.n_prime[..]);
        (self.email.clone(), self.a_power.clone())
    }

    pub fn step2(&mut self, salt: &[u8], b_power_be_bytes: &[u8]) -> String {
        self.b_power = b_power_be_bytes.to_vec();
        self.salt = salt.to_vec();
        self.compute_u_h();
        let x_h = hextobytearray(&sha256::digest(join_bytearrays(&self.salt, &self.password)));
        let base: BigInt = bigint(&self.b_power[..]) - bigint(&self.k[..]) * bigint(&modpow_bytes(&self.g[..], &x_h[..], &self.n_prime[..]));
        let exponent: BigInt = bigint(&self.a[..]) + bigint(&self.u_h) * bigint(&x_h[..]);
        self.big_s = modpow_bytes(&bytearray(&base)[..], &bytearray(&exponent)[..], &self.n_prime[..]);
        self.big_k = hextobytearray(&sha256::digest(self.big_s.clone()));
        hmac_sha256(&self.big_k, &self.salt)
    }

    fn compute_u_h(&mut self) {
        self.u_h = hextobytearray(&sha256::digest(join_bytearrays(&self.a_power, &self.b_power)));
    }

    pub fn print(&self) {
        dbg!("{}", bytearraytohex(&self.a_power));
        dbg!("{}", bytearraytohex(&self.b_power));
        dbg!("{}", bytearraytohex(&self.salt));
        dbg!("{}", bytearraytohex(&self.u_h));
        dbg!("{}", bytearraytohex(&self.big_s));
        dbg!("{}", bytearraytohex(&self.big_k));
    }
}

impl SRPServer {
    pub fn new(b: &[u8], n_prime: &[u8], g: &[u8], k: &[u8], email: &[u8], password: &[u8]) -> SRPServer {
        let mut res = SRPServer{ 
            b: b.to_vec(),
            n_prime: n_prime.to_vec(),
            a_power: Vec::<u8>::new(),
            b_power: Vec::<u8>::new(),
            g: g.to_vec(),
            k: k.to_vec(),
            email: email.to_vec(),
            rng: rand::thread_rng(),
            salt: Vec::<u8>::new(),
            v: Vec::<u8>::new(),
            u_h: Vec::<u8>::new(),
            big_s: Vec::<u8>::new(),
            big_k: Vec::<u8>::new()
        };

        // Generate salt
        let randint: u64 = res.rng.gen::<u64>();
        res.salt = bytearray(&(BigInt::new(Sign::Plus, vec![(randint & 0xFFFFFFFF) as u32, ((randint >> 32) & 0xFFFFFFFF) as u32]) % bigint(&res.n_prime)));
        let x_h = sha256::digest(join_bytearrays(&res.salt, &password.to_vec()));
        res.v = modpow_bytes(&res.g[..], &hextobytearray(&x_h)[..], &res.n_prime[..]);

        res
    }

    pub fn step1(&mut self, email: &[u8], a_power: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.a_power = a_power.to_vec();
        self.email = email.to_vec();
        self.b_power = (bigint(&self.k[..]) * bigint(&self.v[..]) + 
            bigint(&modpow_bytes(&self.g[..], &self.b[..], &self.n_prime[..]))).to_bytes_be().1;
        (self.salt.clone(), self.b_power.clone())
    }

    pub fn step2(&mut self, hmac: String) -> Result<(), Error> {
        self.compute_u_h();
        let base = bigint(&self.a_power[..]) * bigint(&modpow_bytes(&self.v[..], &self.u_h[..], &self.n_prime[..]));
        self.big_s = modpow_bytes(&bytearray(&base)[..], &self.b[..], &self.n_prime[..]);
        self.big_k = hextobytearray(&sha256::digest(self.big_s.clone()));
        let hmac_generated = hmac_sha256(&self.big_k, &self.salt);
        if hmac_generated == hmac {
            Ok(())
        } else {
            Err(Error::HMACMismatch(hmac, hmac_generated))
        }
    }

    fn compute_u_h(&mut self) {
        self.u_h = hextobytearray(&sha256::digest(join_bytearrays(&self.a_power, &self.b_power)));
    }

    pub fn print(&self) {
        dbg!("{}", bytearraytohex(&self.a_power));
        dbg!("{}", bytearraytohex(&self.b_power));
        dbg!("{}", bytearraytohex(&self.salt));
        dbg!("{}", bytearraytohex(&self.v));
        dbg!("{}", bytearraytohex(&self.u_h));
        dbg!("{}", bytearraytohex(&self.big_s));
        dbg!("{}", bytearraytohex(&self.big_k));
    }
}

impl MalSRPClient {
    pub fn new(a: &[u8], n_prime: &[u8], g: &[u8], k: &[u8], email: &[u8], password: &[u8]) -> MalSRPClient {
        MalSRPClient { 
            _a: a.to_vec(),
            _n_prime: n_prime.to_vec(),
            _g: g.to_vec(),
            _k: k.to_vec(),
            salt: Vec::<u8>::new(),
            email: email.to_vec(),
            _password: password.to_vec(),
            u_h: Vec::<u8>::new(),
            a_power: Vec::<u8>::new(),
            b_power: Vec::<u8>::new(),
            big_s: Vec::<u8>::new(),
            big_k: Vec::<u8>::new()
        }
    }
    
    pub fn step1(&mut self, a_power_be_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
        self.a_power = a_power_be_bytes.to_vec();
        (self.email.clone(), self.a_power.clone())
    }

    pub fn step2(&mut self, salt: &[u8]) -> String {
        self.b_power = vec![];
        self.salt = salt.to_vec();
        self.compute_u_h();
        self.big_s = vec![0u8]; 
        self.big_k = hextobytearray(&sha256::digest(self.big_s.clone()));
        hmac_sha256(&self.big_k, &self.salt)
    }

    fn compute_u_h(&mut self) {
        self.u_h = hextobytearray(&sha256::digest(join_bytearrays(&self.a_power, &self.b_power)));
    }

    pub fn print(&self) {
        dbg!("{}", bytearraytohex(&self.a_power));
        dbg!("{}", bytearraytohex(&self.b_power));
        dbg!("{}", bytearraytohex(&self.salt));
        dbg!("{}", bytearraytohex(&self.u_h));
        dbg!("{}", bytearraytohex(&self.big_s));
        dbg!("{}", bytearraytohex(&self.big_k));
    }
}

pub struct SimpleSRPClient {
    a: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    n_prime: Vec<u8>,
    g: Vec<u8>,
    email: Vec<u8>,
    password: Vec<u8>,
    u_h: Vec<u8>,
    salt: Vec<u8>,
    big_s: Vec<u8>,
    big_k: Vec<u8>
}

pub struct SimpleSRPServer {
    b: Vec<u8>,
    n_prime: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    g: Vec<u8>,
    email: Vec<u8>,
    rng: ThreadRng,
    salt: Vec<u8>,
    v: Vec<u8>,
    u_h: Vec<u8>,
    big_s: Vec<u8>,
    big_k: Vec<u8>
}

impl SimpleSRPServer {
    pub fn new(b: &[u8], n_prime: &[u8], g: &[u8], email: &[u8], password: &[u8]) -> SimpleSRPServer {
        let mut res = SimpleSRPServer{ 
            b: b.to_vec(),
            n_prime: n_prime.to_vec(),
            a_power: Vec::<u8>::new(),
            b_power: Vec::<u8>::new(),
            g: g.to_vec(),
            email: email.to_vec(),
            rng: rand::thread_rng(),
            salt: Vec::<u8>::new(),
            v: Vec::<u8>::new(),
            u_h: Vec::<u8>::new(),
            big_s: Vec::<u8>::new(),
            big_k: Vec::<u8>::new()
        };
        
        // Generate salt
        let randint: u64 = res.rng.gen::<u64>();
        res.salt = bytearray(&(BigInt::new(Sign::Plus, vec![(randint & 0xFFFFFFFF) as u32, ((randint >> 32) & 0xFFFFFFFF) as u32]) % bigint(&res.n_prime)));
        let x_h = sha256::digest(join_bytearrays(&res.salt, &password.to_vec()));
        res.v = modpow_bytes(&res.g[..], &hextobytearray(&x_h)[..], &res.n_prime[..]);
        res
    }

    pub fn step1(&mut self, email: &[u8], a_power: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        self.a_power = a_power.to_vec();
        self.email = email.to_vec();
        self.b_power = (bigint(&modpow_bytes(&self.g[..], &self.b[..], &self.n_prime[..]))).to_bytes_be().1;
        self.compute_u_h();
        (self.salt.clone(), self.b_power.clone(), self.u_h.clone())
    }

    pub fn step2(&mut self, hmac: String) -> Result<(), Error> {
        let base = bigint(&self.a_power[..]) * bigint(&modpow_bytes(&self.v[..], &self.u_h[..], &self.n_prime[..]));
        self.big_s = modpow_bytes(&bytearray(&base)[..], &self.b[..], &self.n_prime[..]);
        self.big_k = hextobytearray(&sha256::digest(self.big_s.clone()));
        let hmac_generated = hmac_sha256(&self.big_k, &self.salt);
        if hmac_generated == hmac {
            Ok(())
        } else {
            Err(Error::HMACMismatch(hmac, hmac_generated))
        }
    }

    fn compute_u_h(&mut self) {
        let randint: u128 = self.rng.gen::<u128>();
        self.u_h = bytearray(&(BigInt::new(Sign::Plus, vec![(randint & 0xFFFFFFFF) as u32, ((randint >> 32) & 0xFFFFFFFF) as u32, 
                                                ((randint >> 64) & 0xFFFFFFFF) as u32, ((randint >> 96) & 0xFFFFFFFF) as u32]) % bigint(&self.n_prime)));
    }

    pub fn print(&self) {
        dbg!("{}", bytearraytohex(&self.a_power));
        dbg!("{}", bytearraytohex(&self.b_power));
        dbg!("{}", bytearraytohex(&self.salt));
        dbg!("{}", bytearraytohex(&self.v));
        dbg!("{}", bytearraytohex(&self.u_h));
        dbg!("{}", bytearraytohex(&self.big_s));
        dbg!("{}", bytearraytohex(&self.big_k));
    }
}

impl SimpleSRPClient {
    pub fn new(a: &[u8], n_prime: &[u8], g: &[u8], email: &[u8], password: &[u8]) -> SimpleSRPClient {
        SimpleSRPClient { 
            a: a.to_vec(),
            n_prime: n_prime.to_vec(),
            g: g.to_vec(),
            salt: Vec::<u8>::new(),
            email: email.to_vec(),
            password: password.to_vec(),
            u_h: Vec::<u8>::new(),
            a_power: Vec::<u8>::new(),
            b_power: Vec::<u8>::new(),
            big_s: Vec::<u8>::new(),
            big_k: Vec::<u8>::new()
        }
    }
    
    pub fn step1(&mut self) -> (Vec<u8>, Vec<u8>) {
        self.a_power = modpow_bytes(&self.g, &self.a, &self.n_prime);
        (self.email.clone(), self.a_power.clone())
    }

    pub fn step2(&mut self, salt: &[u8], b_power_be_bytes: &[u8], u_h_be_bytes: &[u8]) -> String {
        self.b_power = b_power_be_bytes.to_vec();
        self.salt = salt.to_vec();
        self.u_h = u_h_be_bytes.to_vec();
        let x_h = hextobytearray(&sha256::digest(join_bytearrays(&self.salt, &self.password)));
        let base: BigInt = bigint(&self.b_power);
        let exponent: BigInt = bigint(&self.a) + bigint(&self.u_h) * bigint(&x_h);
        self.big_s = modpow_bytes(&bytearray(&base), &bytearray(&exponent), &self.n_prime);
        self.big_k = hextobytearray(&sha256::digest(self.big_s.clone()));
        hmac_sha256(&self.big_k, &self.salt)
    }

    pub fn print(&self) {
        dbg!("{}", bytearraytohex(&self.a_power));
        dbg!("{}", bytearraytohex(&self.b_power));
        dbg!("{}", bytearraytohex(&self.salt));
        dbg!("{}", bytearraytohex(&self.u_h));
        dbg!("{}", bytearraytohex(&self.big_s));
        dbg!("{}", bytearraytohex(&self.big_k));
    }
}

pub struct MITMSimpleSRPServer {
    b: Vec<u8>,
    g: Vec<u8>,
    rng: ThreadRng,
    n_prime: Vec<u8>,
    a_power: Vec<u8>,
    b_power: Vec<u8>,
    email: Vec<u8>,
    salt: Vec<u8>,
    v: Vec<u8>,
    u_h: Vec<u8>,
    big_s: Vec<u8>,
    big_k: Vec<u8>
}

impl MITMSimpleSRPServer {
    pub fn new(b_be_bytes: &[u8], n_prime_be_bytes: &[u8], g_be_bytes: &[u8]) -> MITMSimpleSRPServer {
        let mut res = MITMSimpleSRPServer{ 
            b: b_be_bytes.to_vec(),
            n_prime: n_prime_be_bytes.to_vec(),
            g: g_be_bytes.to_vec(),
            rng: rand::thread_rng(),
            a_power: Vec::<u8>::new(),
            b_power: Vec::<u8>::new(),
            email: Vec::<u8>::new(),
            salt: Vec::<u8>::new(),
            v: Vec::<u8>::new(),
            u_h: Vec::<u8>::new(),
            big_s: Vec::<u8>::new(),
            big_k: Vec::<u8>::new()
        };
        
        // Generate salt
        let randint: u64 = res.rng.gen::<u64>();
        res.salt = bytearray(&(BigInt::new(Sign::Plus, vec![(randint & 0xFFFFFFFF) as u32, ((randint >> 32) & 0xFFFFFFFF) as u32]) % bigint(&res.n_prime)));
        res
    }

    pub fn step1(&mut self, email: &[u8], a_power: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        self.a_power = a_power.to_vec();
        self.email = email.to_vec();
        self.b_power = (bigint(&modpow_bytes(&self.g, &self.b, &self.n_prime))).to_bytes_be().1;
        self.compute_u_h();
        (self.salt.clone(), self.b_power.clone(), self.u_h.clone())
    }

    pub fn step2(&mut self, hmac: String, password_guess: &[u8]) -> Result<(), Error> {
        let x_h = hextobytearray(&sha256::digest(join_bytearrays(&self.salt, &password_guess.to_vec())));
        self.big_s = bytearray(&(bigint(&modpow_bytes(&self.a_power, &self.b, &self.n_prime)) * 
                            bigint(&modpow_bytes(&self.b_power, &bytearray(&(bigint(&self.u_h) * bigint(&x_h))), &self.n_prime)) % bigint(&self.n_prime)));
        self.big_k = hextobytearray(&sha256::digest(self.big_s.clone()));
        let hmac_generated = hmac_sha256(&self.big_k, &self.salt);
        if hmac_generated == hmac {
            Ok(())
        } else {
            Err(Error::HMACMismatch(hmac, hmac_generated))
        }
    }

    fn compute_u_h(&mut self) {
        let randint: u128 = self.rng.gen::<u128>();
        self.u_h = bytearray(&(BigInt::new(Sign::Plus, vec![(randint & 0xFFFFFFFF) as u32, ((randint >> 32) & 0xFFFFFFFF) as u32, 
                                                ((randint >> 64) & 0xFFFFFFFF) as u32, ((randint >> 96) & 0xFFFFFFFF) as u32]) % bigint(&self.n_prime)));
    }

    pub fn print(&self) {
        dbg!("{}", bytearraytohex(&self.a_power));
        dbg!("{}", bytearraytohex(&self.b_power));
        dbg!("{}", bytearraytohex(&self.salt));
        dbg!("{}", bytearraytohex(&self.v));
        dbg!("{}", bytearraytohex(&self.u_h));
        dbg!("{}", bytearraytohex(&self.big_s));
        dbg!("{}", bytearraytohex(&self.big_k));
    }
}

fn modexp(base: &u32, exponent: &u32, modulus: &u32) -> u32 {
    if *modulus == 1 {
        return 0;
    }
    let mut pow: u32 = 1;
    for _ in 0..*exponent {
        pow = (pow * base) % modulus;
    }
    return pow;
} 

pub fn mitm_intercept(a_enc_msg: Vec<u8>, guessed_s: &[u8]) {
    let s: Vec<u8> = guessed_s.to_vec();
    let key = hextobytearray(&sha1(&BitVec::new_from_bytearray(&s)))[..16].to_vec();
    let iv = a_enc_msg[a_enc_msg.len()-16..a_enc_msg.len()].to_vec();
    let msg = aes_cbc_decrypt(&a_enc_msg[..a_enc_msg.len()-16].to_vec(), &iv, &key);
    let res = match strip_pkcs7_padding(&msg) {
        Ok(sth) =>  String::from_utf8(sth).unwrap(),
        Err(_) => String::from_utf8(msg).unwrap()
    };
    println!("MITM intercepted message: {}", res);
}

pub fn diffie_hellmann(p_be_bytes: &[u8], g: u32, a_be_bytes: &[u8], b_be_bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let g_be_bytes = BitVec::new_from_num(32, &g).to_bytearray();
    
    let a_power_be_bytes = modpow_bytes(&g_be_bytes, a_be_bytes, p_be_bytes);
    let b_power_be_bytes = modpow_bytes(&g_be_bytes, b_be_bytes, p_be_bytes);
    
    let s_be_bytes = modpow_bytes(&b_power_be_bytes, a_be_bytes, p_be_bytes);
    let s2_be_bytes = modpow_bytes(&a_power_be_bytes, b_be_bytes, p_be_bytes);
    
    (s_be_bytes, s2_be_bytes) 
}

pub fn diffie_hellmann_small_int(p: u32, g: u32) -> (u32, u32) {
    let mut rng = rand::thread_rng();

    let a: u32 = rng.gen::<u32>() % p;
    let a_pow: u32 = modexp(&g, &a, &p);

    let b: u32 = rng.gen::<u32>() % p;
    let b_pow: u32 = modexp(&g, &b, &p);

    let s: u32 = modexp(&a_pow, &b, &p);
    let s2: u32 = modexp(&b_pow, &a, &p);
    
    (s, s2)
}

#[cfg(test)]
mod test {
    use super::*;
    
    #[test]
    fn test_diffie_hellmann_small_int() {
        let res = diffie_hellmann_small_int(37, 5);
        assert_eq!(res.0, res.1);
    }

    #[test]
    fn test_diffie_hellmann() {
        let p: Vec<u8> = hextobytearray(&"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".to_string());
        let g: u32 = 2;
        let a = b"You look lovely today.".to_vec();
        let b = b"Let's play guitar.".to_vec();

        let res = diffie_hellmann(&p, g, &a, &b);
        assert_eq!(res.0, res.1);
    }
}
