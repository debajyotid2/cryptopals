/// Set 6 library functions
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




use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::HashSet;
use primes::{Sieve, PrimeSet};
use num::{BigInt, bigint::Sign, pow::Pow, FromPrimitive};
use md5::{Md5, Digest};
use rand::{thread_rng, Rng};
use bytearrayconversion::hextobytearray;
use aescipher::generate_random_bytevec;
use vecofbits::BitVec;
use sha1hash::sha1;
use rsaprotocol::RSA;
use primegen::generate_large_prime;
use bigintops::{bigint, bytearray, cube_root, modpow_bytes, modinv_bytes, bigint_div_ceil, bigint_div_floor};

const ASN1_MD5: [u8; 18] = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10];

#[derive(Debug, PartialEq)]
pub enum Error {
    DecryptionError,
    InvalidPKCSPadLength(usize),
    InvalidRSASignature,
    InvalidDSASignature,
    InvalidPKCS1v15EncryptionPadding
}

pub struct MessageServer<'a> {
    messages: HashSet<Vec<u8>>,
    timestamps: Vec<u64>,
    rsa: &'a RSA
}

impl MessageServer<'_> {
    pub fn new(rsa: &RSA) -> MessageServer {
        MessageServer{ messages: HashSet::<Vec<u8>>::new(), timestamps: Vec::<u64>::new(), rsa: rsa }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();
        if !self.messages.insert(ciphertext.to_vec()) {
            return Err(Error::DecryptionError);
        }
        self.timestamps.push(time.try_into().unwrap());
        Ok(self.rsa.decrypt(ciphertext))
    }
}

pub struct MiniRSA {
    n: Vec<u8>,
    e: Vec<u8>,
    d: Vec<u8>
}

impl MiniRSA {
    pub fn new(keysize: &usize) -> MiniRSA {
        if *keysize > 1024 {
            panic!("Keysize must be less than 1024!");
        }
        // Pre-generate first 900 primes for later use
        let mut pset = Sieve::new();
        let primes: Vec<u32> = pset.iter().take(900).map(|x| x as u32).collect();

        let (n, e, d) = loop {
            let prime_p = generate_large_prime(keysize / 2, &primes);
            let prime_q = generate_large_prime(keysize / 2, &primes);
            let n_val = prime_p.clone() * prime_q.clone();
            let e_t = (prime_p - 1) * (prime_q - 1);
            let e_val = BigInt::from_i32(3).unwrap();
            match modinv_bytes(&bytearray(&e_val), &bytearray(&e_t)) {
                Ok(sth) => break (n_val, e_val, sth),
                Err(_) => continue,
            }
        };
        
        MiniRSA { n: bytearray(&n), e: bytearray(&e), d: bytearray(&d) }
    }
    
    pub fn get_public_key(&self) -> (Vec<u8>, Vec<u8>) {
        (self.e.clone(), self.n.clone())
    }

    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        modpow_bytes(msg, &self.e, &self.n)
    }

    pub fn decrypt(&self, ciphertxt: &[u8]) -> Vec<u8> {
        modpow_bytes(ciphertxt, &self.d, &self.n)
    }
}

pub fn rsa_unpadded_message_recovery_attack(ciphertext: &[u8], modulus: &[u8], exponent: &[u8], server: &mut MessageServer) -> Vec<u8> {
    let n = bigint(modulus);
    let c = bigint(ciphertext);

    // Calculate c_prime
    let mut rng = thread_rng();
    let randint = 1 + rng.gen::<u64>();
    let s = BigInt::new(Sign::Plus, vec![(randint & 0xFFFFFFFF) as u32, ((randint >> 32) & 0xFFFFFFFF) as u32]) % n.clone();
    let c_prime = (bigint(&modpow_bytes(&bytearray(&s), exponent, modulus)) * c) % n.clone();

    // Get decryption from server
    let p_prime = server.decrypt(&bytearray(&c_prime)).unwrap();

    // Get plaintext from p_prime
    let p = (bigint(&p_prime) * modinv_bytes(&bytearray(&s), modulus).unwrap()) % n;
    bytearray(&p)
}

pub fn pad_pkcs1v15(hash_asn: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if length % 128 != 0 {
        return Err(Error::InvalidPKCSPadLength(length))
    }
    let mut padded: Vec<u8> = vec![0x00, 0x01];
    padded.extend(vec![0xFF].repeat(length-hash_asn.len()-3));
    padded.push(0x00);
    padded.extend(hash_asn);

    Ok(padded)
}

pub fn pad_pkcs1v15_encryption(msg: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if length % 128 != 0 {
        return Err(Error::InvalidPKCSPadLength(length))
    }

    let mut padded: Vec<u8> = vec![0x00, 0x02];
    padded.extend(generate_random_bytevec(length-msg.len()-3));
    padded.push(0x00);
    padded.extend(msg);

    Ok(padded)
}

pub fn hash_md5(msg: &[u8]) -> Vec<u8> {
    let mut hasher = Md5::new();
    hasher.update(msg);
    hasher.finalize().to_vec()
}

pub fn hash_sha1(msg: &[u8]) -> Vec<u8> {
    hextobytearray(&sha1(&BitVec::new_from_bytearray(&msg.to_vec())))
}

pub fn rsa_sign(msg: &[u8], rsa: &RSA) -> Result<Vec<u8>, Error> {
    let mut hash_asn: Vec<u8> = ASN1_MD5.to_vec();
    hash_asn.extend(&hash_md5(msg));
    let padded: Vec<u8> = pad_pkcs1v15(&hash_asn, (rsa.get_keysize() / 8).into())?;
    Ok(rsa.decrypt(&padded))
}

pub fn rsa_verify(message: &[u8], signature: &[u8], rsa: &RSA) -> Result<(), Error> {
    // "Decrypt" the signature
    let mut decrypted: Vec<u8> = rsa.encrypt(&signature);

    // The beginning 0x00 gets omitted due to exponentiation
    if decrypted[0] != 0x00 {
        decrypted.insert(0, 0x00);
    }

    let mut decrypted_iter = decrypted.iter();
    let mut asn1_iter = ASN1_MD5.iter();

    let hash_len = 16;

    // Parse the hash from the decrypted signature
    if decrypted_iter.next() != Some(&0x00) {
        return Err(Error::InvalidRSASignature);
    }
    if decrypted_iter.next() != Some(&0x01) {
        return Err(Error::InvalidRSASignature);
    }
    
    let mut val: Option<&u8>;
    loop {
        val = decrypted_iter.next();
        if val != Some(&0xFF) {
            break;
        }
    }
    
    if val != Some(&0x00) {
        return Err(Error::InvalidRSASignature);
    }
    
    for _ in 0..asn1_iter.len() {
        if decrypted_iter.next() == asn1_iter.next() {
            continue;
        }
        return Err(Error::InvalidRSASignature);
    }

    if decrypted_iter.len() < hash_len {
        return Err(Error::InvalidRSASignature);
    }

    let msg_hash = hash_md5(message);
    let mut msg_hash_iter = msg_hash.iter();

    for _ in 0..hash_len {
        if decrypted_iter.next() == msg_hash_iter.next() {
            continue;
        }
        return Err(Error::InvalidRSASignature);
    }
    Ok(())
}

pub fn forge_rsa_signature(signature: &[u8], modulus: &[u8], exponent: &[u8], appended: &[u8]) -> Vec<u8> {
    let decrypted = modpow_bytes(signature, exponent, modulus);
    let hash_len: usize = 16;   // MD5
    let mut forged: Vec<u8> = vec![0x00, 0x01, 0x00];
    
    forged.extend(&decrypted[(decrypted.len()-ASN1_MD5.len()-hash_len)..]);
    forged.extend(hash_md5(appended));

    forged = if forged.len() < modulus.len() {
        forged.extend(vec![0x00].repeat(modulus.len()-forged.len()));
        forged
    } else {
        forged[..modulus.len()].to_vec()
    };
    
    forged = cube_root(&forged);
    forged
}

// BrokenDSA does not check for zero values during key generation and signing
pub struct BrokenDSA {
    p: Vec<u8>,
    q: Vec<u8>,
    g: Vec<u8>,
    x: Vec<u8>,
    y: Vec<u8>,
}

impl BrokenDSA {
    pub fn new() -> BrokenDSA {
        let p = hextobytearray(&"800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1".to_string());
        let q = hextobytearray(&"f4f47f05794b256174bba6e9b396a7707e563c5b".to_string());
        let g = hextobytearray(&"5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291".to_string());
        let mut res = BrokenDSA { p: p, q: q, g: g, x: Vec::<u8>::new(), y: Vec::<u8>::new() };
        res.generate_user_keys();
        res
    }

    pub fn new_from_params(p: &[u8], q: &[u8], g: &[u8], x: &[u8], y: &[u8]) -> BrokenDSA {
        BrokenDSA { p: p.to_vec(), q: q.to_vec(), g: g.to_vec(), x: x.to_vec(), y: y.to_vec() }
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
        let k: Vec<u8>;
        let r: Vec<u8>;
        
        k = if let Some(val) = k_arg {
            val.to_vec()
        } else {
            self.pick_randint()
        };
        r = bytearray(&(bigint(&modpow_bytes(&self.g, &k, &self.p)) % bigint(&self.q)));
        let s = (modinv_bytes(&k, &self.q).expect("Signing error") * 
                        (bigint(&self.hash(&msg)) + bigint(&self.x) * bigint(&r)) % bigint(&self.q)) % bigint(&self.q);
        return (r, bytearray(&s));
    }

    pub fn verify(&self, msg: &[u8], signature: (&[u8], &[u8])) -> Result<(), Error> {
        let (r, s) = signature;
        if bigint(r) >= bigint(&self.q) {
            return Err(Error::InvalidDSASignature);
        }
        if bigint(s) >= bigint(&self.q) {
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

pub fn rsa_is_even_oracle(ciphertext: &[u8], rsa: &RSA) -> bool {
    let plaintext = rsa.decrypt(ciphertext);
    if plaintext.last().unwrap() % 2 == 0 {
        true
    } else {
        false
    }
}

pub fn rsa_parity_oracle_attack(ciphertext: &[u8], rsa: &RSA) -> Vec<u8> {
    let (exponent, modulus) = rsa.get_public_key();
    let mut ctr = 1u32;
    let mut low = BigInt::ZERO;
    let mut high = bigint(&modulus);
    let ct_int = bigint(ciphertext);
    
    loop {
        if low.clone() + 1 == high {
            return bytearray(&low);
        }
        let product = (ct_int.clone() * bigint(&modpow_bytes(&bytearray(&(bigint(&[2u8]).pow(ctr))), &exponent, &modulus))) % bigint(&modulus);
        if rsa_is_even_oracle(&bytearray(&product), rsa) {
            high -= (high.clone() - low.clone()) / 2;
        } else {
            low += (high.clone() - low.clone()) / 2;
        }
        ctr += 1;
    }
}

pub fn recover_dsa_private_key(k: &[u8], r: &[u8], s: &[u8], q: &[u8], hash: &[u8]) -> Vec<u8> {
    let x = (modinv_bytes(r, q).unwrap() * ((bigint(s) * bigint(k) - bigint(hash)) % bigint(q))) % bigint(q);
    bytearray(&x)
}

pub fn recover_dsa_nonce(m1: &[u8], m2: &[u8], s1: &[u8], s2: &[u8], q: &[u8]) -> Vec<u8> {
    let mut res = modinv_bytes(&bytearray(&(bigint(&s1) - bigint(&s2))), &q).expect("DSA Nonce recovery error");
    res = (((bigint(&hash_sha1(&m1)) - bigint(&hash_sha1(&m2))) % bigint(q)) * res) % bigint(&q);
    bytearray(&res)
}

pub fn rsa_pkcs1v15_encryption_oracle(msg: &[u8]) -> Result<(), Error> {
    let mut msg_iter = msg.iter();
    if msg_iter.next() != Some(&0x00) {
        return Err(Error::InvalidPKCS1v15EncryptionPadding);
    }
    if msg_iter.next() != Some(&0x02) {
        return Err(Error::InvalidPKCS1v15EncryptionPadding);
    }
    Ok(())
}

pub fn mini_bleichenbacher_attack_rsa_pkcs1v15_encryption(rsa: &MiniRSA, ciphertext: &[u8]) -> Vec<u8> {
    let (exponent, modulus) = rsa.get_public_key();

    let generate_ciphertext = |c: &BigInt, base: &BigInt| -> Result<BigInt, Error> {
        let candidate = (c * bigint(&modpow_bytes(&bytearray(&base), &exponent, &modulus))) % bigint(&modulus);
        let mut decrypted = rsa.decrypt(&bytearray(&candidate));
        
        // Manually prepend 0 because conversion of results of mathematical operations does not usually do that
        decrypted.insert(0, 0x00);
        match rsa_pkcs1v15_encryption_oracle(&decrypted) {
            Ok(()) => Ok(candidate),
            Err(e) => Err(e)
        }
    };

    let calculate_capital_m = |curr_capital_m: &Vec<(BigInt, BigInt)>, curr_s: &BigInt, capital_b: &BigInt| -> Vec::<(BigInt, BigInt)> {
        let mut capital_m = Vec::<(BigInt, BigInt)>::new();
        for (a, b) in curr_capital_m.iter() {
            let lower_bnd: BigInt = bigint_div_ceil(&(a * curr_s - 3 * capital_b + 1), &bigint(&modulus));
            let upper_bnd: BigInt = (b * curr_s - 2 * capital_b) / bigint(&modulus);

            if lower_bnd != upper_bnd {
                println!();
                panic!("Lower bound should equal upper bound.");
            }
            
            let r = lower_bnd;
            let lower = std::cmp::max(a.clone(), bigint_div_ceil(&(2 * capital_b + r.clone() * bigint(&modulus)), &curr_s));
            let upper = std::cmp::min(b.clone(), bigint_div_floor(&(3 * capital_b - 1 + r.clone() * bigint(&modulus)), &curr_s));
            capital_m.push((lower, upper));
        }
        capital_m
    };
    
    // Initialize values
    let c = bigint(&ciphertext);
    let capital_b = BigInt::from(2).pow((256-16) as u32);
    let mut capital_m = Vec::<(BigInt, BigInt)>::new();

    let mut s_vals = Vec::<BigInt>::new();
    let mut i = 1usize;
    
    s_vals.push(BigInt::from(1));
    
    capital_m.push((2*capital_b.clone(), 3*capital_b.clone() - 1));

    loop {
        println!(".");
        let s_i_minus_1: BigInt = s_vals.last().unwrap().clone();
        let mut s_i: BigInt;
        
        // Step 2.a
        if i == 1 {
            s_i = bigint_div_ceil(&bigint(&modulus), &(3*capital_b.clone()));
        
            loop {
                if let Ok(_) = generate_ciphertext(&c, &s_i) {
                    break;
                }
                s_i += 1;
            }
        } else {
            let (a, b) = capital_m.last().unwrap();
            
            let mut r_i: BigInt = bigint_div_ceil(&(2 * (b * s_i_minus_1.clone() - 2 * capital_b.clone())), &bigint(&modulus));
            s_i = bigint_div_ceil(&(2 * capital_b.clone() + r_i.clone() * bigint(&modulus)), &b);
            
            loop {
                if let Ok(_) = generate_ciphertext(&c, &s_i) {
                    break;
                }
                if s_i < (3 * capital_b.clone() + r_i.clone() * bigint(&modulus)) / a {
                    s_i += 1;
                }
                else {
                    r_i += 1;
                    s_i = bigint_div_ceil(&(2 * capital_b.clone() + r_i.clone() * bigint(&modulus)), &b);
                }
            }
        }

        s_vals.push(s_i.clone());

        // Step 3
        capital_m = calculate_capital_m(&capital_m, &s_i, &capital_b);
        if capital_m.len() > 1 {
            panic!("More than one bound found.");
        }

        if capital_m[0].1 == capital_m[0].0 {
            println!("\nConverged in {} iterations.", i);
            return bytearray(&capital_m[0].0);
        }

        i += 1;
    }
}

pub fn bleichenbacher_attack_rsa_pkcs1v15_encryption(rsa: &MiniRSA, ciphertext: &[u8]) -> Vec<u8> {
    let (exponent, modulus) = rsa.get_public_key();
    
    let generate_ciphertext = |c: &BigInt, base: &BigInt| -> Result<BigInt, Error> {
        let candidate = (c * bigint(&modpow_bytes(&bytearray(&base), &exponent, &modulus))) % bigint(&modulus);
        let mut decrypted = rsa.decrypt(&bytearray(&candidate));
        
        // Manually prepend 0 because conversion of results of mathematical operations does not usually do that
        decrypted.insert(0, 0x00);
        match rsa_pkcs1v15_encryption_oracle(&decrypted) {
            Ok(()) => Ok(candidate),
            Err(e) => Err(e)
        }
    };

    let calculate_capital_m = |curr_capital_m: &Vec<(BigInt, BigInt)>, curr_s: &BigInt, capital_b: &BigInt| -> Vec::<(BigInt, BigInt)> {
        let mut capital_m = Vec::<(BigInt, BigInt)>::new();
        for (a, b) in curr_capital_m.iter() {
            let lower_bnd: BigInt = bigint_div_ceil(&(a * curr_s - 3 * capital_b + 1), &bigint(&modulus));
            let upper_bnd: BigInt = (b * curr_s - 2 * capital_b) / bigint(&modulus);
            if lower_bnd > upper_bnd {
                panic!("Lower bound greater than upper");
            }
            let mut r = lower_bnd;
            loop {
                if r > upper_bnd {
                    break;
                }
                let lower = std::cmp::max(a.clone(), bigint_div_ceil(&(2 * capital_b + r.clone() * bigint(&modulus)), &curr_s));
                let upper = std::cmp::min(b.clone(), bigint_div_floor(&(3 * capital_b - 1 + r.clone() * bigint(&modulus)), &curr_s));
                capital_m.push((lower, upper));
                r += 1;
            }
        }
        if capital_m.len() > 1 {
            // Take union of all subsets
            let mut union_val = Vec::<(BigInt, BigInt)>::new();
            capital_m.sort_by(|a, b| a.0.cmp(&b.0));
            union_val.push(capital_m[0].clone());
            let mut union_ctr = 0;
            let mut capm_ctr = 1;
            loop {
                if capm_ctr >= capital_m.len() {
                    break;
                }
                if union_val[union_ctr].1 >= capital_m[capm_ctr].0 {
                    union_val[union_ctr].1 = capital_m[capm_ctr].1.clone();
                    capm_ctr += 1;
                } else {
                    union_val.push(capital_m[capm_ctr].clone());
                    union_ctr += 1;
                    capm_ctr += 1;
                }
            }
            union_val
        } else {
            capital_m
        }
    };
    
    // Step 1: Blinding
    let c = bigint(&ciphertext);
    let capital_b = BigInt::from(2).pow((8*(modulus.len()-2)) as u32);
    let mut i: usize = 1;
    let mut capital_m = Vec::<(BigInt, BigInt)>::new();
    let mut s_vals = Vec::<BigInt>::new();
    
    capital_m.push((2*capital_b.clone(), 3*capital_b.clone() - 1));
    
    // Skipping blinding since ciphertext is already PKCS compliant
    // let (c0, s0) = loop {
    //     let randbytes = generate_random_bytevec(modulus.len());
    //     let s0 = bigint(&randbytes) % bigint(&modulus);
    //     if let Ok(c_prime) = generate_ciphertext(&c, &s0) {
    //         break (c_prime, s0);
    //     }
    // };
    
    let c0 = c.clone();
    let s0 = BigInt::from(1);

    s_vals.push(s0);
 
    // Step 2: Searching for PKCS conforming messages
    loop {
        println!(".");
        let s_i_minus_1: BigInt = s_vals.last().unwrap().clone();
        let mut s_i: BigInt = s_i_minus_1.clone() + 1;

        // Step 2.a, b
        if i == 1 || capital_m.len() > 1 {
            if i == 1 {
                s_i = bigint_div_ceil(&bigint(&modulus), &(3*capital_b.clone()));
            }
            loop {
                if let Ok(_) = generate_ciphertext(&c0, &s_i) { 
                    break;
                }
                s_i += 1;
            }
            s_vals.push(s_i.clone());
            
            // Step 3: Narrowing the set of solutions
            capital_m = calculate_capital_m(&capital_m, &s_i, &capital_b);

            // Step 4: Computing the solution
            if capital_m.len() == 1 && capital_m[0].1 == capital_m[0].0 {
                return bytearray(&capital_m[0].0);
            }
            i += 1;
            continue;
        }

        // Step 2.c
        let (a, b) = capital_m.last().unwrap();
            
        let mut r_i: BigInt = bigint_div_ceil(&(2 * (b * s_i_minus_1.clone() - 2 * capital_b.clone())), &bigint(&modulus));
        s_i = bigint_div_ceil(&(2 * capital_b.clone() + r_i.clone() * bigint(&modulus)), &b);
        
        loop {
            if let Ok(_) = generate_ciphertext(&c, &s_i) {
                break;
            }
            if s_i < (3 * capital_b.clone() + r_i.clone() * bigint(&modulus)) / a {
                s_i += 1;
            }
            else {
                r_i += 1;
                s_i = bigint_div_ceil(&(2 * capital_b.clone() + r_i.clone() * bigint(&modulus)), &b);
            }
        }

        s_vals.push(s_i.clone());

        // Step 3: Narrowing the set of solutions
        capital_m = calculate_capital_m(&capital_m, &s_i, &capital_b);
        
        // Step 4: Computing the solution
        if capital_m.len() == 1 && capital_m[0].1 == capital_m[0].0 {
            return bytearray(&capital_m[0].0);
        }
        i += 1;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_rsa_unpadded_message_recovery_attack() {
        let rsa = RSA::new(&2048u16);
        let mut server = MessageServer::new(&rsa);
        
        let (exponent, modulus) = rsa.get_public_key();

        let plaintext = b"Welcome to Bologna";
        let ciphertext = rsa.encrypt(plaintext);
        
        let retrieved_plaintext = rsa_unpadded_message_recovery_attack(&ciphertext, &modulus, &exponent, &mut server);

        assert_eq!(plaintext.to_vec(), retrieved_plaintext);
    }

    #[test]
    fn test_message_server() {
        let rsa = RSA::new(&2048u16);
        let mut server = MessageServer::new(&rsa);
        let plaintext = b"Welcome to Bologna";
        let ciphertext = rsa.encrypt(plaintext);
        
        assert_eq!(server.decrypt(&ciphertext).unwrap(), plaintext.clone());
    }

    #[test]
    fn test_pad_pkcs1v15() {
        let msg = b"Sing the blues.";
        let mut hash = ASN1_MD5.to_vec();
        hash.extend(hash_md5(msg));
        let hash_len = 16; // MD5
        let padded = pad_pkcs1v15(&hash, 128).unwrap();
        assert_eq!(&padded[(padded.len() - hash_len)..], &hash[ASN1_MD5.len()..]);
    }

    #[test]
    fn test_pad_pkcs1v15_encryption() {
        let msg = b"Sing the blues.";
        let mut hash = ASN1_MD5.to_vec();
        hash.extend(hash_md5(msg));
        let hash_len = 16; // MD5
        let padded = pad_pkcs1v15_encryption(&hash, 128).unwrap();
        assert_eq!(&padded[(padded.len() - hash_len)..], &hash[ASN1_MD5.len()..]);
    }

    #[test]
    fn test_md5() {
        assert_eq!(hash_md5(b"hello, world"), hextobytearray(&"e4d7f1b4ed2e42d15898f4b27b019da4".to_string()));
    }

    #[test]
    fn test_rsa_pkcs1v15_encryption_oracle() {
        let rsa = RSA::new(&2048u16);
        let mut padded = rsa.decrypt(&rsa.encrypt(&pad_pkcs1v15_encryption(b"This is Sparta!", 128).unwrap()));
        padded.insert(0, 0x00);
        assert_eq!(rsa_pkcs1v15_encryption_oracle(&padded).unwrap(), ());
        padded[1] = 0x03;
        assert_eq!(rsa_pkcs1v15_encryption_oracle(&padded), Err(Error::InvalidPKCS1v15EncryptionPadding));
    }

    #[test]
    fn test_cube_root() {
        let cbrt = cube_root(&BigInt::from(1207478546322552i64).to_bytes_be().1);
        assert_eq!(BigInt::from_bytes_be(Sign::Plus, &cbrt), BigInt::from(106487i32));
    }
}
