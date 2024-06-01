use std::iter::*;
use std::time::{ SystemTime, UNIX_EPOCH };

use set1::*;
use set2::*;

#[derive(Debug, PartialEq)]
pub enum Error {
    NoMatchFound,
    DecryptionError
}

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

pub fn get_unix_timestamp() -> u64 {
    let now = SystemTime::now();
    let duration_since_epoch = now.duration_since(UNIX_EPOCH).expect("Time cannot go backwards.");
    duration_since_epoch.as_secs()
}

fn u8tohex(val: &u8) -> String {
    let lower_bits = digit2hexsym(&(val & 0x0F));
    let higher_bits = digit2hexsym(&(val >> 4 & 0x0F));
    format!("{}{}", &higher_bits, &lower_bits)
}

pub fn decrypt_known_keysize_repeatingkey_xor(ciphertext: &Vec<u8>, keysize: &usize) -> Vec<u8> {
    let mut to_decrypt = Vec::<String>::new();
    for idx in 1..=(*keysize){
        let collected: Vec<u8> = ciphertext.iter().skip(idx - 1).step_by(16).copied().collect();
        to_decrypt.push(bytearraytohex(&collected));
    }
    let decrypted_keys: Vec<(u8, f32)> = to_decrypt
                        .iter()
                        .map(|a| decrypt_singlebyte_xor(&a))
                        .map(|b| (b[0].key, b[0].score))
                        .collect();
    decrypted_keys.iter().map(|(a, _)| *a).collect()
}

pub fn check_valid_pkcs7_padding(ciphertext: &Vec<u8>) -> bool {
    let block: Vec<&u8> = ciphertext.iter().skip(ciphertext.len()-16).take(16).collect();
    let last_byte: &u8 = block.iter().last().unwrap();
    let mut iterator = block.iter().rev();
    let mut count = 0;
    while let Some(byteval) = iterator.next() {
        if **byteval != *last_byte {
            break;
        }
        count += 1;
    }
    if count <= block.len() && count as u8 == *last_byte {
        return true;
    }
    return false;
}

pub fn aes_cbc_encryptor_decryptor_factory() -> (impl Fn(&Vec<u8>) -> Vec<u8>, impl Fn(&Vec<u8>) -> Vec<u8>, Vec<u8>) {
    let random_key: Vec<u8> = generate_random_bytevec(16usize);
    let random_iv: Vec<u8> = generate_random_bytevec(16usize);
    let key_cloned: Vec<u8> = random_key.clone();
    let iv_cloned: Vec<u8> = random_iv.clone();
    let iv_cloned_cloned: Vec<u8> = iv_cloned.clone();

    let encryptor = move |plaintext: &Vec<u8>| -> Vec<u8> {
        aes_cbc_encrypt(plaintext, &random_iv, &random_key)
    };
    let decryptor = move |ciphertext: &Vec<u8>| -> Vec<u8> {
        aes_cbc_decrypt(ciphertext, &iv_cloned, &key_cloned)
    };
    (encryptor, decryptor, iv_cloned_cloned)
}

pub fn find_matching_byteval(padding_oracle: &dyn Fn(&Vec<u8>) -> bool, ciphertext_arg: &Vec<u8>, pos: usize) -> Result<u8, Error> {
    let mut ciphertext: Vec<u8> = ciphertext_arg.clone();

    for count in 0..=255u8 {
        ciphertext[pos] = count;
        if !padding_oracle(&ciphertext) {
            continue;
        }
        if pos == 15 {
            ciphertext[pos-1] >>= 1;
            if padding_oracle(&ciphertext) {
                return Ok(count);
            }
            ciphertext[pos-1] = ciphertext_arg[pos-1];
            continue;
        }
        return Ok(count);
    }
    return Err(Error::NoMatchFound);
}

pub fn decrypt_cbc_block_padding_oracle(iv: &Vec<u8>, block: &Vec<u8>, padding_oracle: &dyn Fn(&Vec<u8>) -> bool) -> Result<Vec<u8>, Error> {
    let mut zeroing_iv = Vec::<u8>::new();
    let mut matching_byteval: u8;
    let mut ciphertext: Vec<u8> = iv.clone();

    ciphertext.extend(block.clone());
    let mut ciphertext_clone = ciphertext.clone();

    let ciphertext_len: usize = ciphertext.len();
    
    for pos in 1..=16usize {
        for (count, val) in zeroing_iv.iter().enumerate() {
            ciphertext_clone[ciphertext_len - 17 - count] = pos as u8 ^ val;
        }
        matching_byteval = match find_matching_byteval(&padding_oracle, &ciphertext_clone, ciphertext_len - 16 - pos) {
            Ok(sth) => sth,
            Err(_) => return Err(Error::DecryptionError),
        };
        zeroing_iv.push(pos as u8 ^ matching_byteval);
    }

    ciphertext_clone = ciphertext.clone();

    Ok(zip(zeroing_iv.iter().rev(), ciphertext_clone.iter())
        .map(|(val1, val2)| val1 ^ val2) 
        .collect())
}

fn decrypt_aes_ctr_block(ciphertext_block: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>, ctr: &Vec<u8>) -> Vec<u8> {
    let mut to_encrypt: Vec<u8> = nonce.clone();
    to_encrypt.extend(ctr.clone());
    let enc_ctr: Vec<u8> = aes_ecb_encrypt(&to_encrypt, key);
    zip(enc_ctr.iter(), ciphertext_block.iter())
        .map(|(val1, val2)| val1 ^ val2)
        .collect()
}

pub fn mt19937_keystream_encrypt(text: &Vec<u8>, key: &u16) -> Vec<u8> {
    let mut rng = MT19937Gen::new(*key as u32);
    text
        .iter()
        .map(|el| el ^ ((rng.gen() & 0xFF) as u8))
        .collect()
}

pub fn aes_ctr_decrypt(ciphertext: &Vec<u8>, key: &Vec<u8>, nonce: &Vec<u8>) -> Vec<u8> {
    let mut plaintext_chunks = Vec::<Vec<u8>>::new();
    for (ctr, chunk) in ciphertext.chunks(16).enumerate() {
        let mut ctr_vec = vec![0u8; 8];
        let ctr_cnv: Vec<u8> = hextobytearray(&u8tohex(&(ctr as u8)));
        ctr_vec[0..ctr_cnv.len()].copy_from_slice(&ctr_cnv);
        let plaintext_chunk = decrypt_aes_ctr_block(&chunk.to_vec(), &key, &nonce, &ctr_vec);
        match strip_pkcs7_padding(&plaintext_chunk) {
            Ok(sth) => plaintext_chunks.push(sth),
            Err(_) => plaintext_chunks.push(plaintext_chunk),
        };
    }
    plaintext_chunks.into_iter().flatten().collect()
}

pub fn get_ctr_encryptor() -> impl Fn(&Vec<u8>) -> Vec<u8> {
    let key = generate_random_bytevec(16);
    let nonce = b"\x00".repeat(16).to_vec();
    let dumb_ctr_encryptor = move |plaintext: &Vec<u8>| -> Vec<u8> {
        aes_ctr_decrypt(plaintext, &key, &nonce)
    };
    return dumb_ctr_encryptor;
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_check_valid_pkcs7_padding() {
        let block: Vec<u8> = vec![10, 2, 32, 13, 11, 197, 6, 22, 8, 8, 8, 8, 8, 8, 8, 8];
        let block_2: Vec<u8> = vec![10, 2, 32, 13, 11, 197, 6, 22, 7, 7, 7, 7, 7, 7, 1, 1];
        assert!(check_valid_pkcs7_padding(&block));
        assert!(!check_valid_pkcs7_padding(&block_2));
    }

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
