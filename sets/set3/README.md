# Set 3

[Challenge link in the Cryptopals website](https://cryptopals.com/sets/3)

- [x] [The CBC padding oracle](#the-cbc-padding-oracle)
- [x] [Implement CTR or the stream cipher mode](#implement-ctr-or-the-stream-cipher-mode)
- [x] [Break fixed-nonce CTR mode using substitutions](#break-fixed-nonce-ctr-mode-using-substitutions)
- [x] [Break fixed-nonce CTR statistically](#break-fixed-nonce-ctr-statistically)
- [x] [Implement the MT19937 Mersenne Twister RNG](#implement-the-mt19937-mersenne-twister-rng)
- [x] [Crack an MT19937 seed](#crack-an-mt19937-seed)
- [x] [Clone an MT19937 RNG from its output](#clone-an-mt19937-rng-from-its-output)
- [x] [Create the MT19937 stream cipher and break it](#create-the-mt19937-stream-cipher-and-break-it)

## The CBC padding oracle

A padding oracle `padding_oracle()` checks whether the plaintext has valid PKCS7 padding. The function `decrypt_cbc_block_padding_oracle()` uses this oracle to discover the padding byte. Then, similar to the CBC bitflipping attack from [Set 2](../set2/README.md), we build up a zeroing IV for the last (padded) block. The zeroing IV then is the key to the CBC encryptor! The key is then used to decrypt any other ciphertext blocks to recover the plaintext.

```rust
let base64_strings: Vec<String> = vec![
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=".to_string(),
    ... // Skipping the long list of base 64 encoded strings
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93".to_string()
];

let (encryptor, decryptor, iv) = aes_cbc_encryptor_decryptor_factory();

let encryptor_2 = || -> (Vec<u8>, Vec<u8>) {
    let mut rng = rand::thread_rng();
    
    // Pick random base64 encoded string
    let idx: usize = rng.gen::<usize>() % base64_strings.len();
    let to_encrypt: Vec<u8> = base64tobytearray(&base64_strings[idx].replace("=", ""));
    
    (encryptor(&to_encrypt), iv.clone())
};

let padding_oracle = |ciphertext: &Vec<u8>| -> bool {
    let decrypted: Vec<u8> = decryptor(ciphertext);
    check_valid_pkcs7_padding(&decrypted)
};

let mut ciphertexts = Vec::<Vec<u8>>::new();
let mut iv = Vec::<u8>::new();

loop {
    let (ciphertext, got_iv) = encryptor_2();
    if iv.len() == 0 {
        iv = got_iv;
    }
    if !ciphertexts.contains(&ciphertext) {
        ciphertexts.push(ciphertext);
    }

    if ciphertexts.len() == 10 {
        break;
    }
}
println!();

for ciphertext in ciphertexts.iter() {
    let mut ciphertext_chunks: Vec<Vec<u8>> = ciphertext.chunks(16).map(|x| x.to_vec()).collect();
    let mut plaintext_chunks = Vec::<Vec<u8>>::new();
    ciphertext_chunks.insert(0, iv.clone());

    for count in 0..ciphertext_chunks.len()-1 {
        let plaintext_chunk: Vec<u8> = match decrypt_cbc_block_padding_oracle(&ciphertext_chunks[count], &ciphertext_chunks[count+1], &padding_oracle) {
            Ok(sth) => sth,
            Err(_) => {
                println!("Decryption error.");
                break;
            }
        };

        if count == ciphertext_chunks.len() - 2 {
            match strip_pkcs7_padding(&plaintext_chunk) {
                Ok(sth) => plaintext_chunks.push(sth),
                Err(_) => plaintext_chunks.push(plaintext_chunk)
            };
            continue;
        }
        plaintext_chunks.push(plaintext_chunk);
    }
    if plaintext_chunks.len() == ciphertext_chunks.len() - 1 {
        for chunk in plaintext_chunks.into_iter() {
            print!("{}", String::from_utf8(chunk).unwrap());
        }
    }
    println!();
}
```

## Implement CTR or the stream cipher mode

The CTR mode involves prepending the index of the plaintext block in front of it before following the same encryption protocol as AES ECB. Therefore, [`aes_ctr_decrypt()`](../../aescipher/src/lib.rs) uses `aes_ecb_encrypt()` after prepending the counter to each plaintext block.

```rust
let ciphertext: Vec<u8> = base64tobytearray(&"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==".to_string().replace("=", ""));
let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
let nonce: Vec<u8> = b"\x00".repeat(key.len() / 2);
let plaintext: Vec<u8> = aes_ctr_decrypt(&ciphertext, &key, &nonce);
println!("{}", String::from_utf8(plaintext).unwrap());
```

## Break fixed-nonce CTR mode using substitutions

The procedure for breaking CTR mode with a fixed nonce is similar to breaking an AES ECB cipher - we collect bytes from n-th positions of the ciphertext and treat each collection as if it has been encrypted by XOR'ing against a single byte of the key.

```rust
let plaintext_strings: Vec<&str> = vec![
    "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
    ... // Skipping the long list of base 64 encoded strings
    "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
];
let plaintexts: Vec<Vec<u8>> = plaintext_strings
                                                .iter()
                                                .map(|txt_str| base64tobytearray(&txt_str.to_string().replace("=", "")))
                                                .collect();

let max_plaintext_len: usize = plaintexts.iter().map(|x| x.len()).max().unwrap();

let dumb_ctr_encryptor = get_ctr_encryptor();
let ciphertexts: Vec<Vec<u8>> = plaintexts.iter().map(&dumb_ctr_encryptor).collect();

let mut ciphertext_chunk_vec = Vec::<Vec<u8>>::new();
for count in 0..max_plaintext_len {
    let nth_bytes: Vec<u8> = ciphertexts.iter().map(|txt| txt.iter().nth(count)).filter(|x| x.is_some()).map(|x| *x.unwrap()).collect();
    ciphertext_chunk_vec.push(nth_bytes);
}

// Decrypt keystream from ciphertexts
let keystream: Vec<u8> = ciphertext_chunk_vec
                            .iter()
                            .map(|x| {
                                let res = decrypt_singlebyte_xor(&bytearraytohex(&x));
                                res[0].key
                            })
                            .collect();

// Decrypt ciphertexts
for ciphertext in ciphertexts.iter() {
    let decrypted: Vec<u8> = zip(ciphertext.iter(), keystream.iter())
                                .map(|(a, b)| a ^ b)
                                .collect();
    match String::from_utf8(decrypted.clone()) {
        Ok(sth) => println!("{}", sth),
        Err(_) => {
            println!("{}", String::from_utf8(decrypted.into_iter().filter(|x| *x < 127).collect()).unwrap());
        }
    };
}
```

## Break fixed-nonce CTR statistically

The problem from [challenge 19](#break-fixed-nonce-ctr-mode-using-substitutions) is framed as a repeating-key XOR problem. Then it becomes a matter of cracking the repeating-key XOR cipher using a histogram of the English alphabet, like in [Set 1](../set1/README.md). To increase the number of samples for the frequency counts all the ciphertexts in the raw text file given in the problem are concatenated.

```rust
let plaintext_raw = fs::read_to_string("20.txt").unwrap();
let plaintexts: Vec<Vec<u8>> = plaintext_raw
                                    .lines()
                                    .map(|x| base64tobytearray(&x.to_string().replace("=", "")))
                                    .collect();

let mut min_plaintext_len: usize = plaintexts.iter().map(|x| x.len()).min().unwrap();
min_plaintext_len -= min_plaintext_len % 16;   // Truncating to the nearest multiple of block
                                               // size since encryption is in chunks of
                                               // blocksize bytes.

let dumb_ctr_encryptor = get_ctr_encryptor();
let ciphertexts: Vec<Vec<u8>> = plaintexts.iter().map(&dumb_ctr_encryptor).collect();

// Decrypt keystream from concatenated ciphertexts
let ciphertexts_concat: Vec<u8> = ciphertexts.iter().map(|x| x[..min_plaintext_len].to_vec()).flatten().collect();

let keystream = decrypt_known_keysize_repeatingkey_xor(&ciphertexts_concat, &min_plaintext_len);

// Decrypt ciphertexts
for ciphertext in ciphertexts.iter() {
    let decrypted: Vec<u8> = zip(ciphertext.iter(), keystream.iter())
                                .map(|(a, b)| a ^ b)
                                .collect();
    match String::from_utf8(decrypted.clone()) {
        Ok(sth) => println!("{}", sth),
        Err(_) => {
            println!("{}", String::from_utf8(decrypted.into_iter().filter(|x| *x < 127).collect()).unwrap());
        }
    };
}
```

## Implement the MT19937 Mersenne Twister RNG

This implementation of the MT19937 Mersenne Twister random number generator is based on the pseudocode in [Wikipedia](https://en.wikipedia.org/wiki/Mersenne_Twister#Algorithmic_detail). For the sake of conciseness, only the implementation of the struct [`MT19937Gen`](../../mersennetwister/src/lib.rs) is mentioned.

```rust
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
```

## Crack an MT19937 seed

If we know the timestamp in which a particular MT PRNG produces a random integer, we can utilize the timestamp to determine the original timestamp that was used to seed the PRNG. This can be done by repeatedly generating new timestamps at different intervals from the original, creating new PRNGs and seeding them using these timestamps. Since the generation of the first random number is determined by the seed, by checking for equality between the original random number and the present one, we can find out the original timestamp used as a seed for the PRNG.

```rust
let get_rng_output = || -> u32 {
    let mut rng = MT19937Gen::new(13);
    let mut get_random_secs = || -> u64 {
        40 + (rng.gen() as u64) % (1000 - 40)
    };

    let sleep_secs = get_random_secs();
    thread::sleep(Duration::from_secs(sleep_secs));

    let mut rng_2 = MT19937Gen::new(get_unix_timestamp() as u32);
    thread::sleep(Duration::from_secs(get_random_secs()));
    rng_2.gen()   
};

let randint: u32 = get_rng_output();
let timestamp: u64 = get_unix_timestamp();

// Crack the seed of the RNG from the time elapsed since generation
for secs in 40..1000 {
    let mut rng = MT19937Gen::new((timestamp - secs) as u32);
    if !rng.gen() == randint {
        continue;
    }
    println!("Cracked seed = {}", timestamp - secs);
    break;
}
```

## Clone an MT19937 RNG from its output

An MT19937 PRNG comes with a state vector which is used while generating random numbers. To generate a new random number, the state is modified using a tempering step. If the state vector of the RNG is recovered, it can be used to clone the random number generator! This recovery is done using the [`mt19937_32_untemper()`](../../mersennetwister/src/lib.rs) function. `mt19937_32_untemper()` reverses the tempering step of a MT19937 random number generator and uses this to regenerate the state vector of the RNG, and hence helping in the cloning of the MT19937 RNG.

```rust
let mut rng = MT19937Gen::new(get_unix_timestamp().try_into().unwrap());
let mut guessed_state = Vec::<u32>::new();
let mut randnums = Vec::<u32>::new();
for count in 0..624 {
    randnums.push(rng.gen());
    guessed_state.push(mt19937_32_untemper(&randnums[count]));
}
let mut newrng = MT19937Gen::new_from(&guessed_state);
assert_eq!((0..624).map(|_| newrng.gen()).collect::<Vec<u32>>(), (0..624).map(|_| rng.gen()).collect::<Vec<u32>>());
```

## Create the MT19937 stream cipher and break it

The MT19937 stream cipher is different from the CTR stream cipher in that instead of the index of the plaintext block, a random number generated by the PRNG is used for the stream. Usually if the MT19937 PRNG seed is deduced then the stream cipher can be easily broken. In this instance the seed is a 16 bit number which is broken by exhaustively iterating through all possible combinations of bits. The cipher is then broken in a fashion similar to [challenge 22](#crack-an-mt19937-seed).

```rust
let generate_plaintext = || -> Vec<u8> {
    let size = generate_random_bytevec(17)[0];
    let mut plaintext: Vec<u8> = generate_random_bytevec(size as usize);
    plaintext.extend(b"A".to_vec().repeat(14));
    plaintext
};

let seed: u16 = 0xABCD;
let plaintext = generate_plaintext();
let ciphertext: Vec<u8> = mt19937_keystream_encrypt(&plaintext, &seed);

println!("Plaintext:");
format_chunks(&plaintext);

println!("Encrypted:");
format_chunks(&ciphertext);

println!("Decrypted:");
let decrypted: Vec<u8> = mt19937_keystream_encrypt(&ciphertext, &seed);
format_chunks(&decrypted);

let matched_keystream: Vec<u8> = zip(plaintext.iter(), ciphertext.iter())
                                    .map(|(a, b)| a ^ b)
                                    .skip(ciphertext.len() - 14)
                                    .take(14)
                                    .collect();

let break_mt19937_16_bit_keystream = || -> u16 {
    for guess in 0..=0xFFFFu16 {
        let mut rng = MT19937Gen::new(guess as u32);
        let keystream: Vec<u8> = (0..ciphertext.len())
                                    .map(|_| rng.gen())
                                    .skip(ciphertext.len() - 14)
                                    .take(14)
                                    .map(|x| (x & 0xFF) as u8)
                                    .collect();
        if keystream != matched_keystream {
            continue;
        }
        return guess;
    }
    panic!("Match not found.");
};

let guess = break_mt19937_16_bit_keystream();
assert_eq!(guess, seed);

let generate_password_reset_token = |txt: &Vec<u8>| -> Vec<u8> {
    mt19937_keystream_encrypt(txt, &((get_unix_timestamp() & 0xFFFF) as u16))
};

let password = b"DoNotHackMe".to_vec();
let token = generate_password_reset_token(&password);
let timestamp = get_unix_timestamp();
for secs in 0..=60 {
    let guess = mt19937_keystream_encrypt(&password, &(((timestamp - secs) & 0xFFFF) as u16));
    if guess != token {
        continue;
    }
    println!("Key: {}, secs: {}", ((timestamp - secs) & 0xFFFF) as u16, secs);
    break;
}
```

