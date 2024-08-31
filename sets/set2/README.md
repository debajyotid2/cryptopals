# Set 2

[Challenge link in the Cryptopals website](https://cryptopals.com/sets/2)

- [x] [Implement PKCS7 padding](#implement-pkcs7-padding)
- [x] [Implement CBC mode](#implement-cbc-mode)
- [x] [An ECB-CBC detection oracle](#an-ecb-cbc-detection-oracle)
- [x] [Simple Byte-at-a-time ECB decryption](#simple-byte-at-a-time-ecb-decryption)
- [x] [ECB cut-and-paste](#ecb-cut-and-paste)
- [x] [Harder Byte-at-a-time ECB decryption](#harder-byte-at-a-time-ecb-decryption)
- [x] [PKCS7 padding validation](#pkcs7-padding-validation)
- [x] [CBC bitflipping attacks](#cbc-bitflipping-attacks)

## Implement PKCS7 padding

[`pad_pkcs7()`](../../aescipher/src/lib.rs) adds PKCS#7 padding to plaintext before encryption.
```rust
let block: Vec<u8> = b"Pigs are fly".to_vec();
assert_eq!((pad_pkcs7(&block, 16)).unwrap().len(), 16);
assert_eq!((pad_pkcs7(&block, 16)).unwrap(), b"Pigs are fly\x04\x04\x04\x04");
```

## Implement CBC mode

Cipher Block Chaining ([CBC](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)) mode of encryption is implemented by XOR'ing the previous ciphertext block to the next block of plaintext to be encrypted, before "ECB-encrypting" it, i.e. under the hood we can use the same function that was used for AES-ECB encryption! ([`aes_cbc_decrypt()`](../../aescipher/src/lib.rs))

```rust
let base64_ciphertext: String = fs::read_to_string("10.txt")
                            .unwrap_or(String::new())
                            .replace("\n", "")
                            .replace("=", "");
let init_vec: Vec<u8> = b"\x00".to_vec().repeat(16);
let key: Vec<u8> = b"YELLOW SUBMARINE".to_vec();
let encrypted: Vec<u8> = aes_cbc_decrypt(&base64tobytearray(&base64_ciphertext), &init_vec, &key);
println!("Decrypted = \n{}", &String::from_utf8(encrypted).unwrap());
```

## An ECB-CBC detection oracle

To detect whether a given ciphertext is ECB or CBC encrypted, [`encryption_oracle()`](./src/lib.rs) uses `detect_aes_ecb_encryption()` from [Set 1](../set1/README.md/) to find out if the ciphertext is ECB encrypted.

```rust
let plaintext = b"\x00".to_vec().repeat(3 * 16 - 5);
let mut count: usize = 0;
while count < 50 {
    println!("--------------------------------------------");
    println!("Iteration {}: ", count + 1);
    let ciphertext: Vec<u8> = random_aes_encryptor(&plaintext, true);
    encryption_oracle(&ciphertext);
    count += 1;
}
```

## Simple Byte-at-a-time ECB decryption

ECB encryption is broken by first guessing the block size of the encryption, followed by guessing the bytes one at a time. ([`guess_aes_ecb_appended_bytes()`](../../aescipher/src/lib.rs))

```rust
let random_key: Vec<u8> = generate_random_bytevec(16usize);
let encryptor = |plaintext_arg: &Vec<u8>| -> Vec<u8> {
    let mut plaintext: Vec<u8> = plaintext_arg.clone();
    let bytes_to_append: Vec<u8> = base64tobytearray(&String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));

    plaintext.extend(&bytes_to_append);
    aes_ecb_encrypt(&plaintext, &random_key)
};

// Detect AES ECB encryption block size  
let (blocksize, _, suffix_bytes_size): (usize, usize, usize) = get_aes_ecb_blocksize_and_appended_bytes_size(&encryptor);

println!("AES encryptor has block size of {} bits.", blocksize * 8);
println!("AES encryptor appends {} bytes to the plaintext as a suffix before encryption.", suffix_bytes_size);

// Detect whether AES ECB is being used
if detect_aes_ecb_encryption(&bytearraytohex(&encryptor(&b"\xce".to_vec().repeat(2 * blocksize)))) != 0 {
    println!("The encryption algorithm is AES ECB.");
}

// Brute force guess the appended bytes one byte at a time
let guessed_bytes: Vec<u8> = guess_aes_ecb_appended_bytes(blocksize, 0usize, suffix_bytes_size, &encryptor);

// assert!(guessed_bytes.len() >= suffix_bytes_size);
println!("Guessed suffix:\n{}", String::from_utf8(guessed_bytes).unwrap());
```

## ECB cut-and-paste

A user profile in an ECB encrypted plaintext is decrypted and modified by manipulating the user email by inserting a custom block of garbage text such that chunks of size equal to the blocksize of the encryptor get aligned. The result is that the ciphertext, when decrypted by the simulated "server" gets a different user role than the client originally intended to send. ([`get_aes_ecb_blocksize_and_appended_bytes()`](../../aescipher/src/lib.rs))

```rust
let (encryptor, decryptor) = aes_ecb_encryptor_decryptor_factory();
let (blocksize, _, suffix_bytes_size) = get_aes_ecb_blocksize_and_appended_bytes_size(&encryptor);

println!("Block size: {} bytes, appended bytes size: {} bytes.", &blocksize, &suffix_bytes_size);

let plaintext: Vec<u8> = profile_for(&"tesmanlicambalampur@gmail.com".to_string()).as_bytes().to_vec();
let ciphertext: Vec<u8> = encryptor(&plaintext);
let decrypted: Vec<u8> = decryptor(&ciphertext);

assert_eq!(&plaintext, &strip_pkcs7_padding(&decrypted).unwrap());

println!("Plaintext:");
for chunk in decrypted.clone().chunks(blocksize) {
    println!("{}", String::from_utf8(chunk.to_vec()).unwrap());
}

let malicious_plaintext: Vec<u8> = profile_for(&"tesmanlicambalampur@gmail.admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00com".to_string()).as_bytes().to_vec();
let mal_ciphertext_chunks: Vec<Vec<u8>> = (encryptor(&malicious_plaintext)).chunks(blocksize).map(|a| a.to_vec()).collect();
let mut temp: Vec<&Vec<u8>> = mal_ciphertext_chunks.iter().skip(3).take(mal_ciphertext_chunks.len() - 4).collect();

temp.insert(0, &mal_ciphertext_chunks[0]);
temp.insert(1, &mal_ciphertext_chunks[1]);
temp.push(&mal_ciphertext_chunks[2]);

let mal_ciphertext: Vec<u8> = temp.iter().map(|&x| x).flatten().map(|&x| x).collect();
let mal_decrypted: Vec<u8> = decryptor(&mal_ciphertext);

println!("Malicious profile decrypted:");
for chunk in mal_decrypted.clone().chunks(blocksize) {
    println!("{}", String::from_utf8(chunk.to_vec()).unwrap());
}
```

## Harder Byte-at-a-time ECB decryption

The same functions and general procedure as challenge [12](#simple-byte-at-a-time-ecb-decryption) are used. The additional step of guessing the number of prefix bytes is done by repeatedly encrypting plaintexts of varying lengths and looking for changes in the length of the ciphertext.([`detect_aes_ecb_encryption()`](../../aescipher/src/lib.rs))

```rust
let random_prefix_bytes: Vec<u8> = generate_random_bytevec(prefix_size);
let random_key: Vec<u8> = generate_random_bytevec(16usize);

let encryptor = |plaintext_arg: &Vec<u8>| -> Vec<u8> {
    let mut plaintext: Vec<u8> = random_prefix_bytes.clone();
    let bytes_to_append: Vec<u8> = base64tobytearray(&String::from("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"));
    
    plaintext.extend(&plaintext_arg.clone());
    plaintext.extend(&bytes_to_append);

    aes_ecb_encrypt(&plaintext, &random_key)
};

// Detect AES ECB encryption block size  
let (blocksize, num_prefix_bytes, num_suffix_bytes): (usize, usize, usize) = get_aes_ecb_blocksize_and_appended_bytes_size(&encryptor);

println!("AES encryptor has block size of {} bits.", blocksize * 8);
println!("AES encryptor appends {} bytes to the plaintext as a prefix and {} bytes as a suffix before encryption.", &num_prefix_bytes, &num_suffix_bytes);

assert_eq!(blocksize, 16usize);
assert_eq!(num_prefix_bytes, prefix_size);
assert_eq!(num_suffix_bytes, 136usize);

// Detect whether AES ECB is being used
if detect_aes_ecb_encryption(&bytearraytohex(&encryptor(&b"\xce".to_vec().repeat(2 * blocksize)))) != 0 {
    println!("The encryption algorithm is AES ECB.");
}

// Brute force guess the appended bytes one byte at a time
let guessed_bytes: Vec<u8> = guess_aes_ecb_appended_bytes(blocksize, num_prefix_bytes, num_suffix_bytes, &encryptor);

println!("Guessed suffix:\n{}", String::from_utf8(guessed_bytes).unwrap());
```

## PKCS7 padding validation

The function [`strip_pkcs7_padding()`](../../aescipher/src/lib.rs) detects PKCS7 padding and strips it off if it conforms to the PKCS7 standard and returns an error if it does not. The solution is part of the unit test suite in `lib.rs`.

```rust
let bytes: Vec<u8> = b"Bytes are fun!\xae\xae\xae\xae\xae".to_vec();
assert_eq!(strip_pkcs7_padding(&bytes).unwrap(), b"Bytes are fun!".to_vec());

let bytes_no_padding: Vec<u8> = b"ICE ICE BABY\x01\x02\x03\x04".to_vec();
assert_eq!(strip_pkcs7_padding(&bytes_no_padding), Err(Error::NoPadBytesFound));
```

## CBC bitflipping attacks

This attack takes advantage of the properties of the XOR operation and CBC mode of encryption to modify the portion of the plaintext that contains the user role to an "admin" role. The key is to XOR the chunks of ciphertext before the target chunk with a byte vector that can produce the desired ciphertext in place of the target chunk. In other words, we deliberately change bytes of the previous chunk of ciphertext to propagate the changes to the next chunk.

```rust
let prefix: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
let suffix: Vec<u8> = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();
let random_key: Vec<u8> = generate_random_bytevec(16usize);
let random_iv: Vec<u8> = generate_random_bytevec(16usize);

let encryptor = |plaintext_arg: &Vec<u8>| -> Vec<u8> {
    let mut plaintext: Vec<u8> = prefix.clone();
    plaintext.extend(&plaintext_arg.clone());
    plaintext.extend(&suffix);
    
    // Escape any ; and = characters in the plaintext
    let mut offset: usize = 0;
    for (count, byteval) in plaintext_arg.iter().enumerate() {
        if *byteval == b';' || *byteval == b'=' {
            plaintext.insert(prefix.len() + count + offset, b'"');
            plaintext.insert(prefix.len() + count + 2 + offset, b'"');
            offset += 2;
        }
    }

    aes_cbc_encrypt(&plaintext, &random_iv, &random_key)
};

let decryptor = |ciphertext_arg: &Vec<u8>| -> Vec<u8> {
    aes_cbc_decrypt(ciphertext_arg, &random_iv, &random_key)
};

let find_admin_info = |text: &String| -> bool {
    text.contains(";admin=true;")
};

let xor_bytearrays = |arr1: &Vec<u8>, arr2: &Vec<u8>| -> Vec<u8> {
    hextobytearray(&hex_xor(&bytearraytohex(&arr1), &bytearraytohex(&arr2)))
};

let plaintext: Vec<u8> = b"< put anything >DDDDDDDDDDDDDDDD".to_vec();
let ciphertext: Vec<u8> = encryptor(&plaintext);

// Inject malicious bytes into ciphertext
let mut ciphertext_chunks: Vec<Vec<u8>> = ciphertext.chunks(16usize).map(|x| x.to_vec()).collect();

// We exploit the fact that D ^ \x44 = \0
let bytes_to_insert: Vec<u8> = xor_bytearrays(&b"\x44".repeat(16).to_vec(), &b"fooba;admin=true".to_vec());
ciphertext_chunks[2] = xor_bytearrays(&bytes_to_insert, &ciphertext_chunks[2]);

// Decrypt
let decrypted_malbytes: Vec<u8> = decryptor(&ciphertext_chunks.into_iter().flatten().collect::<Vec<u8>>());

let decrypted_bytes: Vec<u8> = decryptor(&ciphertext);

// Check the decrypted byte chunks (for debugging)
println!();
println!("Actual decrypted bytes:");
format_chunks(&decrypted_bytes);

println!();
println!("Fake decrypted bytes:");
format_chunks(&decrypted_malbytes);
    
let mut clean_string = String::new();
for (count, chunk) in decrypted_malbytes.chunks(16).enumerate() {
    if count == 2 { continue; }
    match String::from_utf8(chunk.to_vec()) {
        Ok(sth) => clean_string.push_str(&sth),
        Err(_) => clean_string.push_str(&String::from_utf8(strip_pkcs7_padding(&chunk.to_vec()).unwrap()).unwrap()),
    }
}

println!();
println!("Decrypted mal-bytes: {}", &clean_string);
println!("Does plaintext contain admin information? : {}", find_admin_info(&clean_string));
```
