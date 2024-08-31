# Set 4

[Challenge link in the Cryptopals website](https://cryptopals.com/sets/4)

- [x] [Break random access read-write AES CTR](#break-random-access-read-write-aes-ctr)
- [x] [CTR bitflipping](#ctr-bitflipping)
- [x] [Recover the key from CBC with IV equals Key](#recover-the-key-from-cbc-with-iv-equals-key)
- [x] [Implement a SHA-1 keyed MAC](#implement-a-sha-1-keyed-mac)
- [x] [Break a SHA-1 keyed MAC using length extension](#break-a-sha-1-keyed-mac-using-length-extension)
- [x] [Break an MD4 keyed MAC using length extension](#break-an-md4-keyed-mac-using-length-extension)
- [x] [Implement and break HMAC-SHA1 with an artificial timing leak](#implement-and-break-hmac-sha1-with-an-artificial-timing-leak)
- [x] [Break HMAC-SHA1 with a slightly less artificial timing leak](#break-hmac-sha1-with-a-slightly-less-artificial-timing-leak)

## Break random access read-write AES CTR

The AES CTR encryption mode allows modifications to the ciphertext at any position and substitution with an alternative plaintext. [`edit_ctr_ciphertext()`](./src/lib.rs) serves this purpose by taking an offset and the replacement text as arguments alongside the original ciphertext. 

If somehow an attacker has access to an API that exposes this function, without knowledge of the key, they can replace the ciphertext with null bytes to recover the keystream (since the encryption is simply a XOR operation with the keystream). Then by XORing the keystream against the ciphertext, the plaintext can be easily recovered.

```rust
let plaintext: Vec<u8> = base64tobytearray(&fs::read_to_string("25.txt")
                                                    .expect("File 25.txt not found.")
                                                    .replace("\n", ""));
let key = generate_random_bytevec(16);
let ciphertext = aes_ctr_decrypt(&plaintext, &key, &b"\x00".repeat(8).to_vec());

let editing_api_call = |ciphertext_arg: &Vec<u8>, offset: usize, newtext: &Vec<u8>| -> Vec<u8> {
    edit_ctr_ciphertext(ciphertext_arg, &key, offset, newtext).unwrap_or(Vec::<u8>::new())
};

// Recover original plaintext
let recovered_keystream = editing_api_call(&ciphertext, 0, &b"\x00".repeat(ciphertext.len()).to_vec());
let recovered_plaintext: Vec<u8> = zip(ciphertext.iter(), recovered_keystream.iter())
                            .map(|(a, b)| a ^ b)
                            .collect();
assert_eq!(recovered_plaintext, plaintext);
```

## CTR bitflipping

The main difference between the approach of the CBC bitflipping exercise from [Set 2](../set2/README.md) and the CTR bitflipping exercise is that we ignore the first blocksize/2 bytes when modifying the bytes of the ciphertext that would ultimately propagate to the target part of the plaintext. We do this since these bytes contain the index for that plaintext block and so are not being targeted for modification.

We XOR a portion of the plaintext containing `;admin=true;` against the block previous to the one being targeted. The mechanism of propagation of this modification to the target block is the same as in the CBC bitflipping attack.

```rust
let enc = get_ctr_encryptor();
let prefix: Vec<u8> = b"comment1=cooking%20MCs;userdata=".to_vec();
let suffix: Vec<u8> = b";comment2=%20like%20a%20pound%20of%20bacon".to_vec();

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

    enc(&plaintext)
};

let find_admin_info = |text: &String| -> bool {
    text.contains(";admin=true;")
};

// Generate ciphertext
let plaintext: Vec<u8> = b"AAAAAAAAAAAAAAAA".to_vec();
let ciphertext: Vec<u8> = encryptor(&plaintext);

// Inject "malicious" bytes into ciphertext
let target_keystream: Vec<u8> = zip(plaintext.iter(), ciphertext.chunks(16).nth(2).unwrap().iter())
                                        .map(|(a, b)| a ^ b)
                                        .collect();
let mal_bytes: Vec<u8> = zip(target_keystream.iter(), b"AAAA;admin=true;".iter())
                                .map(|(a, b)| a ^ b)
                                .collect();
let mut mal_ciphertext = ciphertext.clone();
mal_ciphertext[32..48].copy_from_slice(&mal_bytes[..]);

// Test for admin info
let decrypted_str: String = String::from_utf8(enc(&mal_ciphertext)).unwrap();

println!("Does string contain an admin profile? : {}", find_admin_info(&decrypted_str));
```

## Recover the key from CBC with IV equals Key

If the attacker acts as a man-in-the-middle and intercepts a CBC encrypted message, they can modify a three-block long ciphertext `C1, C2, C3` to `C1, 0, C1` and recover the key by XOR'ing the decrypted plaintext of the modified ciphertext. This is possible because the initialization vector (IV) is equal to the key, and using the properties of XOR,

`P1' XOR P3' = (C1 XOR IV XOR KEY) XOR (C1 XOR KEY) = IV `

```rust
let random_key: Vec<u8> = generate_random_bytevec(16);

let encryptor = |plaintext: &Vec<u8>| -> Vec<u8> {
    if let Err(_) = check_ascii_chars(plaintext) {
        panic!("Invalid ASCII characters in plaintext.");
    };
    
    aes_cbc_encrypt(plaintext, &random_key, &random_key)
};

let decryptor = |ciphertext_arg: &Vec<u8>| -> Vec<u8> {
    let decrypted = aes_cbc_decrypt(ciphertext_arg, &random_key, &random_key);
    match check_ascii_chars(&decrypted) {
        Ok(sth) => sth,
        Err(set4::Error::InvalidASCIIChars(val)) => {
            eprintln!("Invalid ASCII characters found.");
            val
        },
        _ => panic!("Decryption error.")
    }
};

let xor_bytearrays = |arr1: &Vec<u8>, arr2: &Vec<u8>| -> Vec<u8> {
    zip(arr1.iter(), arr2.iter()).map(|(a, b)| *a ^ *b).collect()
};

// Generate ciphertext
let plaintext: Vec<u8> = b"fooingaroundwithDDDDDDDDDDDDDDDDbarbazbaebagbatb".to_vec();
let ciphertext: Vec<u8> = encryptor(&plaintext);

// Inject "malicious" bytes into ciphertext
let mut mal_ciphertext: Vec<u8> = ciphertext.clone();
mal_ciphertext[(16 * 0)..(16 * 1)].copy_from_slice(ciphertext.chunks(16).nth(0).unwrap());
mal_ciphertext[(16 * 1)..(16 * 2)].copy_from_slice(&b"\x00".repeat(16).to_vec()[..]);
mal_ciphertext[(16 * 2)..(16 * 3)].copy_from_slice(ciphertext.chunks(16).nth(0).unwrap());

// Decrypt malicious bytes
let decrypted: Vec<u8> = decryptor(&mal_ciphertext);

// Recover key by XOR-ing first and third chunk. This works because
// the IV is the same as the key, but it won't if the attacker does
// not have control over the first chunk.
let recovered_key: Vec<u8> = xor_bytearrays(&decrypted.chunks(16).nth(0).unwrap().to_vec(), &decrypted.chunks(16).nth(2).unwrap().to_vec());
assert_eq!(recovered_key, random_key);
```

## Implement a SHA-1 keyed MAC

For this challenge I implemented the SHA1 algorithm from its [pseudocode](https://en.wikipedia.org/wiki/SHA-1#SHA-1_pseudocode) in pure Rust. Generating the SHA1 MAC of a message involves calculating the MD padding of the message using SHA1, appending it to the message and then generating the hash of the padded message using SHA1. ([`sha1_hash()`](../../sha1hash/src/lib.rs))

```rust
let mut message: BitVec = message_arg.clone();

// Preprocessing
message.extend(compute_md_padding_sha1(message_arg.len()).get_data().clone());

// Processing
let hh: BitVec = sha1_hash(&message, &H0, &H1, &H2, &H3, &H4);

bytearraytohex(&hh.to_bytearray())
```

## Break a SHA-1 keyed MAC using length extension

The SHA1 outputs a MAC that can be used as the starting argument for a new SHA1 algorithm. This is the basis of the length extension attack on a SHA1 keyed MAC. 

To do this we first generate a new hash using the original MAC of the message. The original MAC is broken into the 5 "registers" that SHA1 uses and input into the SHA1 algorithm. 

Then padding of the length of the original message and the key combined is generated and appended to the new MAC, followed by the new message.

When a SHA1 keyed MAC is generated for this new message, the MAC is the same as the original MAC even though the plaintext is different, demonstrating the feasibility of this attack.

```rust
let my_message = BitVec::new_from_bytearray(&b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec());
let my_custom_message = BitVec::new_from_bytearray(&b";admin=true".to_vec());

let generate_mac = get_secret_prefix_sha1_mac_generator();

let key_len: usize = 16 * 8;
let initial_mac = generate_mac(&my_message.to_bytearray());
let new_mac = sha1_length_extension_attack(&my_message, &initial_mac, &my_custom_message, key_len);
println!("Initial MAC: {}\nNew MAC: {}", &initial_mac, &new_mac);

let mut message_to_forge: BitVec = my_message.clone();
let padding: BitVec = compute_md_padding_sha1(my_message.len() + key_len);
message_to_forge.extend(padding.get_data().clone());
message_to_forge.extend(my_custom_message.get_data().clone());

assert_eq!(generate_mac(&message_to_forge.to_bytearray()), new_mac);
```

## Break an MD4 keyed MAC using length extension

Similar to the SHA1 attack, the mechanism for attacking MD4-keyed MACs also involves the same steps of generating a new MAC using the original MAC as the starting point, appending a padding of length equal to the sum of the lengths of the key and the message and the new message, and finally generating a new MD4 keyed MAC for the composite message. For this I implemented the MD4 algorithm from its pseudocode in [RFC1320](https://datatracker.ietf.org/doc/html/rfc1320). (Ref: [`md4hash`](../../md4hash/src/lib.rs))

```rust
let my_message = BitVec::new_from_bytearray(&b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon".to_vec());
let my_custom_message = BitVec::new_from_bytearray(&b";admin=true".to_vec());
let generate_mac = get_secret_prefix_md4_mac_generator();

let key_len: usize = 16 * 8;
let initial_mac = generate_mac(&my_message.to_bytearray());
let new_mac = md4_length_extension_attack(&my_message, &initial_mac, &my_custom_message, key_len);
println!("Initial MAC: {}\nNew MAC: {}", &initial_mac, &new_mac);

let mut message_to_forge: BitVec = my_message.clone();
let padding: BitVec = compute_md_padding_md4(my_message.len() + key_len);
message_to_forge.extend(padding.get_data().clone());
message_to_forge.extend(my_custom_message.get_data().clone());

assert_eq!(generate_mac(&message_to_forge.to_bytearray()), new_mac);
```

## Implement and break HMAC-SHA1 with an artificial timing leak

For this challenge, `main.rs` acts as the server while `client.rs` is the client. The server validates requests with the guessed signature to be correct or incorrect based on an `insecure_compare()` function, which compares the signature in the request with the true signature byte-by-byte. With the artificial timing delay for each comparison, the client can easily guess the MAC by brute-forcing through all possible combinations in each byte position and then taking the guessed byte that has the greatest delay in the response from the server (since greater the delay, more the number of successful comparisons).

### Instructions for running

To start the server: `cargo run --bin set4`.
To start the client: `cargo run --bin client`.

```rust
async fn validate_signature(Query(fileinfo): Query<FileInfo>) -> impl IntoResponse {
    let key = b"key".to_vec();
    let actual: String = hmac_sha1(&fileinfo.file.as_bytes().to_vec(), &key);
    if insecure_compare(&hextobytearray(&fileinfo.signature), &hextobytearray(&actual)) {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("Signature is valid."))
            .unwrap()
    } else {
        Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Signature is invalid."))
            .unwrap()
    } 
}

async fn handle_default() -> impl IntoResponse {
    Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Page not found"))
            .unwrap()
}

let app = Router::new()
            .route("/:test", get(validate_signature))
            .route("/", get(handle_default));
let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

println!("Listening on {} ...", &addr);
axum_server::bind(addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
```

## Break HMAC-SHA1 with a slightly less artificial timing leak

The same set up as before is used, so there is no new code written for this. For a successful guess, the number of retries is increased as the MAC becomes harder to guess for smaller delays in each comparison.
