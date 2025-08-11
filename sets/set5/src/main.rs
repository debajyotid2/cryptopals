#![allow(dead_code)]

use bigintops::modinv_bytes;
use bytearrayconversion::{bytearraytohex, hextobytearray};
/// Set 5
///
///                    GNU AFFERO GENERAL PUBLIC LICENSE
///                       Version 3, 19 November 2007
///
///    Copyright (C) 2024 Debajyoti Debnath
///
///    This program is free software: you can redistribute it and/or modify
///    it under the terms of the GNU Affero General Public License as published
///    by the Free Software Foundation, either version 3 of the License, or
///    (at your option) any later version.
///
///    This program is distributed in the hope that it will be useful,
///    but WITHOUT ANY WARRANTY; without even the implied warranty of
///    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
///    GNU Affero General Public License for more details.
///
///    You should have received a copy of the GNU Affero General Public License
///    along with this program.  If not, see <https://www.gnu.org/licenses/>.
///
use num::{bigint::Sign, BigInt};
use rsaprotocol::RSA;
use set5::*;

fn challenge_33() {
    let p: Vec<u8> = hextobytearray(&"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".to_string());
    let g: u32 = 2;
    let a = b"You look lovely today.".to_vec();
    let b = b"Let's play guitar.".to_vec();

    let res = diffie_hellmann(&p, g, &a, &b);
    println!("Session key: {}", &bytearraytohex(&res.0));
}

fn challenge_34() {
    let a = b"You look lovely today.".to_vec();
    let b = b"Let's play guitar.".to_vec();
    let p: Vec<u8> = hextobytearray(&"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".to_string());
    let g: u32 = 2;

    // Simulate message exchange between two servers
    println!("Normal Diffie-Hellman exchange between two servers:");

    let mut bot_a = EchoBotA::new(&p[..], g, &a[..], b"You better lose yourself in the music.");
    let mut bot_b = EchoBotB::new(&b[..]);

    // A sends p, g, A to B
    let (p_bytes, g_bytes, a_power_bytes) = bot_a.step1();
    // B sends B to A
    let b_power_be_bytes = bot_b.step1(&p_bytes, &g_bytes[..], &a_power_bytes[..]);
    // A encrypts and sends message to B
    let a_enc = bot_a.step2(&b_power_be_bytes[..]);
    println!("{}", bytearraytohex(&a_enc));
    // B decrypts A's message, re-encrypts it and sends message to A
    let b_enc = bot_b.step2(a_enc);
    println!("{}", bytearraytohex(&b_enc));
    println!();

    // Simulate a man-in-the-middle attack on the above message exchange between two servers
    println!("Diffie-Hellman exchange with a MITM between two servers:");
    let mut bot_a = EchoBotA::new(&p[..], g, &a[..], b"You better lose yourself in the music.");
    let mut bot_b = EchoBotB::new(&b[..]);
    // A sends p, g, A to M
    let (p_bytes, g_bytes, _) = bot_a.step1();
    // M sends p, g, p to B
    // B sends B to M
    let _ = bot_b.step1(&p_bytes, &g_bytes[..], &p_bytes[..]);
    // M sends p to A
    // A encodes message and sends to M
    let a_enc = bot_a.step2(&p_bytes[..]);
    // M passes on message to B, but can decrypt the message easily
    println!("{}", bytearraytohex(&a_enc));
    mitm_intercept(a_enc.clone(), &vec![0u8][..]);
    // B encodes A's message and sends to M
    let b_enc = bot_b.step2(a_enc);
    // M passes on message to A, but can decrypt the message easily
    println!("{}", bytearraytohex(&b_enc));
}

fn challenge_35() {
    let a = b"You look lovely today.".to_vec();
    let b = b"Let's play guitar.".to_vec();
    let p: Vec<u8> = hextobytearray(&"ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff".to_string());
    let g: u32 = 2;

    // Simulate message exchange between two servers
    println!("Normal Diffie-Hellman exchange between two servers:");

    let mut bot_a = EchoBotA::new(&p[..], g, &a[..], b"You better lose yourself in the music.");
    let mut bot_b = EchoBotB::new(&b[..]);

    // A sends p, g, A to B
    let (p_bytes, g_bytes, a_power_bytes) = bot_a.step1();
    // B sends B to A
    let b_power_be_bytes = bot_b.step1(&p_bytes, &g_bytes[..], &a_power_bytes[..]);
    // A encrypts and sends message to B
    let a_enc = bot_a.step2(&b_power_be_bytes[..]);
    println!("{}", bytearraytohex(&a_enc));
    // B decrypts A's message, re-encrypts it and sends message to A
    let b_enc = bot_b.step2(a_enc);
    println!("{}", bytearraytohex(&b_enc));
    println!();

    // Simulate a man-in-the-middle attack on the above message exchange between two servers
    println!("Diffie-Hellman exchange with a MITM between two servers:");
    let mut bot_a = EchoBotA::new(&p[..], g, &a[..], b"You better lose yourself in the music.");
    let mut bot_b = EchoBotB::new(&b[..]);

    // Case 1: MITM sends g = 1
    println!("Case 1: MITM sends g = 1");
    // A sends p, g, A to M
    let (p_bytes, _, a_power_bytes) = bot_a.step1();
    // M sends p, 1, A to B
    // B sends B to M
    let b_power_bytes = bot_b.step1(&p_bytes, &vec![1u8][..], &a_power_bytes[..]);
    // M sends B to A
    // A encodes message and sends to M
    let a_enc = bot_a.step2(&b_power_bytes[..]);
    // M passes on message to B, but can decrypt the message easily
    println!("{}", bytearraytohex(&a_enc));
    // s = 1 since 1 ^ something % p = 1
    mitm_intercept(a_enc.clone(), &vec![1u8][..]);
    // B encodes A's message and sends to M
    let b_enc = bot_b.step2(a_enc);
    // M passes on message to A, but can decrypt the message easily
    println!("{}", bytearraytohex(&b_enc));

    // Case 2: MITM sends g = p
    println!("Case 2: MITM sends g = p");
    // A sends p, g, A to M
    let (p_bytes, _, a_power_bytes) = bot_a.step1();
    // M sends p, p, A to B
    // B sends B to M
    let b_power_bytes = bot_b.step1(&p_bytes, &p_bytes, &a_power_bytes[..]);
    // M sends p to A
    // A encodes message and sends to M
    let a_enc = bot_a.step2(&b_power_bytes[..]);
    // M passes on message to B, but can decrypt the message easily
    println!("{}", bytearraytohex(&a_enc));
    // s = 0 since p ^ something % p = 0
    mitm_intercept(a_enc.clone(), &vec![0u8][..]);
    // B encodes A's message and sends to M
    let b_enc = bot_b.step2(a_enc);
    // M passes on message to A, but can decrypt the message easily
    println!("{}", bytearraytohex(&b_enc));

    // Case 3: MITM sends g = p - 1
    let p_minus_1_bytes: Vec<u8> = (BigInt::from_bytes_be(Sign::Plus, &p[..]) - 1i32)
        .to_bytes_be()
        .1;
    println!("Case 3: MITM sends g = p - 1");
    // A sends p, g, A to M
    let (p_bytes, _, a_power_bytes) = bot_a.step1();
    // M sends p, p - 1, A to B
    // B sends B to M
    let b_power_bytes = bot_b.step1(&p_bytes, &p_minus_1_bytes, &a_power_bytes[..]);
    // M sends p to A
    // A encodes message and sends to M
    let a_enc = bot_a.step2(&b_power_bytes[..]);
    // M passes on message to B, but can decrypt the message easily
    println!("{}", bytearraytohex(&a_enc));
    // s = 1 since (p - 1) ^ something % p = 1 (Use binomial theorem on (p - 1) ^ n)
    mitm_intercept(a_enc.clone(), &vec![1u8][..]);
    // B encodes A's message and sends to M
    let b_enc = bot_b.step2(a_enc);
    // M passes on message to A, but can decrypt the message easily
    println!("{}", bytearraytohex(&b_enc));
}

fn challenge_36() {
    let n_prime: Vec<u8> = hextobytearray(&"00c037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3d".to_string());
    let g: Vec<u8> = vec![2u8];
    let k: Vec<u8> = vec![3u8];
    let email: Vec<u8> = b"tryandhackme@example.com".to_vec();
    let password: Vec<u8> = b"myverysecurepassword".to_vec();
    let a = b"You look lovely today.".to_vec();
    let b = b"Let's play guitar.".to_vec();

    // Create SRP server and client
    let mut server = SRPServer::new(&b, &n_prime, &g, &k, &email, &password);
    let mut client = SRPClient::new(&a, &n_prime, &g, &k, &email, &password);

    let (email_data, a_power) = client.step1();
    let (salt, b_power) = server.step1(&email_data[..], &a_power[..]);
    let hmac = client.step2(&salt[..], &b_power[..]);
    match server.step2(hmac) {
        Ok(_) => println!("HMAC verified successfully."),
        Err(Error::HMACMismatch(val1, val2)) => {
            eprintln!("HMAC mismatch. Expected {}, got {}", val1, val2);
            println!("Server: ");
            server.print();
            println!("Client: ");
            client.print();
        }
    };
}

fn challenge_37() {
    let n_prime: Vec<u8> = hextobytearray(&"00c037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3d".to_string());
    let g: Vec<u8> = vec![2u8];
    let k: Vec<u8> = vec![3u8];
    let email: Vec<u8> = b"tryandhackme@example.com".to_vec();
    let password: Vec<u8> = b"myverysecurepassword".to_vec();
    let a = b"You look lovely today.".to_vec();
    let b = b"Let's play guitar.".to_vec();

    let emulate_login =
        |mut server: SRPServer, mut malclient: MalSRPClient, a_power_bytes: &Vec<u8>| {
            let (email_data, _) = malclient.step1(&a_power_bytes[..]);
            let (salt, _) = server.step1(&email_data[..], &a_power_bytes[..]);
            let hmac = malclient.step2(&salt[..]);
            match server.step2(hmac) {
                Ok(_) => println!("HMAC verified successfully."),
                Err(Error::HMACMismatch(val1, val2)) => {
                    eprintln!("HMAC mismatch. Expected {}, got {}", val1, val2);
                    println!("Server: ");
                    server.print();
                    println!("Client: ");
                    malclient.print();
                }
            };
        };

    // Case 1: Attack with actual client replaced by a fake client
    // sending '0' as a and no password
    println!("Case 1: Attack with client sending '0' as a and no password");
    let server = SRPServer::new(&b, &n_prime, &g, &k, &email, &password);
    let malclient = MalSRPClient::new(&a, &n_prime, &g, &k, &email, &vec![]);
    emulate_login(server, malclient, &vec![0u8]);

    // Case 2: Attack with client sending multiples of N as a and no password
    // (2a): a = N
    println!("Case 2a: Attack with client sending N as a and no password");
    let server = SRPServer::new(&b, &n_prime, &g, &k, &email, &password);
    let malclient = MalSRPClient::new(&a, &n_prime, &g, &k, &email, &vec![]);
    emulate_login(server, malclient, &n_prime);

    // (2b): a = k*N where k is a natural number
    println!("Case 2b: Attack with client sending k * N (where k is a natural number) as a and no password");
    let server = SRPServer::new(&b, &n_prime, &g, &k, &email, &password);
    let malclient = MalSRPClient::new(&a, &n_prime, &g, &k, &email, &vec![]);
    emulate_login(
        server,
        malclient,
        &(BigInt::from_bytes_be(Sign::Plus, &n_prime[..]) * 21u32)
            .to_bytes_be()
            .1,
    );
}

fn challenge_38() {
    let n_prime: Vec<u8> = hextobytearray(&"00c037c37588b4329887e61c2da3324b1ba4b81a63f9748fed2d8a410c2fc21b1232f0d3bfa024276cfd88448197aae486a63bfca7b8bf7754dfb327c7201f6fd17fd7fd74158bd31ce772c9f5f8ab584548a99a759b5a2c0532162b7b6218e8f142bce2c30d7784689a483e095e701618437913a8c39c3d".to_string());
    let g: Vec<u8> = vec![2u8];
    let email: Vec<u8> = b"tryandhackme@example.com".to_vec();
    let password: Vec<u8> = b"myverysecurepassword".to_vec();
    let a = b"You look lovely today.".to_vec();
    let b = b"Let's play guitar.".to_vec();

    let emulate_login = |mut server: SimpleSRPServer, mut client: SimpleSRPClient| {
        let (email_data, a_power) = client.step1();
        let (salt, b_power, u_h_bytes) = server.step1(&email_data, &a_power);
        let hmac = client.step2(&salt, &b_power, &u_h_bytes);
        match server.step2(hmac) {
            Ok(_) => println!("HMAC verified successfully."),
            Err(Error::HMACMismatch(val1, val2)) => {
                eprintln!("HMAC mismatch. Expected {}, got {}", val1, val2);
                println!("Server: ");
                server.print();
                println!("Client: ");
                client.print();
            }
        };
    };

    // Normal login validation
    println!("Normal login validation:");
    let server = SimpleSRPServer::new(&b, &n_prime, &g, &email, &password);
    let client = SimpleSRPClient::new(&a, &n_prime, &g, &email, &password);
    emulate_login(server, client);

    // MITM offline dictionary attack
    // NOTE: It is assumed that the attacker has control of the server and knows
    // b, n_prime and g. That's why the attack is "offline".
    println!("MITM offline dictionary attack:");
    let mut client = SimpleSRPClient::new(&a, &n_prime, &g, &email, &password);
    let mut mitm_server = MITMSimpleSRPServer::new(&b, &n_prime, &g);

    let (email_data, a_power) = client.step1();
    let (salt, b_power, u_h_bytes) = mitm_server.step1(&email_data, &a_power);
    let hmac = client.step2(&salt, &b_power, &u_h_bytes);

    let mut password_oracle = |guess: &[u8]| -> bool {
        match mitm_server.step2(hmac.clone(), guess) {
            Ok(_) => {
                println!("HMAC verified successfully.");
                true
            }
            Err(Error::HMACMismatch(val1, val2)) => {
                eprintln!("HMAC mismatch. Expected {}, got {}", val1, val2);
                false
            }
        }
    };

    // Try incorrect guess
    println!("Try incorrect guess:");
    let guess = b"lolwut";
    password_oracle(guess);

    // Try correct guess
    println!("Try correct guess:");
    let guess = &password;
    password_oracle(guess);

    // This enables the password to be guessed by something like a dictionary attack
    // where the attacker has a dictionary of passwords and their hashes/ HMACs
    // available. These dictionaries usually become available through password
    // leaks.
    // See: https://www.alpinesecurity.com/blog/offline-password-cracking-the-attack-and-the-best-defense-against-it/
}

fn challenge_39() {
    let message = b"The math cares not how stupidly you feed it strings.";
    let rsa = RSA::new(&2048u16);
    let encrypted = rsa.encrypt(message);
    let decrypted = rsa.decrypt(&encrypted);
    println!("Message: {:?}", bytearraytohex(&message.to_vec()));
    println!("Encrypted: {}", bytearraytohex(&encrypted));
    println!("Decrypted: {:?}", bytearraytohex(&decrypted));
}

fn challenge_40() {
    let msg = b"The math cares not how stupidly you feed it strings.";

    let bigint = |be_bytes: &[u8]| -> BigInt { BigInt::from_bytes_be(Sign::Plus, be_bytes) };

    let rsa_encrypt = |message: &[u8]| -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let rsa = RSA::new(&2048u16);
        let encrypted = rsa.encrypt(message);
        let (e, n) = rsa.get_public_key();
        (e, n, encrypted)
    };

    let (_, n0, c0) = rsa_encrypt(&msg.to_vec());
    let (_, n1, c1) = rsa_encrypt(&msg.to_vec());
    let (_, n2, c2) = rsa_encrypt(&msg.to_vec());

    let m_s_0 = bigint(&n1) * bigint(&n2);
    let m_s_1 = bigint(&n0) * bigint(&n2);
    let m_s_2 = bigint(&n0) * bigint(&n1);
    let n_012 = bigint(&n0) * bigint(&n1) * bigint(&n2);

    let result: BigInt =
        (bigint(&c0) * m_s_0.clone() * modinv_bytes(&m_s_0.to_bytes_be().1, &n0).unwrap()
            + bigint(&c1) * m_s_1.clone() * modinv_bytes(&m_s_1.to_bytes_be().1, &n1).unwrap()
            + bigint(&c2) * m_s_2.clone() * modinv_bytes(&m_s_2.to_bytes_be().1, &n2).unwrap())
            % n_012;
    let retrieved_message: Vec<u8> = result.cbrt().to_bytes_be().1;

    assert_eq!(&retrieved_message, &msg);

    println!("Original: {}", bytearraytohex(&msg.to_vec()));
    println!("Decrypted: {}", bytearraytohex(&retrieved_message.to_vec()));
}

fn main() {
    println!();
    println!("Running challenge 33 ...");
    println!();
    challenge_33();

    println!();
    println!("Running challenge 34 ...");
    println!();
    challenge_34();

    println!();
    println!("Running challenge 35 ...");
    println!();
    challenge_35();

    println!();
    println!("Running challenge 36 ...");
    println!();
    challenge_36();

    println!();
    println!("Running challenge 37 ...");
    println!();
    challenge_37();

    println!();
    println!("Running challenge 38 ...");
    println!();
    challenge_38();

    println!();
    println!("Running challenge 39 ...");
    println!();
    challenge_39();

    println!();
    println!("Running challenge 40 ...");
    println!();
    challenge_40();
}
