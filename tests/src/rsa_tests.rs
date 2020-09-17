#![allow(unused_imports)]
#![allow(dead_code)]

use super::*;
use ckb_testtool::context::Context;
use ckb_tool::ckb_hash::{new_blake2b, blake2b_256};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use std::fs;

const MAX_CYCLES: u64 = 40_000_000;


fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(
    tx: TransactionView,
    private_key: &PKey<Private>,
    public_key: &PKey<Public>,
) -> TransactionView {
    // see "signature (in witness) memory layout"
    let signature_size = (private_key.bits()/8*2+8) as usize;

    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();

    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(signature_size, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);

    // openssl
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(&message).unwrap();
    let rsa_signature = signer.sign_to_vec().unwrap();

    // see "signature (in witness) memory layout"
    let (mut rsa_info, _) = calculate_pub_key_hash(public_key);
    rsa_info.extend_from_slice(&rsa_signature);

    // verify it locally
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
    verifier.update(&message).unwrap();
    assert!(verifier.verify(&rsa_signature).unwrap());

    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(rsa_info)).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

/** signature (in witness) memory layout
 * This structure contains the following information:
 * 1) RSA Key Size
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
+---------+----------+---------------------------------+------------------------------------+
| key_size|   E      |  N (key_size/8 bytes)           | RSA Signature (key_size/8 bytes)   |
+--------------------+---------------------------------+------------------------------------+
The key_size, N both occupy 4 bytes, in little endian (uint32_t).
So the total length in byte is: 4 + 4 + key_size/8 + key_size/8.

The public key hash is calculated : blake2b(key_size + E + N), dropping RSA signature part.
*/
fn calculate_pub_key_hash(public_key: &PKey<Public>) -> (Vec<u8>, Vec<u8>) {
    let mut result: Vec<u8> = vec![];

    let key_size = public_key.bits() as u32;
    let key_size_buff = key_size.to_le_bytes();
    result.extend_from_slice(&key_size_buff);

    let rsa_public_key = public_key.rsa().unwrap();

    let mut e = rsa_public_key.e().to_vec();
    let mut n = rsa_public_key.n().to_vec();
    e.reverse();
    n.reverse();

    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < 128 {
        n.push(0);
    }

    result.append(&mut e);
    result.append(&mut n);

    let h = blake160(&result).into();
    (result, h)
}

fn generate_openssl_key() -> (PKey<Private>, PKey<Public>) {
    // openssl genrsa -out tiny_key.pem 1024
    let file_content = r#"
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC19jgtjVSBP3UA15/ZyVpFuxK9m5rEYEe4LBmayKIO8c9AlExl
f2pbUXYigteNY75Nx0exKYFoZccwm2zqod2BAfO0kyUxuQqA3wvV7wlN2lvmBCzG
M5d7Q+uQ8byhSrYHnaNHMsT7GQB/o6ihQMIBu+wYzz/A8kNgSP4x/+GEbQIDAQAB
AoGBAKxssvNHV2paTW8M5GaljKtDCBEwIEoxygRVlbW8pQRwUyoo3PPY91mtKbqu
Lb/HYo+lZOQWJpBc0ZHX1i/ITnHVoqHIsSvrE3p1/ywucB0DX+a+l5KzekZ7fuq0
Yh3wD+Xmjic75m1UeSxGkMxiwbtsb7Ubf4TxEgOA562rmAVpAkEA4HoyEUSngpao
sIKcIYSZGESVxigmJnluYWf6yH9VaGD5NM+dr9SN4At8F++H2jUnxRKzVV/+M0ir
688m4fXBTwJBAM+DnrTQ4Y3ONMLuKZiBSXENVkzIXF4oJEq6G0vSXSnx1XiZKxTz
X4Qz28zVbGQ9wtzKuzbC4OCSXBpTAOnGl4MCQHqnKe43hhObgGaZpvfFfOU+rFuO
mnHRTdeZOfUNZjxXKDOL8YweZrrxa4ekkKVQ//71XdmbTsj0v0Nkd8llP48CQCQK
IegZVvL/2x33qvW3jn+550ESkygvJI5t4Au9Dz0XqRF22Iqc8fvN3eCnOFn4d/1M
oFMUaWXXRXO08rWnLe0CQHH38XWaJUkw+Ozoxsq651qWkhm7k6O4Elb4nO3gkiby
fTEpXpRFyDvyXVYcyXuL6w8FMV5ixSJ13IXIUv2i45Y=
-----END RSA PRIVATE KEY-----"#;
    let rsa = Rsa::private_key_from_pem(file_content.as_bytes()).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();
    let public_key_pem: Vec<u8> = private_key.public_key_to_pem().unwrap();
    let public_key = PKey::public_key_from_pem(&public_key_pem).unwrap();
    (private_key, public_key)
}

fn generate_random_key(bits: u32) -> (PKey<Private>, PKey<Public>) {
    assert!(bits == 1024 || bits == 2048 || bits == 4096);
    let rsa = Rsa::generate(bits).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let public_key_pem: Vec<u8> = private_key.public_key_to_pem().unwrap();
    let public_key = PKey::public_key_from_pem(&public_key_pem).unwrap();
    (private_key, public_key)
}

#[test]
fn test_rsa_fixed_1024() {
    let (private_key, public_key) = generate_openssl_key();
    test_rsa(private_key, public_key);
}

#[test]
fn test_rsa_random_1024() {
    let (private_key, public_key) = generate_random_key(1024);
    test_rsa(private_key, public_key);
}

#[test]
fn test_rsa_random_2048() {
    let (private_key, public_key) = generate_random_key(2048);
    test_rsa(private_key, public_key);
}

#[test]
fn test_rsa_random_4096() {
    let (private_key, public_key) = generate_random_key(4096);
    test_rsa(private_key, public_key);
}


fn test_rsa(private_key: PKey<Private> , public_key: PKey<Public> ) {
    let mut result = [0; 3];
    let mut blake2b = new_blake2b();
    blake2b.update(&[0; 32]);
    blake2b.finalize(&mut result);


    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-rsa");
    let out_point = context.deploy_cell(contract_bin);

    let rsa_bin: Bytes = fs::read("../ckb-miscellaneous-scripts/build/rsa_sighash_all")
        .expect("load rsa")
        .into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    let (_public_key_binary, public_key_hash) = calculate_pub_key_hash(&public_key);
    // prepare scripts
    let lock_script = context
        .build_script(&out_point, public_key_hash.into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(rsa_dep)
        .build();
    let tx = context.complete_tx(tx);

    // sign
    let tx = sign_tx(tx, &private_key, &public_key);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES).expect("pass verification");
    println!("consume cycles: {}", cycles);
}
