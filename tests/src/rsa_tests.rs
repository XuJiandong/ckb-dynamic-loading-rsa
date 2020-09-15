#![allow(unused_imports)]
#![allow(dead_code)]

use super::*;
use base64;
use ckb_system_scripts::BUNDLED_CELL;
use ckb_testtool::context::Context;
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};
use ckb_tool::ckb_hash::{blake2b_256, new_blake2b};
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
use rand::rngs::OsRng;
use rsa::{Hash, PaddingScheme, PublicKey, PublicKeyParts, RSAPrivateKey, RSAPublicKey};
use std::fs;

const MAX_CYCLES: u64 = 10_000_000;

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
    const SIGNATURE_SIZE: usize = 128;

    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();
    println!("tx_hash= {:02X?}", tx_hash.as_slice());

    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());
    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_SIZE, 0);
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
    println!("message = {:02X?}", message);

    // openssl
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(&message).unwrap();
    let signature = signer.sign_to_vec().unwrap();

    // verify it locally
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
    verifier.update(&message).unwrap();
    assert!(verifier.verify(&signature).unwrap());

    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(signature)).pack())
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

fn serialize_pub_key(public_key: &PKey<Public>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![];

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
    result
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

#[test]
fn test_rsa() {
    let (private_key, public_key) = generate_openssl_key();

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-rsa");
    let out_point = context.deploy_cell(contract_bin);

    let rsa_bin: Bytes = fs::read("../ckb-miscellaneous-scripts/build/rsa_sighash_all")
        .expect("load rsa")
        .into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    let pub_key_binary = serialize_pub_key(&public_key);
    // println!("public key size = {}, content = {:02X?}", pub_key_binary.len(), pub_key_binary);
    // prepare scripts
    let lock_script = context
        .build_script(&out_point, pub_key_binary.into())
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
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
