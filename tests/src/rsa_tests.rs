#![allow(unused_imports)]
#![allow(dead_code)]

use super::*;
use ckb_testtool::context::Context;
use ckb_tool::ckb_types::{bytes::Bytes, core::{TransactionBuilder, TransactionView}, packed::{self, *}, prelude::*};
use ckb_system_scripts::BUNDLED_CELL;
use ckb_tool::ckb_crypto::secp::{Generator, Privkey};
use ckb_tool::ckb_hash::{blake2b_256, new_blake2b};
use std::fs;
use rsa::{PublicKey, RSAPrivateKey, RSAPublicKey, PaddingScheme, PublicKeyParts, Hash};
use rand::rngs::OsRng;


const MAX_CYCLES: u64 = 10_000_000;

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(tx: TransactionView, key: &RSAPrivateKey) -> TransactionView {
    const SIGNATURE_SIZE: usize = 128;

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

    let sig = key.sign(PaddingScheme::new_pkcs1v15_sign(Some(Hash::SHA2_256)), &message).expect("sign");
    signed_witnesses.push(
        witness
        .as_builder()
        .lock(Some(Bytes::from(sig)).pack())
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


fn serialize_pub_key(pub_key : RSAPublicKey) -> Vec<u8> {
    let mut result : Vec<u8> = vec![];

    let mut e = pub_key.e().to_bytes_le();
    while e.len() < 4 {
        e.push(0);
    }
//    println!("e = {:?}", e);
    let mut n = pub_key.n().to_bytes_le();
    while n.len() < 128 {
        n.push(0);
    }
//    println!("n = {:?}", n);
    result.append(&mut e);
    result.append(&mut n);
//    println!("result = {:?}", result);
    result
}


#[test]
fn test_rsa() {
    let mut rng = OsRng;
    let bits = 1024;
    let priv_key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RSAPublicKey::from(&priv_key);


    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-dynamic-loading-rsa");
    let out_point = context.deploy_cell(contract_bin);

    let rsa_bin: Bytes = fs::read("../ckb-miscellaneous-scripts/build/rsa_sighash_all").expect("load rsa").into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder()
        .out_point(rsa_out_point)
        .build();

    let pub_key_binary = serialize_pub_key(pub_key);
    // prepare scripts
    let lock_script = context
        .build_script(&out_point,pub_key_binary.into())
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
    let tx = sign_tx(tx, &priv_key);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}


