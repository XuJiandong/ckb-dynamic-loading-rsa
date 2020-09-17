#![no_std]
#![no_main]
#![feature(lang_items)]
#![feature(alloc_error_handler)]
#![feature(panic_info_message)]

mod code_hashes;
mod rsa;

// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
use alloc::vec::Vec;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
// use alloc::{vec, vec::Vec};

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_types::{bytes::Bytes, prelude::*},
    debug, default_alloc, entry,
    error::SysError,
    high_level::load_script,
    dynamic_loading::CKBDLContext,
};

use crate::rsa::RsaLib;

entry!(entry);
default_alloc!();

/// Program entry
fn entry() -> i8 {
    // Call main function and return error code
    match main() {
        Ok(_) => 0,
        Err(err) => err as i8,
    }
}

/// Error
#[repr(i8)]
enum Error {
    IndexOutOfBound = 1,
    ItemMissing,
    LengthNotEnough,
    Encoding,
    // Add customized errors here...
    Rsa,
}

impl From<SysError> for Error {
    fn from(err: SysError) -> Self {
        use SysError::*;
        match err {
            IndexOutOfBound => Self::IndexOutOfBound,
            ItemMissing => Self::ItemMissing,
            LengthNotEnough(_) => Self::LengthNotEnough,
            Encoding => Self::Encoding,
            Unknown(err_code) => panic!("unexpected sys error {}", err_code),
        }
    }
}

fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();

    if args.len() != 20 {
        return Err(Error::Encoding);
    }
    let args: Vec<u8> = args.into();

    let mut pubkey_hash = [0u8; 20];
    pubkey_hash.copy_from_slice(&args);

    // create a DL context with 128K buffer size
    let mut context = CKBDLContext::<[u8; 128 * 1024]>::new();

    let lib = RsaLib::load(&mut context);
    lib.validate_rsa_sighash_all(&pubkey_hash).map_err(|err_code| {
        debug!("Rsa error {}", err_code);
        Error::Rsa
    })?;

    if !pubkey_hash.eq(&args.as_slice()) {
        debug!("Rsa public key hashes are different: {:?} {:?}", pubkey_hash, args);
    }

    Ok(())
}
