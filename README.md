# ckb-dynamic-loading-rsa

A contract that do RSA verification via dynamic loading.

### Pre-requirement

* `ckb-std > 0.6.2` which supports dynamic loading and a bug fix
* [validate_rsa_sighash_all](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/master/c/rsa_sighash_all.c) which supports loaded as a shared library.

### Build contracts:

#### 1. init submodules

``` sh
git submodule init && git submodule update -r
```

#### 2. build the shared binary `rsa_sighash_all`

``` sh
cd ckb-miscellaneous-scripts && make install-tools && make all-via-docker
```

#### 3. build contract

``` sh
capsule build
```

### Run tests:

``` sh
capsule test
```

### Implementation Details
It follows the same protocol as [validate_secp256k1_blake2b_sighash_all](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/f072d7d2eef020829fb37a379dc282f8641e8663/c/secp256k1_blake2b_sighash_all_dual.c#L156).
The main entry for C is [here](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/f072d7d2eef020829fb37a379dc282f8641e8663/c/rsa_sighash_all.c#L292).
You can use this project to test the shared library (rsa_sighash_all). Some other notices:
* The script args is the blake160 hash of public key.
* The witness includes public key and RSA signature, find more information: [RsaInfo](https://github.com/nervosnetwork/ckb-miscellaneous-scripts/blob/f072d7d2eef020829fb37a379dc282f8641e8663/c/rsa_sighash_all.h#L8-L46)
* It can support variable key size, including 1024-bits, 2048-bits and 4096-bits. It's based on key size in witness.
