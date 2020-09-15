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
