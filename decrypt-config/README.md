# Crack Phicomm K3 Config File

** Only tested on `K3-B1-V22.1.23.149` **

## Dependency

- OpenSSL 1.0+
- C Compiler like *GCC*
- bcmcrypto (Crypto library from Broadcom)

## How to compile

`gcc phi_aes.c -O3 -lcrypto -static -o phicomm_config_dec`

## How to use

- Compile it
- Put the `config.dat` file at the same directory with compiled program.
- Run the program, and `config.dat.decrypted` is the decrypted config file.

## Disclaimer

Pure research-oriented project, USE AT YOUR OWN DISCRETION, as its a GPLv3 licensed project!
