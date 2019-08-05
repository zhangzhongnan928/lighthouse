# Setup Fuzzer

In order to run the fuzzer efficiently a corpus should be setup. To setup the
corpus in the folder current folder `fuzz` create a directory called `corpus`.
For each of the fuzz targets create a folder with the fuzz target name e.g.
`fuzz_target_random_block_headers`.

Copy the required files from `corpus-binaries` into the `corpus/<fuzz target name>` folder.

e.g. `cp corpus-binaries/block_1.bin corpus/fuzz_target_random_block_headers` OR
`cp corpus-binaries/attestation.bin corpus/fuzz_target_random_attestations`

# Run Fuzzer

To run the fuzzer you must be in rust nightly.

`cargo fuzz run <fuzz_target>`

Examples:

`cargo fuzz run fuzz_target_random_block_headers`

## Fake Crypto

It is recommended in most cases to run it with `--features fake_crypto`.
As most of the block processing time is spent validating signatures it will run
more than 15x faster with fake_crypto.

# Modifications to the code

Modifications have been kept main to change functions to `public` or to be included
in the library. However there is one significant change which is `process_deposits`
no longer verifies the merkle proofs.
