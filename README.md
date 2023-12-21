# Grapevine
Prove degrees of separation from a secret using a nova-folded recursive circuit

## Initialization
Upon cloning this repository, run the bash script `./compile.sh` to build the cli and proving artifacts. Note that these artifacts are included in the git repository so this is not strictly necessary - instead you can just build the CLI with `cargo install --path ./crates/grapevine_cli`

## CLI Use

### PREREQUISITES
0. Install the CLI binary and link it globally
```console
$ cargo install --path ./crates/grapevine_cli
```
You can now use the CLI by running `grapevine` in your terminal.

1. Set artifact directories as ENV variables for ease of access
NOTE: currently proving artifacts `public_params.json`, `folded.r1cs`, and `folded.wasm` are poorly managed and must be given by the CLI. This will eventually be handled (maybe saving in `~/.grapevine`? tbd). 
```console
$ grapevine_PARAMS=./crates/grapevine_circuits/circom/artifacts/public_params.json
$ grapevine_R1CS=./crates/grapevine_circuits/circom/artifacts/folded.r1cs
$ grapevine_WC=./crates/grapevine_circuits/circom/artifacts/folded_js/folded.wasm
```
### Prove a new secret
Just like [The Word](https://github.com/mach-34/the-word), this project starts with proving knowledge of some secret phrase. To do so, you can use the `prove-secret` command in the `grapevine` cli.

Prototype:
```console
$ grapevine prove-secret \
    {SECRET TO PROVE} \
    {YOUR USERNAME} \
    {DIRECTORY TO OUTPUT PROOF} \
    {RELATIVE PATH TO PUBLIC PARAMS} \
    {RELATIVE PATH TO grapevine R1CS} \
    {RELATIVE PATH TO grapevine WITNESS CALCULATOR BINARY}
```

Example: 
```console
$ grapevine prove-secret \
    "hunter2" \
    "mach34" \
    . \
    $grapevine_PARAMS \
    $grapevine_R1CS \
    $grapevine_WC
```
Executing this command will save the computed proof to `{DIRECTORY TO OUTPUT PROOF}/grapevine_degree_1.json`, where 1 indicates that this proof is has 1 degree of separation (i.e. it is a proof of knowledge of the secret phrase)

### Prove degrees of separation from a secret
grapevine uses nova folding to recursively verify degrees of separation from a proof. In order to prove N degrees of separation, you must know someone with N-1 degrees of separation from the secret! If they provide you their proof of N-1 degrees of separation along with their username, you can prove you have N degrees of separation from the secret. To do this, use the `prove-separation` command in the `grapevine` CLI.

Prototype: 
```console
$ grapevine prove-separation \
    {DEGREES OF SEPARATION} \
    {USERNAME TO PROVE 1 DEGREE OF SEPARATION FROM} \
    {YOUR USERNAME} \
    {RELATIVE PATH TO PROOF TO VERIFY} \
    {DIRECTORY TO OUTPUT PROOF} \
    {RELATIVE PATH TO PUBLIC PARAMS} \
    {RELATIVE PATH TO grapevine R1CS} \
    {RELATIVE PATH TO grapevine WITNESS CALCULATOR BINARY}
```

Example:
```console
$ grapevine prove-separation \
    2 \
    "mach34" \
    "jp4g" \
    ./grapevine_degree_1.json \
    . \
    $grapevine_PARAMS \
    $grapevine_R1CS \
    $grapevine_WC
```

Note: this is not secure and in the future we will likely include a secret factor that each degree of separation must provide to lock down the ability for a username to be guessed/ figured out if a proof is known. 

### Verify authenticity of a proof of N degrees of separation from a secret
If you have a proof, you can verify that it is N degrees of separation from a secret using `verify` in the `grapevine` CLI.

Prototype:
```console
$ grapevine verify
    {DEGREES OF SEPARATION} \
    {RELATIVE PATH TO PROOF TO VERIFY} \
    {RELATIVE PATH TO PUBLIC PARAMS}
```

Example:
```console
$ grapevine verify 2 ./grapevine_degree_2.json $grapevine_PARAMS
```