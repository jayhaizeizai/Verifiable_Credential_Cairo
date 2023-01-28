# Verifiable_Credential_Cairo
This is a project aiming to verify Verifiable Credential in W3C standard using Cairo language.

By doing so, we could prove some Verifiable Credential using a STARK proof while no leaking the Verifiable Credential itself to anybody.

Usage:

1.Cairo enviroment is required, see https://www.cairo-lang.org/docs/quickstart.html, Currently we are building on python version Cario instead of the rust version

2.Change the source code & config: Change source code line 84 eth_address_acceptable into the Issuer you accept

3.Compile: cairo-compile Verify_ECDSA.cairo --output Verify_ECDSA_compiled.json

4.Running command: cairo-run --program=Verify_ECDSA_compiled.json     --print_output --layout=all     --program_input=input_temple.json

