%builtins output range_check bitwise

from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.uint256 import Uint256
from starkware.cairo.common.cairo_secp.signature import verify_eth_signature_uint256, recover_public_key
from starkware.cairo.common.cairo_secp.bigint import uint256_to_bigint, BigInt3
from starkware.cairo.common.cairo_secp.ec import EcPoint
from starkware.cairo.common.cairo_builtins import BitwiseBuiltin
from starkware.cairo.common.cairo_keccak.keccak import finalize_keccak


func main{output_ptr: felt*, range_check_ptr, bitwise_ptr: BitwiseBuiltin*}() {
    alloc_locals;

    local request_params;
    local msgHash: Uint256;
    local pub_key_x: Uint256;
    local pub_key_y: Uint256;
    local r: Uint256;
    local s: Uint256;
    local eth_address;
    local eth_address_acceptable;
    local addr_int;
    %{
        import hashlib
        import sha3
        import time
        from jwcrypto.common import base64url_decode, json_decode

        public_key = program_input["public_key"]
        public_key2 = public_key[4:]

        x = int(public_key2[:64], 16)
        y = int(public_key2[64:], 16)
        ids.pub_key_x.low = x & ((1<<128) - 1)
        ids.pub_key_x.high = x >> 128
        ids.pub_key_y.low = y & ((1<<128) - 1)
        ids.pub_key_y.high = y >> 128


        k = sha3.keccak_256()
        k.update(bytes.fromhex(public_key2))
        addr_hex = k.hexdigest()
        print("pub_key_hash hex: ", addr_hex)
        
        addr_int = int(addr_hex[24:], 16)
        print("addr_int: ", addr_int)
        ids.addr_int = addr_int

        request = program_input["req_params"]
        header, claims, signMsg = request.split(".")
        parsed_header = json_decode(base64url_decode(header))

        parsed_claims = json_decode(base64url_decode(claims))

        did = parsed_claims['iss']
        print("payload: ", did)
        print('--', int(did[14:], 16))
        ids.eth_address = int(did[14:], 16)

        rawSig = base64url_decode(signMsg)
        print('hex r: ', rawSig[:32].hex(), len(rawSig))
        r = int.from_bytes(rawSig[:32], 'big')
        print('r: ', r)
        s = int.from_bytes(rawSig[32:64], 'big')
        print('s: ', s)

        ids.r.low = r & ((1<<128) - 1)
        ids.r.high = r >> 128
        ids.s.low = s & ((1<<128) - 1)
        ids.s.high = s >> 128

        msg = header + "." + claims
        msg_hash = hashlib.sha256(msg.encode()).digest()
        hashBytes = int.from_bytes(msg_hash, 'big')
        print("hash hex: ", msg_hash.hex())
        print("hex to int: ", int(msg_hash.hex(), 16))
        ids.msgHash.low = hashBytes & ((1<<128) - 1)
        ids.msgHash.high = hashBytes >> 128
        start = time.time()
    %}// This hint is mainly about reading VC_file from input file and do some preprocess(such as hash, hexadecimal) for cairo, no meanful data process is made here

    let eth_address_acceptable=35029207752483137963156621618327446821269239226;//replace your acceptable issuer's address in decimal here
    let (local keccak_ptr_start) = alloc();
    let keccak_ptr = keccak_ptr_start;
    verify_eth_signature_uint256{keccak_ptr=keccak_ptr}(msg_hash=msgHash, r=r, s=s, v=0, eth_address=eth_address_acceptable);
    //This is the main verify process, using Cairo's offical function, source code:src/starkware/cairo/cairo_secp
    finalize_keccak(keccak_ptr_start=keccak_ptr_start, keccak_ptr_end=keccak_ptr);

    
    %{
        print('cost time: ', time.time() - start)
    %}
    
    serialize_word(eth_address);// Since Cairo don't have string type right now, we print eth_address to express successfully verify 
    return ();
}
