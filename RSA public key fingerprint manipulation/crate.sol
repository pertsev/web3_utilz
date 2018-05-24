pragma solidity ^0.4.17;

contract RSA {
    function verify(bytes32 rawmsg, bytes N, bytes E, bytes S) public view returns (bool) {
        bytes memory b = new bytes(N.length);
        for (uint i = 1; i <= rawmsg.length; i++){
            b[b.length-i] = rawmsg[rawmsg.length-i];
        }
        var (retS, valS) = modexp(S, E, N);
        return (retS == true && keccak256(valS) == keccak256(b));
    }

    function memcopy(bytes src, uint srcoffset, bytes dst, uint dstoffset, uint len) pure internal {
        assembly {
        //begining of data in src and dst
            src := add(src, add(32, srcoffset))
            dst := add(dst, add(32, dstoffset))

        // copy 32 bytes at once
            for
            {} //counter not needed
            iszero(lt(len, 32)) //untill (len>32)
            {
                dst := add(dst, 32) //destination pointer shift to 32 bytes
                src := add(src, 32) //source pointer shift to 32 bytes
                len := sub(len, 32) //length of the remainder decrease to 32 bytes
            }
            { mstore(dst, mload(src)) }
        // copy the remainder (0 < len < 32)
            let mask := sub(exp(256, sub(32, len)), 1) //256^(32-len) - 1
            let srcpart := and(mload(src), not(mask)) //select first len bytes
            let dstpart := and(mload(dst), mask)  //set to zero first len bytes
            mstore(dst, or(srcpart, dstpart))   //first len bits of source copy to dst
        }
    }

    function modexp(bytes base, bytes exponent, bytes modulus) internal view returns (bool success, bytes output) {
        uint base_length = base.length;
        uint exponent_length = exponent.length;
        uint modulus_length = modulus.length;

        //Allocate memory for input
        uint size = (32 * 3) + base_length + exponent_length + modulus_length;
        bytes memory input = new bytes(size);

        ////Allocate memory for output
        output = new bytes(modulus_length);

        //Push lengths on the stack
        assembly {
        //mstore(addr, src) - push src to addr on the stack
            mstore(add(input, 32), base_length) //push base_length on the bytes[0]
            mstore(add(input, 64), exponent_length)
            mstore(add(input, 96), modulus_length)
        }
        //push base on the stack
        memcopy(base, 0, input, 96, base_length);
        //push exponent on the stack
        memcopy(exponent, 0, input, 96 + base_length, exponent_length);
        //push modulus on the stack
        memcopy(modulus, 0, input, 96 + base_length + exponent_length, modulus_length);

        //call bigModExp precompiled contract
        assembly {
            success := staticcall(gas(), 5, add(input, 32), size, add(output, 32), modulus_length)
        }
    }
}

contract Crate {

    mapping(bytes32 => uint) public keys;
    RSA rsa;

    function Crate() public {
        rsa = new RSA();
    }

    function submitPubKey(bytes _N, bytes _E) public payable {
        keys[keccak256(_N, _E)] = msg.value;
    }

    function returnETH(bytes32 addr, bytes _N, bytes _E, bytes _rsaSign) public {
        bytes32 fingerprint = keccak256(_N, _E);
        require(keys[fingerprint] > 0);
        require(rsa.verify(addr, _N, _E, _rsaSign));

        address(addr).transfer(keys[fingerprint]);
    }
}
