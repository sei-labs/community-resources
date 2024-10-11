```typescript
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { keccak_256 } from '@noble/hashes/sha3';
import { secp256k1 } from '@noble/curves/secp256k1';
import { bech32 } from 'bech32';

// Utility function to convert bits for Bech32 encoding
function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
    let acc = 0;
    let bits = 0;
    const result: number[] = [];
    const maxv = (1 << toBits) - 1;

    for (const value of data) {
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            result.push((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            result.push((acc << (toBits - bits)) & maxv);
        }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) {
        throw new Error('Unable to convert bits');
    }

    return result;
}

// Function to generate addresses from a private key
function generateAddresses(privateKeyHex: string): { seiAddress: string, ethAddress: string } {
    // Ensure the private key is exactly 32 bytes long
    const privateKey = Uint8Array.from(Buffer.from(privateKeyHex.padStart(64, '0'), 'hex'));
    if (privateKey.length !== 32) {
        throw new Error('Private key must be 32 bytes long.');
    }

    // Derive the compressed public key from the private key
    const publicKey = secp256k1.getPublicKey(privateKey, true);
    const publicKeyBytes = publicKey;

    // Perform SHA-256 hashing on the compressed public key
    const sha256Digest = sha256(publicKeyBytes);

    // Perform RIPEMD-160 hashing on the SHA-256 digest
    const ripemd160Digest = ripemd160(sha256Digest);

    // Convert the RIPEMD-160 digest to a 5-bit array for Bech32 encoding
    const fiveBitArray = convertBits(ripemd160Digest, 8, 5, true);

    // Bech32 address with "sei" prefix
    const seiAddress = bech32.encode('sei', fiveBitArray, 256);

    // Derive the uncompressed public key from the private key and exclude the first byte
    const publicKeyUncompressed = secp256k1.getPublicKey(privateKey, false).slice(1);

    // Perform Keccak-256 hashing on the uncompressed public key to derive the Ethereum address
    const keccakHash = keccak_256(publicKeyUncompressed);
    const ethAddress = `0x${Buffer.from(keccakHash).slice(-20).toString('hex')}`;

    return { seiAddress, ethAddress };
}

// Example usage of the generateAddresses function
const privateKeyHex = '907ab4bf7fc60cff';
const { seiAddress, ethAddress } = generateAddresses(privateKeyHex);

console.log(`Sei Address: ${seiAddress}`);
console.log(`Ethereum Address: ${ethAddress}`);
```
