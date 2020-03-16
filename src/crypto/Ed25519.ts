import nacl from 'tweetnacl';
import { randomBytes } from 'universal-secure-random';
import { Key } from './key';

export function newEd25519Key(): Key {
    let key = nacl.sign.keyPair.fromSeed(randomBytes(nacl.sign.seedLength))
    return {
        publicKey: Buffer.from(key.publicKey),
        secretKey: Buffer.from(key.secretKey)
    }
}

export function sign(secretKey: Buffer, message: Buffer) {
    return Buffer.from(nacl.sign.detached(message, secretKey));
}

export function verify(message: Buffer, signature: Buffer, publicKey: Buffer) {
    return nacl.sign.detached.verify(message, signature, publicKey);
}