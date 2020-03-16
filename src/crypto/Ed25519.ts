import nacl from 'tweetnacl';
import { randomBytes } from 'universal-secure-random';
import { Key } from './key';

export function newEd25519Key(): Key {
    let secretKey = randomBytes(nacl.sign.secretKeyLength);
    let publicKey = Buffer.from(nacl.sign.keyPair.fromSecretKey(secretKey));
    return {
        publicKey: publicKey,
        secretKey: secretKey
    }
}

export function sign(secretKey: Buffer, message: Buffer) {
    return Buffer.from(nacl.sign.detached(message, secretKey));
}

export function verify(message: Buffer, signature: Buffer, publicKey: Buffer) {
    return nacl.sign.detached.verify(message, signature, publicKey);
}