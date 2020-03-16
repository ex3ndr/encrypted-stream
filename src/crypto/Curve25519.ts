import nacl from 'tweetnacl';
import { randomBytes } from 'universal-secure-random';
import { Key } from './key';

export function newCurve25519Key(): Key {
    let secretKey = randomBytes(nacl.box.secretKeyLength);
    let publicKey = Buffer.from(nacl.box.keyPair.fromSecretKey(secretKey));
    return {
        publicKey,
        secretKey
    };
}

export function curve25519DH(secretKey: Buffer, publicKey: Buffer) {
    return Buffer.from(nacl.scalarMult(secretKey, publicKey));
}