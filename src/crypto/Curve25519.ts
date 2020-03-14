import { Key } from './key';
import nacl from 'tweetnacl';

export function newCurve25519Key(): Key {
    let key = nacl.box.keyPair();
    return {
        publicKey: Buffer.from(key.publicKey),
        secretKey: Buffer.from(key.secretKey)
    };
}

export function curve25519DH(secretKey: Buffer, publicKey: Buffer) {
    return Buffer.from(nacl.scalarMult(secretKey, publicKey));
}