import nacl from 'tweetnacl';

export function openBox(message: Buffer, nonce: Buffer, key: Buffer) {
    let res = nacl.secretbox.open(message, nonce, key);
    if (res) {
        return Buffer.from(res);
    } else {
        return null;
    }
}

export function sealBox(message: Buffer, nonce: Buffer, key: Buffer) {
    return Buffer.from(nacl.secretbox(message, nonce, key));
}

export const BOX_NONCE_SIZE = 24;