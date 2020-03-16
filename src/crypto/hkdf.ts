import { HKDF } from '@stablelib/hkdf';
import { SHA512 } from "@stablelib/sha512";

export function hkdf512(src: Buffer, length: number, salt: string, info: string) {
    let hkdf = new HKDF(SHA512, src, Buffer.from(salt), Buffer.from(info));
    return Buffer.from(hkdf.expand(length));
}