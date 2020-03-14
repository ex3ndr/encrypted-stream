import hkdf from 'futoin-hkdf';

export function hkdf512(src: Buffer, length: number, salt: string, info: string) {
    return hkdf(src, length, { salt, info, hash: 'sha-512' })
}