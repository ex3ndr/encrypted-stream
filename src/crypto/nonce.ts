export function createNonce(length: number, value: string) {
    let b = Buffer.from(value, 'utf-8');
    if (b.length > length) {
        return b.subarray(0, length);
    }
    if (b.length < length) {
        return Buffer.concat([Buffer.alloc(length - b.length, 0), b]);
    }
    return b;
}

export function createCounterIV(mask: Buffer, counter: number) {
    let res = Buffer.alloc(mask.length);
    res.writeInt32BE(counter, 0);
    for (let i = 0; i < mask.length; i++) {
        res[i] = res[i] ^ mask[i];
    }
    return res;
}