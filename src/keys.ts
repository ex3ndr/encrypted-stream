import { sign } from "./crypto/Ed25519";

export type Signer = (buffer: Buffer) => Buffer;

export interface Endpoint {
    endpointId: string;
    publicKey: Buffer;
}

export interface EndpointKey {
    endpointId: string;
    publicKey: Buffer;
    signer: Signer;
}

export function createSigner(secretKey: Buffer): Signer {
    return (msg: Buffer) => sign(secretKey, msg);
}