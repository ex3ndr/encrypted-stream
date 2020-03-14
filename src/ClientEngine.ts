import { BOX_NONCE_SIZE, openBox, sealBox } from './crypto/box';
import { BufferWriter, BufferReader } from './utils/buffer';
import { EndpointKey, Endpoint } from './keys';
import { newCurve25519Key, curve25519DH } from './crypto/Curve25519';
import { hkdf512 } from './crypto/hkdf';
import { createNonce, createCounterIV } from './crypto/nonce';
import { verify } from './crypto/Ed25519';

export type ClientEngineState = 'need-server-hello' | 'open' | 'closed';

export class ClientEngine {
    private readonly _version = 1;
    private readonly _endpointKey: EndpointKey;
    private readonly _endpoint: Endpoint;
    private _state: ClientEngineState = 'need-server-hello';

    // Keys
    private _ephermalKey = newCurve25519Key();
    private _serverEphemeralKey!: Buffer;
    private _sessionKey!: Buffer;

    // Streaming Parameters
    private _outCounter = 0;
    private _inCounter = 0;
    private _writeKey!: Buffer;
    private _writeIV!: Buffer;
    private _readKey!: Buffer;
    private _readIV!: Buffer;

    constructor(endpointKey: EndpointKey, endpoint: Endpoint) {
        this._endpointKey = endpointKey;
        this._endpoint = endpoint;
    }

    get state() {
        return this._state;
    }

    getClientHello() {
        const writer = new BufferWriter();
        writer.appendUInt8(this._version);
        writer.appendBuffer(this._ephermalKey.publicKey);
        return writer.build();
    }

    setServerHello(data: Buffer): boolean {
        this._assertState('need-server-hello');

        const reader = new BufferReader(data);

        // Check Version
        if (reader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        let version = reader.readUInt8();
        if (version !== this._version) {
            this._state = 'closed';
            return false;
        }

        // Server Public Key
        if (reader.remaining < 32) {
            this._state = 'closed';
            return false;
        }
        this._serverEphemeralKey = reader.readBuffer(32);

        // Compute premaster key
        this._sessionKey = curve25519DH(this._ephermalKey.secretKey, this._serverEphemeralKey);

        // Derive required keys
        this._writeKey = hkdf512(this._sessionKey, 32, 'server-write-key', 'server-write-key-info');
        this._writeIV = hkdf512(this._sessionKey, 24, 'server-write-iv', 'server-write-iv-info');
        this._readKey = hkdf512(this._sessionKey, 32, 'client-write-key', 'client-write-key-info');
        this._readIV = hkdf512(this._sessionKey, 24, 'client-write-iv', 'client-write-iv-info');

        // Decrypt box
        const encryptedBoxLength = reader.readUInt16();
        const encryptedBox = reader.readBuffer(encryptedBoxLength);
        const handshakeKey = hkdf512(this._sessionKey, 32, 'handshake-m2-key', 'handshake-m2-info');
        const handshakeNonce = createNonce(BOX_NONCE_SIZE, 'handshake-m2');
        const encrypted = openBox(encryptedBox, handshakeNonce, handshakeKey);
        if (!encrypted) {
            this._state = 'closed';
            return false;
        }

        // Parse decrypted
        const encryptedReader = new BufferReader(encrypted);
        if (encryptedReader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        let endpointLength = encryptedReader.readUInt8();
        if (encryptedReader.remaining < endpointLength) {
            this._state = 'closed';
            return false;
        }
        let endpoint = encryptedReader.readUTF8String(endpointLength);
        if (endpoint !== this._endpoint.endpointId) {
            this._state = 'closed';
            return false;
        }
        if (encryptedReader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        let sigLength = encryptedReader.readUInt8();
        if (encryptedReader.remaining < sigLength) {
            this._state = 'closed';
            return false;
        }
        let sig = encryptedReader.readBuffer(sigLength);


        // Check Signatrue
        const signDataWriter = new BufferWriter();
        signDataWriter.appendUInt8(endpointLength);
        signDataWriter.appendUTF8String(endpoint);
        signDataWriter.appendBuffer(this._serverEphemeralKey); // Server Key
        signDataWriter.appendBuffer(this._ephermalKey.publicKey); // Client Key
        const signed = verify(signDataWriter.build(), sig, this._endpoint.publicKey);
        if (!signed) {
            this._state = 'closed';
            return false;
        }

        this._state = 'open';

        return true;
    }

    getPeerInfo() {
        const signedWriter = new BufferWriter();
        // Endpoint ID
        signedWriter.appendUInt8(Buffer.byteLength(this._endpointKey.endpointId, 'utf-8'));
        signedWriter.appendUTF8String(this._endpointKey.endpointId);
        // Own Ephemeral Key
        signedWriter.appendBuffer(this._ephermalKey.publicKey);
        // Received Ephemeral Key
        signedWriter.appendBuffer(this._serverEphemeralKey);

        // Sign
        let signature = this._endpointKey.signer(signedWriter.build());

        // Plain Text Container
        let plainTextWriter = new BufferWriter();
        plainTextWriter.appendUInt8(Buffer.byteLength(this._endpointKey.endpointId, 'utf-8'));
        plainTextWriter.appendUTF8String(this._endpointKey.endpointId);
        plainTextWriter.appendUInt8(signature.length);
        plainTextWriter.appendBuffer(signature);

        // Encrypted part
        const handshakeResponseKey = hkdf512(this._sessionKey, 32, 'handshake-m3-key', 'handshake-m3-info');
        const handshakeResponseNonce = createNonce(BOX_NONCE_SIZE, 'handshake-m3');
        const encryptedResponse = sealBox(plainTextWriter.build(), handshakeResponseNonce, handshakeResponseKey);

        const writer = new BufferWriter();
        writer.appendUInt8(this._version);
        writer.appendUInt16(encryptedResponse.length);
        writer.appendBuffer(encryptedResponse);
        return writer.build();
    }

    encrypt(buffer: Buffer): Buffer {
        this._assertState('open');

        let writer = new BufferWriter();

        // Version
        writer.appendUInt8(this._version);

        // Encrypted box
        let counter = this._outCounter;
        this._outCounter++;
        let ctx = sealBox(buffer, createCounterIV(this._writeIV, counter), this._writeKey);
        writer.appendUInt32(ctx.length);
        writer.appendBuffer(ctx);

        return writer.build();
    }

    decrypt(buffer: Buffer): Buffer | null {
        this._assertState('open');

        let reader = new BufferReader(buffer);

        // Version
        if (reader.remaining < 1) {
            this._state = 'closed';
            return null;
        }
        let version = reader.readUInt8();
        if (version !== this._version) {
            this._state = 'closed';
            return null;
        }

        if (reader.remaining < 4) {
            this._state = 'closed';
            return null;
        }
        let boxSize = reader.readUInt32();
        if (reader.remaining < boxSize) {
            this._state = 'closed';
            return null;
        }
        let box = reader.readBuffer(boxSize);

        // Decrypted
        let counter = this._inCounter;
        this._inCounter++;
        let decrypted = openBox(box, createCounterIV(this._readIV, counter), this._readKey);
        if (!decrypted) {
            this._state = 'closed';
            return null;
        }

        return decrypted;
    }

    close() {
        this._state = 'closed';
    }

    private _assertState(state: ClientEngineState) {
        if (this._state !== state) {
            throw Error('Expected state ' + state + ', got: ' + this._state);
        }
    }
}