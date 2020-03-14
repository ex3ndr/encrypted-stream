import { EndpointKey } from './keys';
import { BOX_NONCE_SIZE, sealBox, openBox } from './crypto/box';
import { BufferReader, BufferWriter } from './utils/buffer';
import { newCurve25519Key, curve25519DH } from "./crypto/Curve25519";
import { hkdf512 } from './crypto/hkdf';
import { createNonce, createCounterIV } from './crypto/nonce';
import { verify } from './crypto/Ed25519';

export type PeerLoader = (endpointId: string) => Buffer | null;

export type ServerEngineState = 'need-client-hello' | 'need-peer-info' | 'open' | 'closed';

export class ServerEngine {
    private readonly _version = 1;
    private readonly _key: EndpointKey;
    private readonly _peerLoader: PeerLoader;
    private _state: ServerEngineState = 'need-client-hello';

    // Keys
    private _ephemeralKey = newCurve25519Key();
    private _clientEphemeralKey!: Buffer;
    private _sessionKey!: Buffer;

    // Streaming Parameters
    private _outCounter = 0;
    private _inCounter = 0;
    private _writeKey!: Buffer;
    private _writeIV!: Buffer;
    private _readKey!: Buffer;
    private _readIV!: Buffer;

    // Endpoint
    private _endpointId!: string;

    /**
     * Server Engine Contstuctor
     * @param key Server LTS key and endpointId
     * @param peerLoader Function to load peer public keys by it's endpoint id
     */
    constructor(key: EndpointKey, peerLoader: PeerLoader) {
        this._key = key;
        this._peerLoader = peerLoader;
    }

    /**
     * Get Server Engine State
     */
    get state() {
        return this._state;
    }

    /**
     * Get Client Endpoint Id
     */
    get endpointId() {
        if (!this._endpointId) {
            throw Error('Peer Info needed');
        }
        return this._endpointId;
    }

    /**
     * Set client Hello
     * @param buffer raw client hello buffer
     * @returns true if successful
     */
    setClientHello(buffer: Buffer): boolean {
        this._assertState('need-client-hello');

        const reader = new BufferReader(buffer);
        if (reader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        const version = reader.readUInt8();
        if (version !== this._version) {
            this._state = 'closed';
            return false;
        }

        // Read client ephemeral key
        if (reader.remaining < 32) {
            this._state = 'closed';
            return false;
        }
        this._clientEphemeralKey = reader.readBuffer(32);

        // Compute premaster key
        this._sessionKey = curve25519DH(this._ephemeralKey.secretKey, this._clientEphemeralKey);

        // Derive keys
        this._writeKey = hkdf512(this._sessionKey, 32, 'client-write-key', 'client-write-key-info');
        this._writeIV = hkdf512(this._sessionKey, 24, 'client-write-iv', 'client-write-iv-info');
        this._readKey = hkdf512(this._sessionKey, 32, 'server-write-key', 'server-write-key-info');
        this._readIV = hkdf512(this._sessionKey, 24, 'server-write-iv', 'server-write-iv-info');

        // Update state
        this._state = 'need-peer-info';

        return true;
    }

    /**
     * Get ServerHello to send to user
     * @returns buffer
     */
    getServerHello() {
        this._assertState('need-peer-info');

        //
        // Signing data
        //
        const signedWriter = new BufferWriter();
        // Endpoint ID
        signedWriter.appendUInt8(Buffer.byteLength(this._key.endpointId, 'utf-8'));
        signedWriter.appendUTF8String(this._key.endpointId);
        // Own Ephemeral Key
        signedWriter.appendBuffer(this._ephemeralKey.publicKey);
        // Received Ephemeral Key
        signedWriter.appendBuffer(this._clientEphemeralKey);
        let signature = this._key.signer(signedWriter.build());

        // Plain Text
        let plainTextWriter = new BufferWriter();
        plainTextWriter.appendUInt8(Buffer.byteLength(this._key.endpointId, 'utf-8'));
        plainTextWriter.appendUTF8String(this._key.endpointId);
        plainTextWriter.appendUInt8(signature.length);
        plainTextWriter.appendBuffer(signature);

        // Encrypt
        const handshakeKey = hkdf512(this._sessionKey, 32, 'handshake-m2-key', 'handshake-m2-info');
        const handshakeNonce = createNonce(BOX_NONCE_SIZE, 'handshake-m2');
        const encrypted = sealBox(plainTextWriter.build(), handshakeNonce, handshakeKey);

        // Make a package
        const writer = new BufferWriter();
        writer.appendUInt8(this._version);
        writer.appendBuffer(this._ephemeralKey.publicKey);
        writer.appendUInt16(encrypted.length);
        writer.appendBuffer(encrypted);
        return writer.build();
    }

    /**
     * Set Peer Info from Client
     * @param buffer Raw Peer Info
     */
    setPeerInfo(frame: Buffer): boolean {
        this._assertState('need-peer-info');

        const reader = new BufferReader(frame);

        // Check Version
        if (reader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        const version = reader.readUInt8();
        if (version !== this._version) {
            this._state = 'closed';
            return false;
        }
        if (reader.remaining < 2) {
            this._state = 'closed';
            return false;
        }

        // Decrypting contents
        const encryptedLength = reader.readUInt16();
        if (reader.remaining < encryptedLength) {
            this._state = 'closed';
            return false;
        }
        const encrypted = reader.readBuffer(encryptedLength);
        const handshakeKey = hkdf512(this._sessionKey, 32, 'handshake-m3-key', 'handshake-m3-info');
        const handshakeNonce = createNonce(BOX_NONCE_SIZE, 'handshake-m3');
        let plainText = openBox(encrypted, handshakeNonce, handshakeKey);
        if (!plainText) {
            this._state = 'closed';
            return false;
        }

        // Parsing plain text
        const plainTextReader = new BufferReader(Buffer.from(plainText));
        if (plainTextReader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        let clientIdLength = plainTextReader.readUInt8();
        if (plainTextReader.remaining < clientIdLength) {
            this._state = 'closed';
            return false;
        }
        let clientId = plainTextReader.readUTF8String(clientIdLength);
        if (plainTextReader.remaining < 1) {
            this._state = 'closed';
            return false;
        }
        let sigLength = plainTextReader.readUInt8();
        if (plainTextReader.remaining < sigLength) {
            this._state = 'closed';
            return false;
        }
        let sig = plainTextReader.readBuffer(sigLength);

        // Extract client public key
        let clientKey = this._peerLoader(clientId);
        if (!clientKey) {
            this._state = 'closed';
            return false;
        }

        // Check signature
        const signDataWriter = new BufferWriter();
        signDataWriter.appendUInt8(clientIdLength);
        signDataWriter.appendUTF8String(clientId);
        signDataWriter.appendBuffer(this._clientEphemeralKey); // Client Key
        signDataWriter.appendBuffer(this._ephemeralKey.publicKey); // Server Key
        if (!verify(signDataWriter.build(), sig, clientKey)) {
            this._state = 'closed';
            return false;
        }

        this._endpointId = clientId;
        this._state = 'open'

        return true;
    }

    /**
     * Encrypt next frame
     * @param buffer Frame to decrypt
     */
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

    /**
     * Decrypt next frame
     * @param buffer Frame to decrypt
     */
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

    /**
     * Close Engine
     */
    close() {
        this._state = 'closed';
    }

    private _assertState(state: ServerEngineState) {
        if (this._state !== state) {
            throw Error('Expected state ' + state + ', got: ' + this._state);
        }
    }
}