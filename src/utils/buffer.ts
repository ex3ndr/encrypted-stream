export class BufferReader {
    readonly buffer: Buffer;
    private _offset = 0;

    constructor(buffer: Buffer) {
        this.buffer = buffer;
    }

    get remaining() {
        return this.buffer.length - this._offset;
    }

    readUInt8() {
        if (this.buffer.length < this._offset + 1) {
            throw Error('EOF');
        }
        let res = this.buffer.readUInt8(this._offset);
        this._offset++;
        return res;
    }

    readUInt16() {
        if (this.buffer.length < this._offset + 2) {
            throw Error('EOF');
        }
        let res = this.buffer.readUInt16BE(this._offset);
        this._offset += 2;
        return res;
    }

    readUInt32() {
        if (this.buffer.length < this._offset + 4) {
            throw Error('EOF');
        }
        let res = this.buffer.readUInt32BE(this._offset);
        this._offset += 4;
        return res;
    }

    readAsciiString(length: number) {
        if (this.buffer.length < this._offset + length) {
            throw Error('EOF');
        }
        let res = this.buffer.subarray(this._offset, this._offset + length);
        this._offset += length;
        return res.toString('ascii');
    }

    readUTF8String(length: number) {
        if (this.buffer.length < this._offset + length) {
            throw Error('EOF');
        }
        let res = this.buffer.subarray(this._offset, this._offset + length);
        this._offset += length;
        return res.toString('utf8');
    }


    readBuffer(length: number) {
        if (this.buffer.length < this._offset + length) {
            throw Error('EOF');
        }
        let res = this.buffer.subarray(this._offset, this._offset + length);
        this._offset += length;
        return res;
    }
}

export class BufferWriter {
    private _buffer: Buffer = Buffer.alloc(0);

    appendUInt8(value: number) {
        let b = Buffer.alloc(1);
        b.writeUInt8(value, 0);
        this._buffer = Buffer.concat([this._buffer, b]);
    }

    appendUInt16(value: number) {
        let b = Buffer.alloc(2);
        b.writeUInt16BE(value, 0);
        this._buffer = Buffer.concat([this._buffer, b]);
    }

    appendUInt32(value: number) {
        let b = Buffer.alloc(4);
        b.writeUInt32BE(value, 0);
        this._buffer = Buffer.concat([this._buffer, b]);
    }

    appendAsciiString(value: string) {
        let b = Buffer.from(value, 'ascii');
        this._buffer = Buffer.concat([this._buffer, b]);
    }

    appendUTF8String(value: string) {
        let b = Buffer.from(value, 'utf8');
        this._buffer = Buffer.concat([this._buffer, b]);
    }

    appendBuffer(buffer: Buffer) {
        this._buffer = Buffer.concat([this._buffer, buffer]);
    }

    build() {
        return this._buffer;
    }
}