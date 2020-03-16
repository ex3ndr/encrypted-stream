import hkdf from 'futoin-hkdf';
import { hkdf512 } from './hkdf';

describe('hkdf', () => {
    it('should match ', () => {
        let res = hkdf(Buffer.from([1, 2, 3]), 32, { salt: 'Hello-Salt', info: 'Hello-Info', hash: 'sha-512' })
        let res2 = hkdf512(Buffer.from([1, 2, 3]), 32, 'Hello-Salt', 'Hello-Info');
        expect(res.toString('hex')).toBe(res2.toString('hex'));
    })
});