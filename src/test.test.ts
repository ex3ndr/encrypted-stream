import { ClientEngine } from './ClientEngine';
import { ServerEngine } from './ServerEngine';
import { newEd25519Key } from "./crypto/Ed25519";
import { createSigner } from "./keys";

describe('Encryptor', () => {
    it('should encrypt and decrypt successfully', () => {
        const ltsKey = newEd25519Key();
        const ltsSigner = createSigner(ltsKey.secretKey);
        const serverEndpointId = 'eego-RANDOM-ID';
        const clientLTSKey = newEd25519Key();
        const clientId = 'user1';

        const server = new ServerEngine({
            endpointId: serverEndpointId,
            publicKey: ltsKey.publicKey,
            signer: ltsSigner
        }, (v) => v === clientId ? clientLTSKey.publicKey : null);

        const client = new ClientEngine({
            endpointId: clientId,
            publicKey: clientLTSKey.publicKey,
            signer: createSigner(clientLTSKey.secretKey)
        }, { endpointId: serverEndpointId, publicKey: ltsKey.publicKey });

        // Hello Messages
        let clientHello = client.getClientHello();
        expect(server.setClientHello(clientHello)).toBe(true);
        let serverHello = server.getServerHello();
        expect(client.setServerHello(serverHello)).toBe(true);

        // Peer Info
        let clientPeerInfo = client.getPeerInfo();
        expect(server.setPeerInfo(clientPeerInfo)).toBe(true);
        expect(server.endpointId).toBe(clientId);

        // Server -> Client
        let clientDecrypted = client.decrypt(server.encrypt(Buffer.from('Hello World!', 'utf-8')));
        expect(clientDecrypted!.toString('utf-8')).toBe('Hello World!');

        // Client -> Server
        let serverDecrypted = server.decrypt(client.encrypt(Buffer.from('Hello World!', 'utf-8')));
        expect(serverDecrypted!.toString('utf-8')).toBe('Hello World!');
    });
})