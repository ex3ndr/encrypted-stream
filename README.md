# encrypted-stream: Simple streaming encryption with authentication
[![Version npm](https://img.shields.io/npm/v/encrypted-stream.svg?logo=npm)](https://www.npmjs.com/package/encrypted-stream)

`encrypted-stream` is a simple and safe encryption library that provides a simple API for implementing userspace encrypted networking protocols. Inspired on simplicity of NaCL aimed to provide similar API but for authenticated two-side protocols.

## Features
* ✍️ Based on TLS and HomeKit Accessory Protocol
* 🏎Fast and trusted Ed25519 and Curve25519 cryptography
* 💪NaCl as base library for encryption implementation 
* 🔐Long term keys can be stored on hardware token
* 🔑Forward Secrecy (new key per connection)

# Getting Started
## Install
```bash
yarn add encrypted-stream
```

## Configuration
`encrypted-stream` protocol expects both sides to have assigned unique endpointId and Ed25519 key. Both sides have to know public key and endpointId of another.

## Server Engine
**ServerEngine can not be reused between connections**. Create a new one for each incoming connection.
### Keys
To create server you need a Ed25519 key that is stored persistently in some safe place. **Losing the key will lead to impossibility to connect to a server by clients.** Signer for this public key - a function that accepts buffer and creates a digital signature for it. For simplicity we provide `createSigner` function that creates this function from private key for you.
### Peer Resolver
`encrypted-stream` does not send public keys since it should have them already therefore to make everything work you need to provide a function (`endpointLookup` in example bellow) that resolves an endpointId to a publicKey or a null if endpoint is unknown.

### Example
```js
import { newEd25519Key, createSigner, ServerEngine } from 'encrypted-stream';

const ltsKey = newEd25519Key();
const ltsSigner = createSigner(ltsKey.secretKey);
const serverEndpointId = 'eego-RANDOM-ID';
const endpointLookup = (id: string) => resolveKeyByIdOrNull(id); 

const server = new ServerEngine({
  endpointId: serverEndpointId,
  publicKey: ltsKey.publicKey,
  signer: ltsSigner
}, endpointLookup);
```

## Client Engine
Client Engine is similar to Server one: you need Ed255519 key, endpoint ids and server keys.

```js
import { newEd25519Key, createSigner, ClientEngine } from 'encrypted-stream';

const clientLTSKey = newEd25519Key();
const clientLTSSigner = createSigner(clientLTSKey.secretKey);
const clientEndpointId = 'user1';
const serverEndpointId = 'eego-RANDOM-ID';
const serverPublicKey = ....;

const client = new ClientEngine({
  endpointId: clientEndpointId,
  publicKey: clientLTSKey.publicKey,
  signer: clientLTSSigner
}, { endpointId: serverEndpointId, publicKey: serverPublicKey });
```

## Handshake
Before being able to exchange encrypted messages handshake protocol must be executed. If any of the methods return null or false you can't use engine anymore - all methods will throw an error.

```js
// First create Client Hello message
let clientHello = client.getClientHello();

// Deliver to server and apply
if (!server.setClientHello(clientHello)) {
  throw Error('Invalid Client Hello');
}

// Create Server Hello message
let serverHello = server.getServerHello();

// Deliver to client and apply
if (!client.setServerHello(serverHello)) {
  throw Error('Invalid Server Hello');
}

// Create Peer Info message
let clientPeerInfo = client.getPeerInfo();

// Deliver Peer Info to server
if (!server.setPeerInfo(clientPeerInfo)) {
    throw Error('Invalid Peer Info');
}

// Here you can find connected endpointId
const endpointId = server.endpointId;
```

## Frame encryption and decryption
After a successful handshake encrypt and decrypt functions became available. `encrypted-stream` protocol requires **strict order** of decription of messages: they have to be decrypted in the same order as was encrypted. Incorrect order will lead to aborting engine. If decrypt method returns null then frame was invalid and engine is aborted.

```js
const chipherText = server.encrypt(Buffer.from('Hello World!', 'utf-8'));
const plainText = client.decrypt(encrypted);
console.lof(plainText!.toString('utf-8')); // Ouput: Hello World!
```

# License
[MIT](LICENSE)
