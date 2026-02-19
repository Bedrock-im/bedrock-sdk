# Bedrock SDK

TypeScript SDK for [Bedrock](https://bedrock.im) - decentralized cloud storage powered by [Aleph](https://aleph.im).

## Features

- End-to-end encryption (AES-256-CBC + ECIES)
- Works in Node.js and browser environments
- File management (upload, download, move, delete, share)
- Public file sharing without authentication
- Contact management with secure file sharing
- Knowledge bases (organize files into collections)
- Credit tracking
- Built on Aleph network, no central server
- Wallet integration (MetaMask, Rabby, WalletConnect, or private key)
- Full TypeScript type safety

## Installation

```bash
npm install bedrock-ts-sdk
```

## Quick Start

### Node.js

```typescript
import { BedrockClient } from 'bedrock-ts-sdk';

const client = await BedrockClient.fromPrivateKey('0x...');

// Upload a file
await client.files.uploadFiles([{
  name: 'hello.txt',
  path: '/documents/hello.txt',
  content: Buffer.from('Hello, Bedrock!'),
}]);

// List all files
const files = await client.files.listFiles();
console.log('Files:', files);
```

### Browser with MetaMask

```typescript
import { BedrockClient, BEDROCK_MESSAGE } from 'bedrock-ts-sdk';

const accounts = await window.ethereum.request({
  method: 'eth_requestAccounts'
});
const signature = await window.ethereum.request({
  method: 'personal_sign',
  params: [BEDROCK_MESSAGE, accounts[0]],
});

const client = await BedrockClient.fromSignature(signature, window.ethereum);
```

## Documentation

For full API reference, architecture details, and configuration options, visit the [Bedrock SDK Documentation](https://docs.bedrock.im/sdk/getting-started).

## License

MIT
