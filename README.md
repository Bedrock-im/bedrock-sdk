# Bedrock SDK

TypeScript SDK for [Bedrock](https://bedrock.im) - decentralized cloud storage powered by [Aleph](https://aleph.im).

## Features

- 🔐 **End-to-end encryption** - All files and metadata encrypted with AES-256-CBC + ECIES
- 🌐 **Universal** - Works in Node.js and browser environments
- 📁 **File management** - Upload, download, move, delete (soft/hard), share files
- 🔗 **Public sharing** - Share files publicly without authentication
- 👥 **Contact management** - Manage contacts and share files securely
- 🧠 **Knowledge bases** - Organize files into collections
- 💳 **Credit tracking** - Monitor usage credits and transaction history
- ⚡ **Decentralized** - Built on Aleph network, no central server
- 🔑 **Wallet integration** - MetaMask, Rabby, WalletConnect, or private key
- 📦 **TypeScript** - Full type safety with TypeScript

## Installation

```bash
npm install bedrock-ts-sdk
```

## Quick Start

### Node.js

```typescript
import { BedrockClient } from 'bedrock-ts-sdk';

// Initialize from private key
const client = await BedrockClient.fromPrivateKey('0x...');

// Upload a file
const files = await client.files.uploadFiles([{
  name: 'hello.txt',
  path: '/documents/hello.txt',
  content: Buffer.from('Hello, Bedrock!'),
}]);

// List all files
const allFiles = await client.files.listFiles();
console.log('Files:', allFiles);

// Download a file
const content = await client.files.downloadFile(allFiles[0]);
console.log('Content:', content.toString());
```

### Browser with MetaMask

```typescript
import { BedrockClient, BEDROCK_MESSAGE } from 'bedrock-ts-sdk';

// Request signature from MetaMask
const accounts = await window.ethereum.request({
  method: 'eth_requestAccounts'
});
const signature = await window.ethereum.request({
  method: 'personal_sign',
  params: [BEDROCK_MESSAGE, accounts[0]],
});

// Initialize client with signature
const client = await BedrockClient.fromSignature(
  signature,
  window.ethereum
);

// Upload a file from user input
const fileInput = document.querySelector('input[type="file"]');
const file = fileInput.files[0];
const buffer = Buffer.from(await file.arrayBuffer());

await client.files.uploadFiles([{
  name: file.name,
  path: `/uploads/${file.name}`,
  content: buffer,
}]);
```

## API Reference

### Initialization

#### `BedrockClient.fromPrivateKey(privateKey, config?)`

Create client from Ethereum private key.

```typescript
const client = await BedrockClient.fromPrivateKey('0xabc123...');
```

#### `BedrockClient.fromProvider(provider, config?)`

Create client from wallet provider (MetaMask, WalletConnect, etc.).

```typescript
const client = await BedrockClient.fromProvider(window.ethereum);
```

#### `BedrockClient.fromSignature(signatureHash, provider, config?)`

Create client from wallet signature (recommended for web apps).

```typescript
// User signs message with wallet
const signature = await wallet.signMessage({ message: 'Bedrock.im' });
const client = await BedrockClient.fromSignature(
  signature,
  window.ethereum,
  { apiServer: 'https://api2.aleph.im' }
);
```

### File Operations

#### Upload Files

```typescript
const files = await client.files.uploadFiles([
  {
    name: 'document.pdf',
    path: '/documents/document.pdf',
    content: fileBuffer, // Buffer or File
  },
  {
    name: 'image.jpg',
    path: '/images/image.jpg',
    content: imageBuffer,
  },
]);
```

#### List Files

```typescript
// List all non-deleted files
const files = await client.files.listFiles();

// Include soft-deleted files
const allFiles = await client.files.listFiles(true);
```

#### Get File by Path

```typescript
const file = await client.files.getFile('documents/document.pdf');
console.log(file.name, file.size, file.created_at);
```

#### Download File

```typescript
const file = await client.files.getFile('documents/document.pdf');
const content = await client.files.downloadFile(file);

// Save to disk (Node.js)
fs.writeFileSync('downloaded.pdf', content);

// Create download link (Browser)
const blob = new Blob([content]);
const url = URL.createObjectURL(blob);
```

#### Move/Rename Files

```typescript
await client.files.moveFiles([
  { oldPath: 'old/path.txt', newPath: 'new/path.txt' },
  { oldPath: 'doc.pdf', newPath: 'documents/doc.pdf' },
]);
```

#### Duplicate File

```typescript
await client.files.duplicateFile('original.txt', 'copy.txt');
```

#### Soft Delete (Trash)

```typescript
// Move to trash
await client.files.softDeleteFiles(['path/to/file.txt']);

// Restore from trash
await client.files.restoreFiles(['path/to/file.txt']);
```

#### Hard Delete (Permanent)

```typescript
// WARNING: This permanently removes files from Aleph network
await client.files.hardDeleteFiles(['path/to/file.txt']);
```

#### Share Files

```typescript
// Share with a contact
await client.files.shareFile('document.pdf', contactPublicKey);

// Unshare
await client.files.unshareFile('document.pdf', contactPublicKey);
```

#### Public File Sharing

```typescript
// Share file publicly (anyone can access without authentication)
const file = await client.files.getFile('document.pdf');
const publicHash = await client.files.shareFilePublicly(file, 'username');

console.log(`Share this link: https://app.bedrock.im/public/${publicHash}`);

// Fetch public file metadata (static method - no auth needed)
import { FileService } from 'bedrock-ts-sdk';
const metadata = await FileService.fetchPublicFileMeta(publicHash);
console.log(metadata.name, metadata.size, metadata.username);

// Download public file (static method - no auth needed)
const content = await FileService.downloadPublicFile(metadata.store_hash);
```

### Contact Operations

#### Add Contact

```typescript
const contact = await client.contacts.addContact(
  'Alice',                                      // Name
  '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1', // Address
  'public_key_hex'                              // Public key
);
```

#### List Contacts

```typescript
const contacts = await client.contacts.listContacts();
contacts.forEach(c => {
  console.log(c.name, c.address, c.public_key);
});
```

#### Get Contact

```typescript
// By public key
const contact = await client.contacts.getContact(publicKey);

// By address
const contact = await client.contacts.getContactByAddress('0x...');
```

#### Update Contact

```typescript
await client.contacts.updateContactName(publicKey, 'Alice Smith');
```

#### Remove Contact

```typescript
await client.contacts.removeContact(publicKey);
```

#### Share Files with Contact

```typescript
// Share
await client.contacts.shareFileWithContact('file.pdf', publicKey);

// Get files you shared with a contact
const sharedFiles = await client.contacts.getSharedFiles(publicKey);

// Get files a contact shared with you
const receivedFiles = await client.contacts.fetchFilesSharedByContact(publicKey);

// Unshare
await client.contacts.unshareFileWithContact('file.pdf', publicKey);
```

### Knowledge Base Operations

#### Create Knowledge Base

```typescript
const kb = await client.knowledgeBases.createKnowledgeBase('My Documents');

// With initial files
const kb = await client.knowledgeBases.createKnowledgeBase(
  'Research Papers',
  ['paper1.pdf', 'paper2.pdf']
);
```

#### List Knowledge Bases

```typescript
const kbs = await client.knowledgeBases.listKnowledgeBases();
kbs.forEach(kb => {
  console.log(kb.name, kb.file_paths.length);
});
```

#### Get Knowledge Base

```typescript
const kb = await client.knowledgeBases.getKnowledgeBase('My Documents');
```

#### Rename Knowledge Base

```typescript
await client.knowledgeBases.renameKnowledgeBase('Old Name', 'New Name');
```

#### Manage Files in Knowledge Base

```typescript
// Set files (replaces all)
await client.knowledgeBases.setFiles('My KB', ['file1.txt', 'file2.txt']);

// Add files
await client.knowledgeBases.addFiles('My KB', ['file3.txt']);

// Remove files
await client.knowledgeBases.removeFiles('My KB', ['file1.txt']);

// Clear all files
await client.knowledgeBases.clearFiles('My KB');
```

#### Delete Knowledge Base

```typescript
await client.knowledgeBases.deleteKnowledgeBase('My Documents');
```

### Credit Operations

The credit system is backend-managed (read-only from SDK).

#### Get Credit Balance

```typescript
const credits = await client.credits.getCreditBalance();

console.log('Balance:', credits.balance);
console.log('Transactions:', credits.transactions);

// Transaction history
credits.transactions.forEach(tx => {
  console.log(tx.type, tx.amount, tx.description, tx.timestamp);
});
```

**Note:** Credits are managed by the backend. Users cannot modify their balance via the SDK. The backend maintains a credit aggregate with user balances and transaction history.

### Utility Methods

#### Get Account Info

```typescript
const mainAddress = client.getMainAddress();
const subAddress = client.getSubAddress();
const publicKey = client.getPublicKey();
const encryptionKey = client.getEncryptionKey();
```

#### Reset Data

```typescript
// WARNING: These operations permanently delete data

// Reset all data
await client.resetAllData();

// Reset specific data types
await client.resetFiles();
await client.resetContacts();
await client.resetKnowledgeBases();
```

## Architecture

### Encryption

Bedrock uses a dual encryption approach:

1. **File content**: Encrypted with AES-256-CBC using random key/IV
2. **File paths**: Encrypted with ECIES using user's public key
3. **Metadata**: Encrypted with AES-256-CBC using signature-derived key
4. **Shared keys**: Encrypted with ECIES using recipient's public key

### Sub-accounts

- Main account signs a message to generate a signature
- Signature is used to derive encryption key and sub-account
- Sub-account is authorized via Aleph security aggregate
- All operations use the sub-account for better security

### Aleph Storage

- **STORE**: Binary file content (encrypted)
- **POST**: File metadata (encrypted)
- **AGGREGATE**: File index, contacts, knowledge bases
- **FORGET**: Delete messages from network

## Configuration

```typescript
const client = await BedrockClient.fromPrivateKey(privateKey, {
  channel: 'MY_CUSTOM_CHANNEL',        // Default: 'bedrock'
  apiServer: 'https://api2.aleph.im',  // Default: 'https://api2.aleph.im'
});
```

**Configuration Options:**
- `channel`: Aleph channel for data isolation (default: `'bedrock'`)
- `apiServer`: Aleph API server URL (default: `'https://api2.aleph.im'`)

## Development

### Setup

```bash
# Install dependencies
npm install

# Build
npm run build

# Watch mode
npm run dev

# Run tests
npm test

# Type check
npm run typecheck
```

### Project Structure

```
bedrock-sdk/
├── src/
│   ├── bedrock-client.ts    # Main client interface
│   ├── client/              # Core client & Aleph service
│   ├── services/            # File, Contact, KB services
│   ├── crypto/              # Encryption utilities
│   ├── types/               # TypeScript types & schemas
│   └── index.ts             # Public API exports
├── tests/                   # Unit tests
├── examples/                # Usage examples
└── package.json
```

## Examples

See the [examples/](./examples) directory:

- [basic-usage.ts](./examples/basic-usage.ts) - Complete Node.js example
- [browser-usage.html](./examples/browser-usage.html) - Interactive browser demo

## Error Handling

The SDK provides typed errors:

```typescript
import {
  BedrockError,
  AuthenticationError,
  EncryptionError,
  FileError,
  FileNotFoundError,
  ContactError,
  KnowledgeBaseError,
  CreditError,
  NetworkError,
  ValidationError,
} from 'bedrock-ts-sdk';

try {
  await client.files.getFile('nonexistent.txt');
} catch (error) {
  if (error instanceof FileNotFoundError) {
    console.log('File not found:', error.message);
  } else if (error instanceof NetworkError) {
    console.log('Network error:', error.message);
  } else if (error instanceof CreditError) {
    console.log('Credit operation failed:', error.message);
  }
}
```

## Browser Compatibility

The SDK works in modern browsers with:

- WebCrypto API (for encryption)
- BigInt support
- ES2020+ features

Tested on:
- Chrome 90+
- Firefox 90+
- Safari 14+
- Edge 90+

## Security Considerations

- Private keys are never sent over the network
- All file content is encrypted before upload
- File paths are encrypted to hide folder structure
- Metadata is encrypted with signature-derived key
- Use HTTPS/secure connections in production
- Keep private keys secure and never commit them

## License

MIT

## Contributing

Contributions welcome! Please open an issue or PR.

## Support

- Documentation: [https://docs.bedrock.im](https://docs.bedrock.im)
- Issues: [GitHub Issues](https://github.com/bedrock-im/bedrock-sdk/issues)
- Aleph Docs: [https://docs.aleph.cloud](https://docs.aleph.cloud)

## Acknowledgments

Built on [Aleph](https://aleph.cloud) decentralized network.
