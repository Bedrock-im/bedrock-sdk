/**
 * Basic usage examples for Bedrock SDK
 *
 * To run this example:
 * 1. Set PRIVATE_KEY environment variable
 * 2. Run: npx tsx examples/basic-usage.ts
 */

import { BedrockClient } from '../src';

async function main() {
  // ============================================================================
  // 1. Initialize client
  // ============================================================================

  console.log('Initializing Bedrock client...');

  // Option A: From private key
  const privateKey = process.env.PRIVATE_KEY || '0x...';
  const client = await BedrockClient.fromPrivateKey(privateKey);

  // Option B: From wallet provider (in browser)
  // const client = await BedrockClient.fromProvider(window.ethereum);

  console.log('✓ Client initialized');
  console.log('Main address:', client.getMainAddress());
  console.log('Sub address:', client.getSubAddress());

  // ============================================================================
  // 2. File operations
  // ============================================================================

  console.log('\n--- File Operations ---');

  // Upload files
  console.log('Uploading files...');
  const files = await client.files.uploadFiles([
    {
      name: 'hello.txt',
      path: 'documents/hello.txt',
      content: Buffer.from('Hello, Bedrock!'),
    },
    {
      name: 'data.json',
      path: 'documents/data.json',
      content: Buffer.from(JSON.stringify({ message: 'Test data' })),
    },
  ]);
  console.log(`✓ Uploaded ${files.length} files`);

  // List files
  console.log('Listing files...');
  const allFiles = await client.files.listFiles();
  console.log(`✓ Found ${allFiles.length} files:`);
  allFiles.forEach(f => console.log(`  - ${f.path} (${f.size} bytes)`));

  // Download a file
  console.log('Downloading file...');
  const file = allFiles[0];
  const content = await client.files.downloadFile(file);
  console.log(`✓ Downloaded ${file.name}:`, content.toString());

  // Move/rename file
  console.log('Moving file...');
  await client.files.moveFiles([
    { oldPath: 'documents/hello.txt', newPath: 'archive/hello.txt' },
  ]);
  console.log('✓ File moved');

  // Duplicate file
  console.log('Duplicating file...');
  await client.files.duplicateFile('archive/hello.txt', 'archive/hello-copy.txt');
  console.log('✓ File duplicated');

  // Soft delete (move to trash)
  console.log('Soft deleting file...');
  await client.files.softDeleteFiles(['archive/hello-copy.txt']);
  console.log('✓ File soft deleted');

  // Restore from trash
  console.log('Restoring file...');
  await client.files.restoreFiles(['archive/hello-copy.txt']);
  console.log('✓ File restored');

  // Hard delete (permanent)
  console.log('Hard deleting file...');
  await client.files.hardDeleteFiles(['archive/hello-copy.txt']);
  console.log('✓ File permanently deleted');

  // ============================================================================
  // 3. Contact operations
  // ============================================================================

  console.log('\n--- Contact Operations ---');

  // Add contact
  console.log('Adding contact...');
  const contact = await client.contacts.addContact(
    'Alice',
    '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1',
    'public_key_here'
  );
  console.log('✓ Contact added:', contact.name);

  // List contacts
  console.log('Listing contacts...');
  const contacts = await client.contacts.listContacts();
  console.log(`✓ Found ${contacts.length} contacts`);

  // Share file with contact
  console.log('Sharing file with contact...');
  await client.contacts.shareFileWithContact('documents/data.json', contact.public_key);
  console.log('✓ File shared');

  // Get shared files
  console.log('Getting shared files...');
  const sharedFiles = await client.contacts.getSharedFiles(contact.public_key);
  console.log(`✓ ${sharedFiles.length} files shared with contact`);

  // Unshare file
  console.log('Unsharing file...');
  await client.contacts.unshareFileWithContact('documents/data.json', contact.public_key);
  console.log('✓ File unshared');

  // Update contact name
  console.log('Updating contact name...');
  await client.contacts.updateContactName(contact.public_key, 'Alice Smith');
  console.log('✓ Contact updated');

  // Remove contact
  console.log('Removing contact...');
  await client.contacts.removeContact(contact.public_key);
  console.log('✓ Contact removed');

  // ============================================================================
  // 4. Knowledge base operations
  // ============================================================================

  console.log('\n--- Knowledge Base Operations ---');

  // Create knowledge base
  console.log('Creating knowledge base...');
  const kb = await client.knowledgeBases.createKnowledgeBase('My Documents');
  console.log('✓ Knowledge base created:', kb.name);

  // Add files to knowledge base
  console.log('Adding files to knowledge base...');
  await client.knowledgeBases.addFiles('My Documents', [
    'documents/data.json',
    'archive/hello.txt',
  ]);
  console.log('✓ Files added');

  // List knowledge bases
  console.log('Listing knowledge bases...');
  const kbs = await client.knowledgeBases.listKnowledgeBases();
  console.log(`✓ Found ${kbs.length} knowledge bases`);
  kbs.forEach(k => console.log(`  - ${k.name} (${k.file_paths.length} files)`));

  // Remove file from knowledge base
  console.log('Removing file from knowledge base...');
  await client.knowledgeBases.removeFiles('My Documents', ['documents/data.json']);
  console.log('✓ File removed');

  // Rename knowledge base
  console.log('Renaming knowledge base...');
  await client.knowledgeBases.renameKnowledgeBase('My Documents', 'Archive');
  console.log('✓ Knowledge base renamed');

  // Delete knowledge base
  console.log('Deleting knowledge base...');
  await client.knowledgeBases.deleteKnowledgeBase('Archive');
  console.log('✓ Knowledge base deleted');

  // ============================================================================
  // 5. Cleanup (optional)
  // ============================================================================

  console.log('\n--- Cleanup ---');
  console.log('WARNING: Uncomment the following line to delete all data');
  // await client.resetAllData();
  // console.log('✓ All data deleted');

  console.log('\n✓ Example completed successfully!');
}

// Run the example
main().catch(console.error);
