import { BedrockCore, BedrockCoreConfig } from './client/bedrock-core';
import { FileService } from './services/file-service';
import { ContactService } from './services/contact-service';
import { KnowledgeBaseService } from './services/knowledge-base-service';
import { CreditService } from './services/credit-service';

/**
 * Main Bedrock SDK client
 *
 * @example
 * ```typescript
 * // Initialize from private key
 * const client = await BedrockClient.fromPrivateKey('0x...');
 *
 * // Initialize from wallet provider (MetaMask, etc.)
 * const client = await BedrockClient.fromProvider(window.ethereum);
 *
 * // Upload files
 * const files = await client.files.uploadFiles([
 *   { name: 'doc.txt', path: 'documents/doc.txt', content: buffer }
 * ]);
 *
 * // List files
 * const allFiles = await client.files.listFiles();
 *
 * // Add contact
 * await client.contacts.addContact('Alice', '0x...', 'publicKey');
 *
 * // Create knowledge base
 * await client.knowledgeBases.createKnowledgeBase('My Documents');
 *
 * // Check credit balance
 * const balance = await client.credits.getCreditBalance();
 *
 * // Share file publicly
 * const publicHash = await client.files.shareFilePublicly(file, 'username');
 * const meta = await FileService.fetchPublicFileMeta(publicHash);
 * const content = await FileService.downloadPublicFile(meta.store_hash);
 *
 * // Get files shared by contact
 * const sharedFiles = await client.contacts.fetchFilesSharedByContact(contactPubKey);
 * ```
 */
export class BedrockClient {
  private core: BedrockCore;

  /**
   * File operations service
   */
  public readonly files: FileService;

  /**
   * Contact management service
   */
  public readonly contacts: ContactService;

  /**
   * Knowledge base management service
   */
  public readonly knowledgeBases: KnowledgeBaseService;

  /**
   * Credit management service
   */
  public readonly credits: CreditService;

  private constructor(core: BedrockCore) {
    this.core = core;
    this.files = new FileService(core);
    this.contacts = new ContactService(core, this.files);
    this.knowledgeBases = new KnowledgeBaseService(core);
    this.credits = new CreditService(core);
  }

  /**
   * Create BedrockClient from a private key
   *
   * @param privateKey - Ethereum private key (hex string with or without 0x prefix)
   * @param config - Optional configuration
   * @returns Initialized BedrockClient
   *
   * @example
   * ```typescript
   * const client = await BedrockClient.fromPrivateKey('0xabc123...');
   * ```
   */
  static async fromPrivateKey(privateKey: string, config?: BedrockCoreConfig): Promise<BedrockClient> {
    const core = await BedrockCore.fromPrivateKey(privateKey, config);
    const client = new BedrockClient(core);
    await client.setup();
    return client;
  }

  /**
   * Create BedrockClient from a wallet provider (e.g., MetaMask)
   *
   * @param provider - EIP-1193 provider
   * @param config - Optional configuration
   * @returns Initialized BedrockClient
   *
   * @example
   * ```typescript
   * const client = await BedrockClient.fromProvider(window.ethereum);
   * ```
   */
  static async fromProvider(provider: any, config?: BedrockCoreConfig): Promise<BedrockClient> {
    const core = await BedrockCore.fromProvider(provider, config);
    const client = new BedrockClient(core);
    await client.setup();
    return client;
  }

  /**
   * Create BedrockClient from a signature hash
   *
   * @param signatureHash - Signature hash from wallet
   * @param provider - EIP-1193 provider
   * @param config - Optional configuration
   * @returns Initialized BedrockClient
   *
   * @example
   * ```typescript
   * const signature = await wallet.signMessage({ message: 'Bedrock.im' });
   * const client = await BedrockClient.fromSignature(signature, window.ethereum);
   * ```
   */
  static async fromSignature(signatureHash: string, provider: any, config?: BedrockCoreConfig): Promise<BedrockClient> {
    const core = await BedrockCore.fromSignature(signatureHash, provider, config);
    const client = new BedrockClient(core);
    await client.setup();
    return client;
  }

  /**
   * Get the main account address
   */
  getMainAddress(): string {
    return this.core.getMainAddress();
  }

  /**
   * Get the sub-account address
   */
  getSubAddress(): string {
    return this.core.getSubAddress();
  }

  /**
   * Get the account's public key
   */
  getPublicKey(): string {
    return this.core.getPublicKey();
  }

  /**
   * Get the encryption key (32 bytes derived from signature)
   */
  getEncryptionKey(): Buffer {
    return this.core.getEncryptionKey();
  }

  /**
   * Reset all data (files, contacts, knowledge bases)
   * WARNING: This will delete all user data from Aleph
   */
  async resetAllData(): Promise<void> {
    await Promise.all([this.resetFiles(), this.resetContacts(), this.resetKnowledgeBases()]);
  }

  /**
   * Reset all files
   * WARNING: This will delete all files from Aleph
   */
  async resetFiles(): Promise<void> {
    const aleph = this.core.getAlephService();
    await aleph.createAggregate(AGGREGATE_KEYS.FILE_ENTRIES, [] as any);
  }

  /**
   * Reset all contacts
   * WARNING: This will delete all contacts
   */
  async resetContacts(): Promise<void> {
    const aleph = this.core.getAlephService();
    await aleph.createAggregate(AGGREGATE_KEYS.CONTACTS, [] as any);
  }

  /**
   * Reset all knowledge bases
   * WARNING: This will delete all knowledge bases
   */
  async resetKnowledgeBases(): Promise<void> {
    const aleph = this.core.getAlephService();
    await aleph.createAggregate(AGGREGATE_KEYS.KNOWLEDGE_BASES, [] as any);
  }

  /**
   * Setup user profile at sub-account address
   * Call this after username registration
   * @param username - The registered username
   */
  async setupUserProfile(username: string): Promise<void> {
    const aleph = this.core.getAlephService();
    const publicKey = this.core.getPublicKey();

    await aleph.createAggregate(AGGREGATE_KEYS.USER_PROFILE, {
      username,
      public_key: publicKey,
    });
  }

  /**
   * Get user profile from an address
   * @param address - The address to fetch profile from
   */
  async getUserProfile(address: string): Promise<{ username?: string; public_key: string } | null> {
    const aleph = this.core.getAlephService();

    try {
      const profile = await aleph.fetchAggregate(AGGREGATE_KEYS.USER_PROFILE, UserProfileSchema, address);
      return profile;
    } catch {
      return null;
    }
  }

  // ============================================================================
  // Private methods
  // ============================================================================

  /**
   * Setup all services (create aggregates if they don't exist)
   */
  private async setup(): Promise<void> {
    await Promise.all([this.files.setup(), this.contacts.setup(), this.knowledgeBases.setup()]);
  }
}

// Re-export AGGREGATE_KEYS for use in reset methods
import { AGGREGATE_KEYS, UserProfileSchema } from './types/schemas';
