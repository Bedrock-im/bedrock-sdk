import { AuthenticatedAlephHttpClient } from '@aleph-sdk/client';
import type { ETHAccount } from '@aleph-sdk/ethereum';
import { AggregateMessage, ForgetMessage, ItemType, PostMessage, StoreMessage } from '@aleph-sdk/message';
import { z } from 'zod';
import { NetworkError } from '../types/errors';
import { ALEPH_GENERAL_CHANNEL } from '../types/schemas';

/**
 * Low-level Aleph SDK wrapper (matches Bedrock implementation)
 */
export class AlephService {
  private readonly subAccountClient: AuthenticatedAlephHttpClient;
  private readonly account: ETHAccount;
  private readonly channel: string;

  constructor(
    account: ETHAccount,
    channel: string = ALEPH_GENERAL_CHANNEL,
    apiServer: string = 'https://api2.aleph.im'
  ) {
    this.account = account;
    this.channel = channel;
    this.subAccountClient = new AuthenticatedAlephHttpClient(account, apiServer);
  }

  /**
   * Get the account address
   */
  getAddress(): string {
    return this.account.address;
  }

  /**
   * Get the account's public key
   */
  getPublicKey(): string {
    return this.account.publicKey || '';
  }

  /**
   * Get the underlying Aleph client
   */
  getClient(): AuthenticatedAlephHttpClient {
    return this.subAccountClient;
  }

  /**
   * Get the account
   */
  getAccount(): ETHAccount {
    return this.account;
  }

  // ============================================================================
  // STORE operations (file storage)
  // ============================================================================

  /**
   * Upload a file to Aleph storage
   * @param fileObject - File content as Buffer or File
   * @returns Store message
   */
  async uploadFile(fileObject: Buffer | File): Promise<StoreMessage> {
    try {
      return await this.subAccountClient.createStore({
        fileObject,
        storageEngine: ItemType.ipfs,
        channel: this.channel,
      });
    } catch (error) {
      throw new NetworkError(`Failed to upload file: ${(error as Error).message}`);
    }
  }

  /**
   * Download a file from Aleph storage
   * @param storeHash - The STORE message item_hash
   * @returns File content as ArrayBuffer
   */
  async downloadFile(storeHash: string): Promise<ArrayBuffer> {
    try {
      const ipfsHash = await this.subAccountClient.getMessage(storeHash);
      const ContentSchema = z.object({
        address: z.string(),
        item_type: z.string(),
        item_hash: z.string(),
        time: z.number(),
      });
      const { success, data } = ContentSchema.safeParse(ipfsHash.content);
      if (!success) throw new Error(`Invalid data from Aleph: ${data}`);
      return this.subAccountClient.downloadFile(data.item_hash);
    } catch (error) {
      throw new NetworkError(`Failed to download file ${storeHash}: ${(error as Error).message}`);
    }
  }

  /**
   * Delete files from Aleph storage
   * @param itemHashes - Array of item hashes to forget
   * @returns Forget message
   */
  async deleteFiles(itemHashes: string[]): Promise<ForgetMessage> {
    try {
      return this.subAccountClient.forget({ hashes: itemHashes });
    } catch (error) {
      throw new NetworkError(`Failed to delete files: ${(error as Error).message}`);
    }
  }

  // ============================================================================
  // AGGREGATE operations (key-value storage)
  // ============================================================================

  async createAggregate<T extends Record<string, unknown>>(key: string, content: T): Promise<AggregateMessage<T>> {
    try {
      return this.subAccountClient.createAggregate({
        key,
        content,
        channel: this.channel,
        address: this.account.address,
      });
    } catch (error) {
      throw new NetworkError(`Failed to create aggregate: ${(error as Error).message}`);
    }
  }

  async fetchAggregate<T extends z.ZodTypeAny>(key: string, schema: T, owner: string = this.account.address) {
    try {
      const unparsedData = await this.subAccountClient.fetchAggregate(owner, key);
      const { success, data, error } = schema.safeParse(unparsedData);
      if (!success)
        throw new Error(`Invalid data from Aleph: ${error.message}, data was ${JSON.stringify(unparsedData)}`);
      return data as z.infer<T>;
    } catch (error) {
      throw new NetworkError(`Failed to fetch aggregate: ${(error as Error).message}`);
    }
  }

  async updateAggregate<S extends z.ZodTypeAny, T extends z.infer<S>>(
    key: string,
    schema: S,
    update_content: (content: T) => Promise<T>
  ): Promise<AggregateMessage<T>> {
    try {
      const currentContent = await this.fetchAggregate(key, schema);
      const newContent = await update_content(currentContent);
      return await this.createAggregate(key, newContent);
    } catch (error) {
      throw new NetworkError(`Failed to update aggregate: ${(error as Error).message}`);
    }
  }

  // ============================================================================
  // POST operations (JSON messages)
  // ============================================================================

  async createPost<T extends Record<string, unknown>>(type: string, content: T): Promise<PostMessage<T>> {
    try {
      return this.subAccountClient.createPost({
        postType: type,
        content,
        channel: this.channel,
        address: this.account.address,
      });
    } catch (error) {
      throw new NetworkError(`Failed to create post: ${(error as Error).message}`);
    }
  }

  async fetchPosts<T extends z.ZodTypeAny>(
    type: string,
    schema: T,
    addresses: string[] = [this.account.address],
    hashes: string[] = []
  ) {
    try {
      return z.array(schema).parse(
        (
          await this.subAccountClient.getPosts({
            channels: [this.channel],
            types: [type],
            addresses,
            hashes,
          })
        ).posts.map((post) => post.content)
      ) as z.infer<T>[];
    } catch (error) {
      throw new NetworkError(`Failed to fetch posts: ${(error as Error).message}`);
    }
  }

  async fetchPost<T extends z.ZodTypeAny>(
    type: string,
    schema: T,
    addresses: string[] = [this.account.address],
    hash: string
  ) {
    try {
      return schema.parse(
        (
          await this.subAccountClient.getPost({
            channels: [this.channel],
            types: [type],
            addresses,
            hashes: [hash],
          })
        ).content
      ) as z.infer<T>;
    } catch (error) {
      throw new NetworkError(`Failed to fetch post: ${(error as Error).message}`);
    }
  }

  async updatePost<S extends z.ZodTypeAny, T extends z.infer<S>>(
    type: string,
    hash: string,
    addresses: string[],
    schema: S,
    update_content: (content: T) => Promise<T>
  ): Promise<PostMessage<T>> {
    try {
      const currentContent = await this.fetchPost(type, schema, addresses, hash);
      const newContent = await update_content(currentContent);
      return await this.subAccountClient.createPost({
        postType: type,
        content: newContent,
        ref: hash,
        channel: this.channel,
        address: this.account.address,
      });
    } catch (error) {
      throw new NetworkError(`Failed to update post: ${(error as Error).message}`);
    }
  }
}
