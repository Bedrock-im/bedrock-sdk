import { BedrockCore } from '../client/bedrock-core';
import { EncryptionService } from '../crypto/encryption';
import {
  FileEntry,
  FileMeta,
  FileFullInfo,
  FileMetaEncryptedSchema,
  FileEntriesAggregateSchema,
  PublicFileMeta,
  PublicFileMetaSchema,
  AGGREGATE_KEYS,
  POST_TYPES,
  ALEPH_GENERAL_CHANNEL,
} from '../types/schemas';
import { FileError, FileNotFoundError, EncryptionError } from '../types/errors';
import { AlephHttpClient } from '@aleph-sdk/client';

/**
 * File input type for uploads
 */
export interface FileInput {
  name: string;
  path: string;
  content: Buffer | File;
}

/**
 * File service for managing encrypted files
 */
export class FileService {
  private core: BedrockCore;

  constructor(core: BedrockCore) {
    this.core = core;
  }

  /**
   * Initialize file entries aggregate if it doesn't exist
   */
  async setup(): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      await aleph.fetchAggregate(
        AGGREGATE_KEYS.FILE_ENTRIES,
        FileEntriesAggregateSchema
      );
    } catch {
      // Create empty aggregate if it doesn't exist
      await aleph.createAggregate(AGGREGATE_KEYS.FILE_ENTRIES, { files: [] });
    }
  }

  /**
   * Upload files with encryption
   * @param files - Array of files to upload
   * @param directoryPath - Optional directory path prefix
   * @returns Array of uploaded file info
   */
  async uploadFiles(files: FileInput[], directoryPath: string = ''): Promise<FileFullInfo[]> {
    const aleph = this.core.getAlephService();
    const publicKey = this.core.getPublicKey();
    const uploadedFiles: FileFullInfo[] = [];

    try {
      for (const file of files) {
        // Generate encryption key and IV
        const key = EncryptionService.generateKey();
        const iv = EncryptionService.generateIv();

        // Encrypt file content
        let fileBuffer: Buffer;
        if (file.content instanceof Buffer) {
          fileBuffer = file.content;
        } else {
          // It's a File object
          const arrayBuffer = await (file.content as File).arrayBuffer();
          fileBuffer = Buffer.from(arrayBuffer);
        }
        const encryptedContent = await EncryptionService.encryptFile(fileBuffer, key, iv);

        // Upload encrypted file to Aleph STORE
        const storeResult = await aleph.uploadFile(encryptedContent);

        // Prepare file metadata
        const fullPath = directoryPath ? `${directoryPath}/${file.path}` : file.path;
        const createdAt = new Date().toISOString();

        const fileMeta: FileMeta = {
          name: file.name,
          path: fullPath,
          key: key.toString('hex'),
          iv: iv.toString('hex'),
          store_hash: storeResult.item_hash,
          size: fileBuffer.length,
          created_at: createdAt,
          deleted_at: null,
          shared_keys: {},
        };

        // Encrypt metadata
        const encryptedMeta = await this.encryptFileMeta(fileMeta);

        // Create POST message with encrypted metadata
        const postResult = await aleph.createPost(POST_TYPES.FILE, encryptedMeta);

        // Create file entry
        const encryptedPath = EncryptionService.encryptEcies(fullPath, publicKey);
        const fileEntry: FileEntry = {
          path: encryptedPath,
          post_hash: postResult.item_hash,
          shared_with: [],
        };

        uploadedFiles.push({ ...fileEntry, ...fileMeta });
      }

      // Save file entries to aggregate
      await this.saveFileEntries(uploadedFiles);

      return uploadedFiles;
    } catch (error) {
      throw new FileError(`Failed to upload files: ${(error as Error).message}`);
    }
  }

  /**
   * Download and decrypt a file
   * @param fileInfo - File information
   * @returns Decrypted file buffer
   */
  async downloadFile(fileInfo: FileFullInfo): Promise<Buffer> {
    const aleph = this.core.getAlephService();

    try {
      const key = Buffer.from(fileInfo.key, 'hex');
      const iv = Buffer.from(fileInfo.iv, 'hex');

      // Download encrypted file
      const encryptedContent = await aleph.downloadFile(fileInfo.store_hash);

      // Decrypt file
      const decryptedContent = await EncryptionService.decryptFile(encryptedContent, key, iv);

      return decryptedContent;
    } catch (error) {
      throw new FileError(`Failed to download file: ${(error as Error).message}`);
    }
  }

  /**
   * Fetch all file entries
   */
  async fetchFileEntries(): Promise<FileEntry[]> {
    const aleph = this.core.getAlephService();

    try {
      const aggregate = await aleph.fetchAggregate(
        AGGREGATE_KEYS.FILE_ENTRIES,
        FileEntriesAggregateSchema
      );
      return aggregate.files;
    } catch (error) {
      throw new FileError(`Failed to fetch file entries: ${(error as Error).message}`);
    }
  }

  /**
   * Fetch file metadata from entries
   * @param entries - File entries
   * @param owner - Optional owner address
   * @returns Array of full file info
   */
  async fetchFilesMetaFromEntries(entries: FileEntry[], owner?: string): Promise<FileFullInfo[]> {
    const aleph = this.core.getAlephService();
    const privateKey = owner ? undefined : this.core.getSubAccountPrivateKey();
    const files: FileFullInfo[] = [];

    try {
      for (const entry of entries) {
        try {
          // Fetch encrypted metadata from POST
          const encryptedMeta = await aleph.fetchPost(
            POST_TYPES.FILE,
            FileMetaEncryptedSchema,
            owner ? [owner] : undefined,
            entry.post_hash
          );

          // Decrypt metadata
          const decryptedMeta = await this.decryptFileMeta(encryptedMeta, privateKey);

          files.push({
            ...entry,
            ...decryptedMeta,
          });
        } catch (error) {
          // Skip files that can't be decrypted
          console.warn(`Failed to fetch metadata for ${entry.post_hash}:`, error);
        }
      }

      return files;
    } catch (error) {
      throw new FileError(`Failed to fetch files metadata: ${(error as Error).message}`);
    }
  }

  /**
   * List all files
   * @param includeDeleted - Include soft-deleted files
   */
  async listFiles(includeDeleted: boolean = false): Promise<FileFullInfo[]> {
    const entries = await this.fetchFileEntries();
    const files = await this.fetchFilesMetaFromEntries(entries);

    if (!includeDeleted) {
      return files.filter(f => !f.deleted_at);
    }

    return files;
  }

  /**
   * Get a file by path
   * @param path - File path
   */
  async getFile(path: string): Promise<FileFullInfo> {
    const files = await this.listFiles(true);
    const file = files.find(f => f.path === path);

    if (!file) {
      throw new FileNotFoundError(path);
    }

    return file;
  }

  /**
   * Soft delete files
   * @param filePaths - Paths of files to delete
   * @param deletionDate - Optional deletion date
   */
  async softDeleteFiles(filePaths: string[], deletionDate?: Date): Promise<void> {
    const aleph = this.core.getAlephService();
    const deletedAt = (deletionDate || new Date()).toISOString();

    try {
      for (const path of filePaths) {
        const file = await this.getFile(path);

        // Update metadata with deleted_at
        await aleph.updatePost(
          POST_TYPES.FILE,
          file.post_hash,
          [this.core.getMainAddress()],
          FileMetaEncryptedSchema,
          async (encryptedMeta) => {
            const decryptedMeta = await this.decryptFileMeta(encryptedMeta);
            decryptedMeta.deleted_at = deletedAt;
            return await this.encryptFileMeta(decryptedMeta);
          }
        );
      }
    } catch (error) {
      throw new FileError(`Failed to soft delete files: ${(error as Error).message}`);
    }
  }

  /**
   * Restore soft-deleted files
   * @param filePaths - Paths of files to restore
   */
  async restoreFiles(filePaths: string[]): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      for (const path of filePaths) {
        const file = await this.getFile(path);

        // Update metadata to remove deleted_at
        await aleph.updatePost(
          POST_TYPES.FILE,
          file.post_hash,
          [this.core.getMainAddress()],
          FileMetaEncryptedSchema,
          async (encryptedMeta) => {
            const decryptedMeta = await this.decryptFileMeta(encryptedMeta);
            decryptedMeta.deleted_at = null;
            return await this.encryptFileMeta(decryptedMeta);
          }
        );
      }
    } catch (error) {
      throw new FileError(`Failed to restore files: ${(error as Error).message}`);
    }
  }

  /**
   * Hard delete files (permanently remove from Aleph)
   * @param filePaths - Paths of files to delete
   */
  async hardDeleteFiles(filePaths: string[]): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      const files = await Promise.all(filePaths.map(path => this.getFile(path)));

      // Remove from file entries aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.FILE_ENTRIES,
        FileEntriesAggregateSchema,
        async (aggregate) => ({
          files: aggregate.files.filter(entry =>
            !files.some(f => f.post_hash === entry.post_hash)
          )
        })
      );

      // Forget STORE and POST messages
      const hashesToForget = files.flatMap(f => [f.store_hash, f.post_hash]);
      await aleph.deleteFiles(hashesToForget);
    } catch (error) {
      throw new FileError(`Failed to hard delete files: ${(error as Error).message}`);
    }
  }

  /**
   * Move/rename files
   * @param moves - Array of {oldPath, newPath} objects
   */
  async moveFiles(moves: Array<{ oldPath: string; newPath: string }>): Promise<void> {
    const aleph = this.core.getAlephService();
    const publicKey = this.core.getPublicKey();

    try {
      for (const { oldPath, newPath } of moves) {
        const file = await this.getFile(oldPath);

        // Update metadata with new path and name
        await aleph.updatePost(
          POST_TYPES.FILE,
          file.post_hash,
          [this.core.getMainAddress()],
          FileMetaEncryptedSchema,
          async (encryptedMeta) => {
            const decryptedMeta = await this.decryptFileMeta(encryptedMeta);
            decryptedMeta.path = newPath;
            decryptedMeta.name = newPath.split('/').pop() || newPath;
            return await this.encryptFileMeta(decryptedMeta);
          }
        );

        // Update file entry with new encrypted path
        const newEncryptedPath = EncryptionService.encryptEcies(newPath, publicKey);
        await aleph.updateAggregate(
          AGGREGATE_KEYS.FILE_ENTRIES,
          FileEntriesAggregateSchema,
          async (aggregate) => ({
            files: aggregate.files.map(entry =>
              entry.post_hash === file.post_hash
                ? { ...entry, path: newEncryptedPath }
                : entry
            )
          })
        );
      }
    } catch (error) {
      throw new FileError(`Failed to move files: ${(error as Error).message}`);
    }
  }

  /**
   * Duplicate a file
   * @param sourcePath - Source file path
   * @param newPath - New file path
   */
  async duplicateFile(sourcePath: string, newPath: string): Promise<FileFullInfo> {
    try {
      const sourceFile = await this.getFile(sourcePath);
      const content = await this.downloadFile(sourceFile);

      const [newFile] = await this.uploadFiles([{
        name: newPath.split('/').pop() || newPath,
        path: newPath,
        content,
      }]);

      return newFile;
    } catch (error) {
      throw new FileError(`Failed to duplicate file: ${(error as Error).message}`);
    }
  }

  /**
   * Share a file with a contact
   * @param filePath - File path
   * @param contactPublicKey - Contact's public key
   */
  async shareFile(filePath: string, contactPublicKey: string): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      const file = await this.getFile(filePath);

      // Encrypt file key and IV with contact's public key
      const encryptedKey = EncryptionService.encryptEcies(file.key, contactPublicKey);
      const encryptedIv = EncryptionService.encryptEcies(file.iv, contactPublicKey);

      // Update metadata with shared keys
      await aleph.updatePost(
        POST_TYPES.FILE,
        file.post_hash,
        [this.core.getMainAddress()],
        FileMetaEncryptedSchema,
        async (encryptedMeta) => {
          const decryptedMeta = await this.decryptFileMeta(encryptedMeta);
          decryptedMeta.shared_keys[contactPublicKey] = {
            key: encryptedKey,
            iv: encryptedIv,
          };
          return await this.encryptFileMeta(decryptedMeta);
        }
      );

      // Update file entry shared_with list
      await aleph.updateAggregate(
        AGGREGATE_KEYS.FILE_ENTRIES,
        FileEntriesAggregateSchema,
        async (aggregate) => ({
          files: aggregate.files.map(entry =>
            entry.post_hash === file.post_hash
              ? { ...entry, shared_with: [...new Set([...entry.shared_with, contactPublicKey])] }
              : entry
          )
        })
      );
    } catch (error) {
      throw new FileError(`Failed to share file: ${(error as Error).message}`);
    }
  }

  /**
   * Unshare a file with a contact
   * @param filePath - File path
   * @param contactPublicKey - Contact's public key
   */
  async unshareFile(filePath: string, contactPublicKey: string): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      const file = await this.getFile(filePath);

      // Remove shared keys from metadata
      await aleph.updatePost(
        POST_TYPES.FILE,
        file.post_hash,
        [this.core.getMainAddress()],
        FileMetaEncryptedSchema,
        async (encryptedMeta) => {
          const decryptedMeta = await this.decryptFileMeta(encryptedMeta);
          delete decryptedMeta.shared_keys[contactPublicKey];
          return await this.encryptFileMeta(decryptedMeta);
        }
      );

      // Update file entry shared_with list
      await aleph.updateAggregate(
        AGGREGATE_KEYS.FILE_ENTRIES,
        FileEntriesAggregateSchema,
        async (aggregate) => ({
          files: aggregate.files.map(entry =>
            entry.post_hash === file.post_hash
              ? { ...entry, shared_with: entry.shared_with.filter(pk => pk !== contactPublicKey) }
              : entry
          )
        })
      );
    } catch (error) {
      throw new FileError(`Failed to unshare file: ${(error as Error).message}`);
    }
  }

  /**
   * Share a file publicly (unencrypted, anyone can access)
   * @param fileInfo - File to share publicly
   * @param username - Username for attribution
   * @returns Public post hash for sharing
   */
  async shareFilePublicly(fileInfo: FileFullInfo, username: string): Promise<string> {
    const aleph = this.core.getAlephService();

    try {
      // Download and decrypt file
      const decryptedContent = await this.downloadFile(fileInfo);

      // Re-upload without encryption
      const storeResult = await aleph.uploadFile(decryptedContent);

      // Create public metadata
      const publicMeta: PublicFileMeta = {
        name: fileInfo.name,
        size: fileInfo.size,
        created_at: new Date().toISOString(),
        store_hash: storeResult.item_hash,
        username,
      };

      // Create public POST
      const postResult = await aleph.createPost(POST_TYPES.PUBLIC_FILE, publicMeta);

      return postResult.item_hash;
    } catch (error) {
      throw new FileError(`Failed to share file publicly: ${(error as Error).message}`);
    }
  }

  /**
   * Fetch public file metadata (static - no auth required)
   * @param postHash - Public post hash
   * @returns Public file metadata or null if not found
   */
  static async fetchPublicFileMeta(postHash: string): Promise<PublicFileMeta | null> {
    try {
      const client = new AlephHttpClient('https://api2.aleph.im');
      const post = await client.getPost({
        channels: [ALEPH_GENERAL_CHANNEL],
        types: [POST_TYPES.PUBLIC_FILE],
        hashes: [postHash],
      });

      return PublicFileMetaSchema.parse(post.content);
    } catch {
      return null;
    }
  }

  /**
   * Download public file (static - no auth required)
   * @param storeHash - Store hash from public metadata
   * @returns File content as ArrayBuffer
   */
  static async downloadPublicFile(storeHash: string): Promise<ArrayBuffer> {
    try {
      const client = new AlephHttpClient('https://api2.aleph.im');
      return await client.downloadFile(storeHash);
    } catch (error) {
      throw new FileError(`Failed to download public file: ${(error as Error).message}`);
    }
  }

  // ============================================================================
  // Private helper methods
  // ============================================================================

  private async saveFileEntries(files: FileFullInfo[]): Promise<void> {
    const aleph = this.core.getAlephService();

    await aleph.updateAggregate(
      AGGREGATE_KEYS.FILE_ENTRIES,
      FileEntriesAggregateSchema,
      async (aggregate) => {
        const newEntries = files.map(f => ({
          path: f.path,
          post_hash: f.post_hash,
          shared_with: f.shared_with || [],
        }));
        return { files: [...aggregate.files, ...newEntries] };
      }
    );
  }

  private async encryptFileMeta(meta: FileMeta): Promise<any> {
    const key = this.core.getEncryptionKey();
    const iv = EncryptionService.generateIv();
    const publicKey = this.core.getPublicKey();

    return {
      name: await EncryptionService.encrypt(meta.name, key, iv),
      path: EncryptionService.encryptEcies(meta.path, publicKey),
      key: EncryptionService.encryptEcies(meta.key, publicKey),
      iv: EncryptionService.encryptEcies(meta.iv, publicKey),
      store_hash: meta.store_hash,
      size: await EncryptionService.encrypt(meta.size.toString(), key, iv),
      created_at: await EncryptionService.encrypt(meta.created_at, key, iv),
      deleted_at: meta.deleted_at ? await EncryptionService.encrypt(meta.deleted_at, key, iv) : null,
      shared_keys: meta.shared_keys,
    };
  }

  private async decryptFileMeta(encryptedMeta: any, privateKey?: string): Promise<FileMeta> {
    const key = this.core.getEncryptionKey();
    const iv = EncryptionService.generateIv();
    const privKey = privateKey || this.core.getSubAccountPrivateKey();

    if (!privKey) {
      throw new EncryptionError('Private key not available');
    }

    return {
      name: await EncryptionService.decrypt(encryptedMeta.name, key, iv),
      path: EncryptionService.decryptEcies(encryptedMeta.path, privKey),
      key: EncryptionService.decryptEcies(encryptedMeta.key, privKey),
      iv: EncryptionService.decryptEcies(encryptedMeta.iv, privKey),
      store_hash: encryptedMeta.store_hash,
      size: parseInt(await EncryptionService.decrypt(encryptedMeta.size, key, iv)),
      created_at: await EncryptionService.decrypt(encryptedMeta.created_at, key, iv),
      deleted_at: encryptedMeta.deleted_at ? await EncryptionService.decrypt(encryptedMeta.deleted_at, key, iv) : null,
      shared_keys: encryptedMeta.shared_keys || {},
    };
  }
}
