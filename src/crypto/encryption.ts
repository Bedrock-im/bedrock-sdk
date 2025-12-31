import { encrypt as eciesEncrypt, decrypt as eciesDecrypt } from 'eciesjs';
import { EncryptionError } from '../types/errors';

/**
 * Universal crypto utilities that work in both Node.js and browser
 */
class CryptoUtils {
  static isBrowser = typeof window !== 'undefined' && typeof window.crypto !== 'undefined';

  /**
   * Get crypto implementation (Node.js or browser)
   */
  static getCrypto() {
    if (this.isBrowser) {
      return window.crypto;
    }
    // Node.js
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const nodeCrypto = require('crypto');
    return nodeCrypto.webcrypto || nodeCrypto;
  }

  /**
   * Generate random bytes
   */
  static getRandomBytes(length: number): Uint8Array {
    const crypto = this.getCrypto();
    const bytes = new Uint8Array(length);

    if (this.isBrowser) {
      crypto.getRandomValues(bytes);
    } else {
      // Node.js
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('crypto');
      const randomBytes = nodeCrypto.randomBytes(length);
      bytes.set(randomBytes);
    }

    return bytes;
  }

  /**
   * Convert buffer to hex string
   */
  static bufferToHex(buffer: Buffer | Uint8Array): string {
    return Buffer.from(buffer).toString('hex');
  }

  /**
   * Convert hex string to buffer
   */
  static hexToBuffer(hex: string): Buffer {
    return Buffer.from(hex, 'hex');
  }

  /**
   * Hash using SHA-256
   */
  static async sha256(data: string | Buffer): Promise<Buffer> {
    const bytes = typeof data === 'string' ? Buffer.from(data, 'utf-8') : data;

    if (this.isBrowser) {
      const crypto = this.getCrypto();
      const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
      return Buffer.from(hashBuffer);
    } else {
      // Node.js
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const nodeCrypto = require('crypto');
      return nodeCrypto.createHash('sha256').update(bytes).digest();
    }
  }
}

/**
 * Encryption service for AES-256-CBC and ECIES operations
 */
export class EncryptionService {
  /**
   * Generate a random encryption key (32 bytes for AES-256)
   */
  static generateKey(): Buffer {
    return Buffer.from(CryptoUtils.getRandomBytes(32));
  }

  /**
   * Generate a random initialization vector (16 bytes for AES)
   */
  static generateIv(): Buffer {
    return Buffer.from(CryptoUtils.getRandomBytes(16));
  }

  /**
   * Encrypt data using AES-256-CBC
   * @param data - Data to encrypt
   * @param key - 32-byte encryption key
   * @param iv - 16-byte initialization vector
   * @returns Hex-encoded encrypted data
   */
  static async encrypt(data: string, key: Buffer, iv: Buffer): Promise<string> {
    try {
      if (key.length !== 32) {
        throw new EncryptionError('Key must be 32 bytes for AES-256');
      }
      if (iv.length !== 16) {
        throw new EncryptionError('IV must be 16 bytes');
      }

      if (CryptoUtils.isBrowser) {
        return await this.encryptBrowser(data, key, iv);
      } else {
        return this.encryptNode(data, key, iv);
      }
    } catch (error) {
      throw new EncryptionError(`Encryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decrypt data using AES-256-CBC
   * @param encryptedData - Hex-encoded encrypted data
   * @param key - 32-byte encryption key
   * @param iv - 16-byte initialization vector
   * @returns Decrypted string
   */
  static async decrypt(encryptedData: string, key: Buffer, iv: Buffer): Promise<string> {
    try {
      if (key.length !== 32) {
        throw new EncryptionError('Key must be 32 bytes for AES-256');
      }
      if (iv.length !== 16) {
        throw new EncryptionError('IV must be 16 bytes');
      }

      if (CryptoUtils.isBrowser) {
        return await this.decryptBrowser(encryptedData, key, iv);
      } else {
        return this.decryptNode(encryptedData, key, iv);
      }
    } catch (error) {
      throw new EncryptionError(`Decryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Encrypt file buffer using AES-256-CBC
   * @param fileBuffer - File data as Buffer or ArrayBuffer
   * @param key - 32-byte encryption key
   * @param iv - 16-byte initialization vector
   * @returns Encrypted file buffer
   */
  static async encryptFile(
    fileBuffer: Buffer | ArrayBuffer,
    key: Buffer,
    iv: Buffer
  ): Promise<Buffer> {
    try {
      const buffer = Buffer.isBuffer(fileBuffer) ? fileBuffer : Buffer.from(fileBuffer);

      if (CryptoUtils.isBrowser) {
        return await this.encryptFileBrowser(buffer, key, iv);
      } else {
        return this.encryptFileNode(buffer, key, iv);
      }
    } catch (error) {
      throw new EncryptionError(`File encryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decrypt file buffer using AES-256-CBC
   * @param encryptedBuffer - Encrypted file data
   * @param key - 32-byte encryption key
   * @param iv - 16-byte initialization vector
   * @returns Decrypted file buffer
   */
  static async decryptFile(
    encryptedBuffer: Buffer | ArrayBuffer,
    key: Buffer,
    iv: Buffer
  ): Promise<Buffer> {
    try {
      const buffer = Buffer.isBuffer(encryptedBuffer) ? encryptedBuffer : Buffer.from(encryptedBuffer);

      if (CryptoUtils.isBrowser) {
        return await this.decryptFileBrowser(buffer, key, iv);
      } else {
        return this.decryptFileNode(buffer, key, iv);
      }
    } catch (error) {
      throw new EncryptionError(`File decryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Encrypt data using ECIES (Elliptic Curve Integrated Encryption Scheme)
   * @param data - Data to encrypt
   * @param publicKey - Recipient's public key (hex or Buffer)
   * @returns Hex-encoded encrypted data
   */
  static encryptEcies(data: string, publicKey: string | Buffer): string {
    try {
      const pubKeyBuffer = typeof publicKey === 'string'
        ? CryptoUtils.hexToBuffer(publicKey)
        : publicKey;

      const dataBuffer = Buffer.from(data, 'utf-8');
      const encrypted = eciesEncrypt(pubKeyBuffer, dataBuffer);
      return encrypted.toString('hex');
    } catch (error) {
      throw new EncryptionError(`ECIES encryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Decrypt data using ECIES
   * @param encryptedData - Hex-encoded encrypted data
   * @param privateKey - Recipient's private key (hex or Buffer)
   * @returns Decrypted string
   */
  static decryptEcies(encryptedData: string, privateKey: string | Buffer): string {
    try {
      const privKeyBuffer = typeof privateKey === 'string'
        ? CryptoUtils.hexToBuffer(privateKey)
        : privateKey;

      const encryptedBuffer = CryptoUtils.hexToBuffer(encryptedData);
      const decrypted = eciesDecrypt(privKeyBuffer, encryptedBuffer);
      return decrypted.toString('utf-8');
    } catch (error) {
      throw new EncryptionError(`ECIES decryption failed: ${(error as Error).message}`);
    }
  }

  /**
   * Hash data using SHA-256
   */
  static async hash(data: string | Buffer): Promise<string> {
    const hashBuffer = await CryptoUtils.sha256(data);
    return CryptoUtils.bufferToHex(hashBuffer);
  }

  // ============================================================================
  // Node.js implementations
  // ============================================================================

  private static encryptNode(data: string, key: Buffer, iv: Buffer): string {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf-8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
  }

  private static decryptNode(encryptedData: string, key: Buffer, iv: Buffer): string {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedData, 'hex', 'utf-8');
    decrypted += decipher.final('utf-8');
    return decrypted;
  }

  private static encryptFileNode(buffer: Buffer, key: Buffer, iv: Buffer): Buffer {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([cipher.update(buffer), cipher.final()]);
  }

  private static decryptFileNode(buffer: Buffer, key: Buffer, iv: Buffer): Buffer {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const crypto = require('crypto');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(buffer), decipher.final()]);
  }

  // ============================================================================
  // Browser implementations
  // ============================================================================

  private static async encryptBrowser(data: string, key: Buffer, iv: Buffer): Promise<string> {
    const crypto = CryptoUtils.getCrypto();
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    );

    const dataBuffer = Buffer.from(data, 'utf-8');
    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      cryptoKey,
      dataBuffer
    );

    return CryptoUtils.bufferToHex(Buffer.from(encrypted));
  }

  private static async decryptBrowser(encryptedData: string, key: Buffer, iv: Buffer): Promise<string> {
    const crypto = CryptoUtils.getCrypto();
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );

    const encryptedBuffer = CryptoUtils.hexToBuffer(encryptedData);
    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      cryptoKey,
      encryptedBuffer
    );

    return Buffer.from(decrypted).toString('utf-8');
  }

  private static async encryptFileBrowser(buffer: Buffer, key: Buffer, iv: Buffer): Promise<Buffer> {
    const crypto = CryptoUtils.getCrypto();
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['encrypt']
    );

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-CBC', iv },
      cryptoKey,
      buffer
    );

    return Buffer.from(encrypted);
  }

  private static async decryptFileBrowser(buffer: Buffer, key: Buffer, iv: Buffer): Promise<Buffer> {
    const crypto = CryptoUtils.getCrypto();
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      key,
      { name: 'AES-CBC' },
      false,
      ['decrypt']
    );

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-CBC', iv },
      cryptoKey,
      buffer
    );

    return Buffer.from(decrypted);
  }
}

export { CryptoUtils };
