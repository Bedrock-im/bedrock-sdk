
import { EncryptionService } from '../src/crypto/encryption';
import { PrivateKey } from 'eciesjs';

describe('EncryptionService', () => {
  describe('Key and IV generation', () => {
    it('should generate a 32-byte key', () => {
      const key = EncryptionService.generateKey();
      expect(key.length).toBe(32);
    });

    it('should generate a 16-byte IV', () => {
      const iv = EncryptionService.generateIv();
      expect(iv.length).toBe(16);
    });

    it('should generate different keys each time', () => {
      const key1 = EncryptionService.generateKey();
      const key2 = EncryptionService.generateKey();
      expect(key1.toString('hex')).not.toBe(key2.toString('hex'));
    });
  });

  describe('AES encryption/decryption', () => {
    it('should encrypt and decrypt string data', async () => {
      const data = 'Hello, Bedrock!';
      const key = EncryptionService.generateKey();
      const iv = EncryptionService.generateIv();

      const encrypted = await EncryptionService.encrypt(data, key, iv);
      const decrypted = await EncryptionService.decrypt(encrypted, key, iv);

      expect(decrypted).toBe(data);
      expect(encrypted).not.toBe(data);
    });

    it('should encrypt and decrypt file buffers', async () => {
      const fileData = Buffer.from('File content here');
      const key = EncryptionService.generateKey();
      const iv = EncryptionService.generateIv();

      const encrypted = await EncryptionService.encryptFile(fileData, key, iv);
      const decrypted = await EncryptionService.decryptFile(encrypted, key, iv);

      expect(decrypted.toString()).toBe(fileData.toString());
      expect(encrypted.toString()).not.toBe(fileData.toString());
    });

    it('should handle unicode characters', async () => {
      const data = 'Hello 世界 🌍';
      const key = EncryptionService.generateKey();
      const iv = EncryptionService.generateIv();

      const encrypted = await EncryptionService.encrypt(data, key, iv);
      const decrypted = await EncryptionService.decrypt(encrypted, key, iv);

      expect(decrypted).toBe(data);
    });

    it('should fail with wrong key', async () => {
      const data = 'Secret data';
      const key1 = EncryptionService.generateKey();
      const key2 = EncryptionService.generateKey();
      const iv = EncryptionService.generateIv();

      const encrypted = await EncryptionService.encrypt(data, key1, iv);

      await expect(
        EncryptionService.decrypt(encrypted, key2, iv)
      ).rejects.toThrow();
    });

    it('should fail with wrong IV', async () => {
      const data = 'Secret data';
      const key = EncryptionService.generateKey();
      const iv1 = EncryptionService.generateIv();
      const iv2 = EncryptionService.generateIv();

      const encrypted = await EncryptionService.encrypt(data, key, iv1);

      await expect(
        EncryptionService.decrypt(encrypted, key, iv2)
      ).rejects.toThrow();
    });
  });

  describe('ECIES encryption/decryption', () => {
    // Generate a test key pair using eciesjs
    const privateKeyHex = '1234567890123456789012345678901234567890123456789012345678901234';
    const privateKey = PrivateKey.fromHex(privateKeyHex);
    const publicKey = privateKey.publicKey;

    it('should encrypt and decrypt with ECIES', () => {
      const data = 'Sensitive information';

      // Use the derived public key for encryption
      const encrypted = EncryptionService.encryptEcies(data, publicKey.toHex());
      const decrypted = EncryptionService.decryptEcies(encrypted, privateKeyHex);

      expect(decrypted).toBe(data);
      expect(encrypted).not.toBe(data);
    });

    it('should handle hex string keys', () => {
      const data = 'Test data';

      const encrypted = EncryptionService.encryptEcies(data, publicKey.toHex());
      const decrypted = EncryptionService.decryptEcies(encrypted, privateKeyHex);

      expect(decrypted).toBe(data);
    });
  });

  describe('Hashing', () => {
    it('should hash data with SHA-256', async () => {
      const data = 'Test data';
      const hash = await EncryptionService.hash(data);

      expect(hash).toHaveLength(64); // 32 bytes = 64 hex chars
      expect(hash).toMatch(/^[0-9a-f]{64}$/);
    });

    it('should produce consistent hashes', async () => {
      const data = 'Consistent data';
      const hash1 = await EncryptionService.hash(data);
      const hash2 = await EncryptionService.hash(data);

      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different data', async () => {
      const hash1 = await EncryptionService.hash('Data 1');
      const hash2 = await EncryptionService.hash('Data 2');

      expect(hash1).not.toBe(hash2);
    });
  });
});
