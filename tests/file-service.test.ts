import { PrivateKey } from 'eciesjs';
import { EncryptionService } from '../src/crypto/encryption';
import { FileService } from '../src/services/file-service';
import { FileConflictError, FileNotFoundError } from '../src/types/errors';
import { AGGREGATE_KEYS, POST_TYPES } from '../src/types/schemas';
import {
  createMockCore,
  TEST_PUBLIC_KEY,
  type MockCore
} from './helpers/mock-core';

describe('FileService', () => {
  let service: FileService;
  let mockCore: MockCore;

  // State tracking for aggregate and post
  let fileEntriesState: { files: any[] };
  let postStore: Map<string, any>;

  beforeEach(() => {
    mockCore = createMockCore();
    service = new FileService(mockCore as any);

    fileEntriesState = { files: [] };
    postStore = new Map();

    // fetchAggregate: return current fileEntries state
    mockCore._mockAleph.fetchAggregate.mockImplementation(async (key: string) => {
      if (key === AGGREGATE_KEYS.FILE_ENTRIES) return { ...fileEntriesState };
      throw new Error('not found');
    });

    // updateAggregate: invoke callback with current state, persist result
    mockCore._mockAleph.updateAggregate.mockImplementation(
      async (_key: string, _schema: any, cb: (content: any) => Promise<any>) => {
        const result = await cb({ ...fileEntriesState });
        fileEntriesState = result;
        return { item_hash: 'agg_' + Date.now() };
      }
    );

    // uploadFile: return deterministic hash based on call count
    let uploadCount = 0;
    mockCore._mockAleph.uploadFile.mockImplementation(async () => {
      uploadCount++;
      const hash = uploadCount.toString(16).padStart(64, '0');
      return { item_hash: hash, size: 100 };
    });

    // createPost: store the content, return hash
    let postCount = 0;
    mockCore._mockAleph.createPost.mockImplementation(async (_type: string, content: any) => {
      postCount++;
      const hash = 'post' + postCount.toString(16).padStart(60, '0');
      postStore.set(hash, content);
      return { item_hash: hash };
    });

    // fetchPost: return stored encrypted meta
    mockCore._mockAleph.fetchPost.mockImplementation(async (_type: string, _schema: any, _addrs: any, hash: string) => {
      const stored = postStore.get(hash);
      if (stored) return stored;
      throw new Error('post not found');
    });

    // updatePost: fetch current, invoke callback, store new
    mockCore._mockAleph.updatePost.mockImplementation(
      async (_type: string, hash: string, _addrs: string[], _schema: any, cb: (content: any) => Promise<any>) => {
        const current = postStore.get(hash);
        if (!current) throw new Error('post not found: ' + hash);
        const updated = await cb(current);
        const newHash = 'upd' + Math.random().toString(16).slice(2, 14).padEnd(61, '0');
        postStore.set(newHash, updated);
        return { item_hash: newHash };
      }
    );

    // downloadFile: return encrypted content (for tests that need it, we'll set up specifically)
    mockCore._mockAleph.downloadFile.mockResolvedValue(Buffer.alloc(32));
  });

  describe('setup', () => {
    it('fetches existing aggregate', async () => {
      await service.setup();
      expect(mockCore._mockAleph.fetchAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.FILE_ENTRIES,
        expect.anything()
      );
    });

    it('creates empty aggregate on fetch failure', async () => {
      mockCore._mockAleph.fetchAggregate.mockRejectedValueOnce(new Error('not found'));
      await service.setup();
      expect(mockCore._mockAleph.createAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.FILE_ENTRIES,
        { files: [] }
      );
    });
  });

  describe('uploadFiles', () => {
    it('encrypts, uploads STORE, creates POST, updates aggregate', async () => {
      const files = [{ name: 'test.txt', path: '/docs/test.txt', content: Buffer.from('hello world') }];

      const result = await service.uploadFiles(files);
      expect(result).toHaveLength(1);
      expect(result[0].name).toBe('test.txt');
      expect(result[0].path).toBe('/docs/test.txt');
      expect(result[0].size).toBe(11);
      expect(result[0].key).toHaveLength(64);
      expect(result[0].iv).toHaveLength(32);
      expect(result[0].deleted_at).toBeNull();
      expect(result[0].shared_keys).toEqual({});

      // Verify calls
      expect(mockCore._mockAleph.uploadFile).toHaveBeenCalledTimes(1);
      expect(mockCore._mockAleph.createPost).toHaveBeenCalledWith(POST_TYPES.FILE, expect.anything());
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();

      // Entries should have been saved
      expect(fileEntriesState.files).toHaveLength(1);
    });

    it('applies directoryPath prefix', async () => {
      const files = [{ name: 'a.txt', path: 'a.txt', content: Buffer.from('x') }];
      const result = await service.uploadFiles(files, '/mydir/');
      expect(result[0].path).toBe('/mydir/a.txt');
    });

    it('throws FileConflictError on existing path', async () => {
      // Upload first file
      await service.uploadFiles([{ name: 'f.txt', path: '/f.txt', content: Buffer.from('a') }]);

      // Now fetchPost needs to return decryptable meta for listFiles -> getFile path
      // We need the file entries + post store to allow path conflict checking
      // The checkPathConflicts calls listFiles which fetches entries + decrypts
      // For simplicity, test that the conflict logic works by checking the method behavior
      // The first upload populates fileEntriesState, and on second upload checkPathConflicts
      // will call listFiles which calls fetchFileEntries (works) then fetchFilesMetaFromEntries
      // which needs to decrypt posts — this is handled by postStore + real encryption

      // Since the encrypted posts are in postStore and fetchPost returns them,
      // and decryptFileMeta uses real ECIES with our test keys, this should work end-to-end

      await expect(
        service.uploadFiles([{ name: 'f.txt', path: '/f.txt', content: Buffer.from('b') }])
      ).rejects.toThrow(FileConflictError);
    });
  });

  describe('downloadFile', () => {
    it('downloads encrypted content, decrypts with key/iv', async () => {
      const key = EncryptionService.generateKey();
      const iv = EncryptionService.generateIv();
      const originalContent = Buffer.from('secret data');
      const encrypted = await EncryptionService.encryptFile(originalContent, key, iv);

      mockCore._mockAleph.downloadFile.mockResolvedValue(encrypted);

      const fileInfo: any = {
        key: key.toString('hex'),
        iv: iv.toString('hex'),
        store_hash: 'a'.repeat(64),
      };

      const result = await service.downloadFile(fileInfo);
      expect(result.toString()).toBe('secret data');
    });
  });

  describe('fetchFileEntries', () => {
    it('fetches aggregate and decrypts ECIES paths', async () => {
      const encPath = EncryptionService.encryptEcies('/docs/hello.txt', TEST_PUBLIC_KEY);
      fileEntriesState = {
        files: [{ path: encPath, post_hash: 'a'.repeat(64), shared_with: [] }],
      };

      const entries = await service.fetchFileEntries();
      expect(entries).toHaveLength(1);
      expect(entries[0].path).toBe('/docs/hello.txt');
    });
  });

  describe('listFiles', () => {
    it('filters non-deleted by default', async () => {
      // Upload two files, soft-delete one
      await service.uploadFiles([
        { name: 'a.txt', path: '/a.txt', content: Buffer.from('a') },
        { name: 'b.txt', path: '/b.txt', content: Buffer.from('b') },
      ]);

      // Soft delete /a.txt
      await service.softDeleteFiles(['/a.txt']);

      const files = await service.listFiles();
      expect(files.length).toBe(1);
      expect(files[0].path).toBe('/b.txt');
    });

    it('includes deleted when flag true', async () => {
      await service.uploadFiles([
        { name: 'a.txt', path: '/a.txt', content: Buffer.from('a') },
      ]);
      await service.softDeleteFiles(['/a.txt']);

      const files = await service.listFiles(true);
      expect(files.length).toBe(1);
      expect(files[0].deleted_at).toBeTruthy();
    });
  });

  describe('getFile', () => {
    it('returns match by path', async () => {
      await service.uploadFiles([{ name: 'x.txt', path: '/x.txt', content: Buffer.from('x') }]);
      const file = await service.getFile('/x.txt');
      expect(file.name).toBe('x.txt');
    });

    it('throws FileNotFoundError', async () => {
      await expect(service.getFile('/missing')).rejects.toThrow(FileNotFoundError);
    });
  });

  describe('softDeleteFiles', () => {
    it('sets deleted_at in metadata', async () => {
      await service.uploadFiles([{ name: 'f.txt', path: '/f.txt', content: Buffer.from('f') }]);

      await service.softDeleteFiles(['/f.txt']);

      const files = await service.listFiles(true);
      expect(files[0].deleted_at).toBeTruthy();
    });
  });

  describe('restoreFiles', () => {
    it('clears deleted_at', async () => {
      await service.uploadFiles([{ name: 'r.txt', path: '/r.txt', content: Buffer.from('r') }]);
      await service.softDeleteFiles(['/r.txt']);

      // Verify it's deleted
      let files = await service.listFiles(false);
      expect(files).toHaveLength(0);

      await service.restoreFiles(['/r.txt']);

      files = await service.listFiles(false);
      expect(files).toHaveLength(1);
      expect(files[0].deleted_at).toBeNull();
    });

    it('throws FileConflictError on path conflict with non-trashed file', async () => {
      await service.uploadFiles([
        { name: 'a.txt', path: '/a.txt', content: Buffer.from('a') },
      ]);

      // Upload second file at same path — need to trick the system
      // Actually, conflict check is done on restore: if a non-trashed file exists at the same path
      // Let's upload, delete, upload a new one at same path would fail at upload time
      // So: upload a.txt, soft-delete it, upload a new a.txt, then try restoring old a.txt
      // This is complex to set up. Let's verify the method calls checkPathConflicts instead.
      // The real test is that restoreFiles calls checkPathConflicts before restoring.
      // Since we already test checkPathConflicts via uploadFiles conflict above,
      // we trust the delegation. Still, let's do a simple assertion:

      await service.softDeleteFiles(['/a.txt']);
      // re-upload /a.txt
      await service.uploadFiles([{ name: 'a.txt', path: '/a.txt', content: Buffer.from('new') }]);

      // now try restoring the old trashed /a.txt — conflict with new non-trashed /a.txt
      await expect(service.restoreFiles(['/a.txt'])).rejects.toThrow(FileConflictError);
    });
  });

  describe('hardDeleteFiles', () => {
    it('removes entries + forgets store/post hashes', async () => {
      await service.uploadFiles([{ name: 'h.txt', path: '/h.txt', content: Buffer.from('h') }]);

      await service.hardDeleteFiles(['/h.txt']);

      expect(fileEntriesState.files).toHaveLength(0);
      expect(mockCore._mockAleph.deleteFiles).toHaveBeenCalled();
    });
  });

  describe('moveFiles', () => {
    it('updates path/name in metadata, updates encrypted path in aggregate', async () => {
      await service.uploadFiles([{ name: 'old.txt', path: '/old.txt', content: Buffer.from('data') }]);

      await service.moveFiles([{ oldPath: '/old.txt', newPath: '/new.txt' }]);

      const files = await service.listFiles();
      expect(files).toHaveLength(1);
      expect(files[0].path).toBe('/new.txt');
      expect(files[0].name).toBe('new.txt');
    });

    it('throws on path collision', async () => {
      await service.uploadFiles([
        { name: 'a.txt', path: '/a.txt', content: Buffer.from('a') },
        { name: 'b.txt', path: '/b.txt', content: Buffer.from('b') },
      ]);

      await expect(
        service.moveFiles([{ oldPath: '/a.txt', newPath: '/b.txt' }])
      ).rejects.toThrow(FileConflictError);
    });
  });

  describe('duplicateFiles', () => {
    it('downloads + re-uploads as new files', async () => {
      // Upload original
      await service.uploadFiles([{ name: 'orig.txt', path: '/orig.txt', content: Buffer.from('content') }]);

      // Set up download mock to return decryptable content
      const origFile = (await service.listFiles())[0];
      const key = Buffer.from(origFile.key, 'hex');
      const iv = Buffer.from(origFile.iv, 'hex');
      const encrypted = await EncryptionService.encryptFile(Buffer.from('content'), key, iv);
      mockCore._mockAleph.downloadFile.mockResolvedValue(encrypted);

      const result = await service.duplicateFiles([{ oldPath: '/orig.txt', newPath: '/copy.txt' }]);
      expect(result).toHaveLength(1);
      expect(result[0].path).toBe('/copy.txt');
      expect(result[0].name).toBe('copy.txt');
    });
  });

  describe('shareFile', () => {
    it('encrypts key/iv with contact pubkey, updates metadata + aggregate', async () => {
      await service.uploadFiles([{ name: 's.txt', path: '/s.txt', content: Buffer.from('share me') }]);

      // Generate contact keypair
      const contactPrivKey = PrivateKey.fromHex('ab'.repeat(32));
      const contactPubKey = contactPrivKey.publicKey.compressed.toString('hex');

      await service.shareFile('/s.txt', contactPubKey);

      // Verify updatePost and updateAggregate were called
      expect(mockCore._mockAleph.updatePost).toHaveBeenCalled();
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();
    });
  });

  describe('unshareFile', () => {
    it('removes from shared_keys + shared_with', async () => {
      await service.uploadFiles([{ name: 'u.txt', path: '/u.txt', content: Buffer.from('unshare') }]);

      const contactPrivKey = PrivateKey.fromHex('cd'.repeat(32));
      const contactPubKey = contactPrivKey.publicKey.compressed.toString('hex');

      // Share first
      await service.shareFile('/u.txt', contactPubKey);

      // Then unshare
      await service.unshareFile('/u.txt', contactPubKey);

      expect(mockCore._mockAleph.updatePost).toHaveBeenCalled();
    });
  });

  describe('shareFilePublicly', () => {
    it('downloads, decrypts, re-uploads unencrypted, creates public POST', async () => {
      await service.uploadFiles([{ name: 'pub.txt', path: '/pub.txt', content: Buffer.from('public data') }]);

      const file = (await service.listFiles())[0];
      const key = Buffer.from(file.key, 'hex');
      const iv = Buffer.from(file.iv, 'hex');
      const encrypted = await EncryptionService.encryptFile(Buffer.from('public data'), key, iv);
      mockCore._mockAleph.downloadFile.mockResolvedValue(encrypted);

      const hash = await service.shareFilePublicly(file, 'testuser');
      expect(hash).toBeTruthy();
      expect(mockCore._mockAleph.uploadFile).toHaveBeenCalled();
      expect(mockCore._mockAleph.createPost).toHaveBeenCalledWith(
        POST_TYPES.PUBLIC_FILE,
        expect.objectContaining({ name: 'pub.txt', username: 'testuser' })
      );
    });
  });

  describe('editFileContent', () => {
    it('re-encrypts, uploads new STORE, updates POST + aggregate', async () => {
      await service.uploadFiles([{ name: 'edit.txt', path: '/edit.txt', content: Buffer.from('original') }]);

      const file = (await service.listFiles())[0];
      const result = await service.editFileContent(file, Buffer.from('modified'));

      expect(result.post_hash).toBeTruthy();
      expect(mockCore._mockAleph.updatePost).toHaveBeenCalled();
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();
    });
  });
});
