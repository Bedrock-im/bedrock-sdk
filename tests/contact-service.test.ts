import { describe, it, expect, beforeEach, vi } from 'vitest';
import { ContactService } from '../src/services/contact-service';
import { FileService } from '../src/services/file-service';
import { ContactError } from '../src/types/errors';
import { AGGREGATE_KEYS } from '../src/types/schemas';
import { createMockCore, TEST_PUBLIC_KEY, type MockCore } from './helpers/mock-core';

describe('ContactService', () => {
  let service: ContactService;
  let mockCore: MockCore;
  let mockFileService: any;

  const CONTACT_PK = 'contact_public_key_hex';
  const CONTACT_ADDR = '0x' + 'cc'.repeat(20);

  const makeContact = (name = 'Alice', pk = CONTACT_PK, addr = CONTACT_ADDR) => ({
    name,
    address: addr,
    public_key: pk,
  });

  beforeEach(() => {
    mockCore = createMockCore();
    mockFileService = {
      fetchFileEntries: vi.fn().mockResolvedValue([]),
      fetchFilesMetaFromEntries: vi.fn().mockResolvedValue([]),
      shareFile: vi.fn().mockResolvedValue(undefined),
      unshareFile: vi.fn().mockResolvedValue(undefined),
    };
    service = new ContactService(mockCore as any, mockFileService as unknown as FileService);

    // Default: empty contacts
    mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [] });
    mockCore._mockAleph.updateAggregate.mockImplementation(
      async (_key: string, _schema: any, cb: (content: any) => Promise<any>) => {
        const currentData = await mockCore._mockAleph.fetchAggregate(AGGREGATE_KEYS.CONTACTS, null as any);
        await cb(currentData);
        return { item_hash: 'updated' };
      }
    );
  });

  describe('setup', () => {
    it('fetches existing aggregate', async () => {
      await service.setup();
      expect(mockCore._mockAleph.fetchAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.CONTACTS,
        expect.anything()
      );
    });

    it('creates empty on fetch failure', async () => {
      mockCore._mockAleph.fetchAggregate.mockRejectedValueOnce(new Error('not found'));
      await service.setup();
      expect(mockCore._mockAleph.createAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.CONTACTS,
        { contacts: [] }
      );
    });
  });

  describe('listContacts', () => {
    it('returns contacts array', async () => {
      const contact = makeContact();
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [contact] });
      const result = await service.listContacts();
      expect(result).toEqual([contact]);
    });
  });

  describe('getContact', () => {
    it('returns match by public_key', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      const result = await service.getContact(CONTACT_PK);
      expect(result.name).toBe('Alice');
    });

    it('throws if not found', async () => {
      await expect(service.getContact('unknown')).rejects.toThrow(ContactError);
    });
  });

  describe('getContactByAddress', () => {
    it('matches case-insensitive', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      const result = await service.getContactByAddress(CONTACT_ADDR.toUpperCase());
      expect(result.name).toBe('Alice');
    });

    it('throws if not found', async () => {
      await expect(service.getContactByAddress('0x' + '00'.repeat(20))).rejects.toThrow(ContactError);
    });
  });

  describe('addContact', () => {
    it('fetches profile, creates contact, updates aggregate', async () => {
      // First call: listContacts (empty), second: fetchProfile
      mockCore._mockAleph.fetchAggregate
        .mockResolvedValueOnce({ contacts: [] }) // listContacts
        .mockResolvedValueOnce({ public_key: 'fetched_pk', username: 'Alice' }); // profile

      const result = await service.addContact('Alice', CONTACT_ADDR);
      expect(result.name).toBe('Alice');
      expect(result.public_key).toBe('fetched_pk');
      expect(result.address).toBe(CONTACT_ADDR);
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();
    });

    it('throws if contact already exists', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      await expect(service.addContact('Alice', CONTACT_ADDR)).rejects.toThrow(ContactError);
      await expect(service.addContact('Alice', CONTACT_ADDR)).rejects.toThrow('already exists');
    });

    it('throws if profile fetch fails', async () => {
      mockCore._mockAleph.fetchAggregate
        .mockResolvedValueOnce({ contacts: [] }) // listContacts
        .mockRejectedValueOnce(new Error('no profile')); // profile fetch
      await expect(service.addContact('Bob', '0x' + '00'.repeat(20))).rejects.toThrow('Could not fetch contact profile');
    });

    it('throws on username mismatch', async () => {
      mockCore._mockAleph.fetchAggregate
        .mockResolvedValueOnce({ contacts: [] }) // listContacts
        .mockResolvedValueOnce({ public_key: 'pk', username: 'RealName' }); // profile fetch
      await expect(service.addContact('WrongName', CONTACT_ADDR)).rejects.toThrow('Username mismatch');
    });
  });

  describe('removeContact', () => {
    it('verifies exists, removes', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      await service.removeContact(CONTACT_PK);
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();
    });

    it('throws if not found', async () => {
      await expect(service.removeContact('unknown')).rejects.toThrow(ContactError);
    });
  });

  describe('updateContactName', () => {
    it('finds, updates name, returns updated', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      const result = await service.updateContactName(CONTACT_PK, 'NewName');
      expect(result.name).toBe('NewName');
      expect(result.public_key).toBe(CONTACT_PK);
    });

    it('throws if not found', async () => {
      await expect(service.updateContactName('unknown', 'x')).rejects.toThrow(ContactError);
    });
  });

  describe('getSharedFiles', () => {
    it('filters entries by shared_with, fetches metadata', async () => {
      const contact = makeContact();
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [contact] });
      mockFileService.fetchFileEntries.mockResolvedValue([
        { path: '/shared', post_hash: 'a'.repeat(64), shared_with: [CONTACT_PK] },
        { path: '/private', post_hash: 'b'.repeat(64), shared_with: [] },
      ]);
      mockFileService.fetchFilesMetaFromEntries.mockResolvedValue([{ path: '/shared' }]);

      const result = await service.getSharedFiles(CONTACT_PK);
      expect(result).toHaveLength(1);
      expect(mockFileService.fetchFilesMetaFromEntries).toHaveBeenCalledWith(
        [{ path: '/shared', post_hash: 'a'.repeat(64), shared_with: [CONTACT_PK] }]
      );
    });
  });

  describe('fetchFilesSharedByContact', () => {
    it("fetches contact's aggregate, filters by current user pubkey", async () => {
      const contact = makeContact();
      mockCore._mockAleph.fetchAggregate
        .mockResolvedValueOnce({ contacts: [contact] }) // getContact -> listContacts
        .mockResolvedValueOnce({
          files: [
            { path: 'enc', post_hash: 'a'.repeat(64), shared_with: [TEST_PUBLIC_KEY] },
            { path: 'enc2', post_hash: 'b'.repeat(64), shared_with: ['other_pk'] },
          ],
        }); // contact's file entries

      mockFileService.fetchFilesMetaFromEntries.mockResolvedValue([{ path: '/shared_with_me' }]);

      const result = await service.fetchFilesSharedByContact(CONTACT_PK);
      expect(result).toHaveLength(1);
      expect(mockCore._mockAleph.fetchAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.FILE_ENTRIES,
        expect.anything(),
        CONTACT_ADDR
      );
    });
  });

  describe('shareFileWithContact', () => {
    it('verifies contact, delegates to fileService.shareFile', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      await service.shareFileWithContact('/myfile', CONTACT_PK);
      expect(mockFileService.shareFile).toHaveBeenCalledWith('/myfile', CONTACT_PK);
    });
  });

  describe('unshareFileWithContact', () => {
    it('verifies contact, delegates to fileService.unshareFile', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ contacts: [makeContact()] });
      await service.unshareFileWithContact('/myfile', CONTACT_PK);
      expect(mockFileService.unshareFile).toHaveBeenCalledWith('/myfile', CONTACT_PK);
    });
  });
});
