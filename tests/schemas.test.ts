import { describe, it, expect } from 'vitest';
import {
  HexString64Schema,
  HexString32Schema,
  DatetimeSchema,
  AddressSchema,
  FileEntrySchema,
  FileMetaEncryptedSchema,
  FileMetaSchema,
  ContactSchema,
  ContactsAggregateSchema,
  KnowledgeBaseSchema,
  KnowledgeBasesAggregateSchema,
  UserCreditSchema,
  CreditTransactionSchema,
  CreditAggregateSchema,
  FileEntriesAggregateSchema,
  SecurityAggregateSchema,
  UserProfileSchema,
  PublicFileMetaSchema,
} from '../src/types/schemas';

describe('Schemas', () => {
  describe('HexString64Schema', () => {
    it('accepts valid 64-char hex', () => {
      const val = 'a'.repeat(64);
      expect(HexString64Schema.parse(val)).toBe(val);
    });

    it('rejects wrong length', () => {
      expect(() => HexString64Schema.parse('a'.repeat(63))).toThrow();
      expect(() => HexString64Schema.parse('a'.repeat(65))).toThrow();
    });

    it('rejects non-hex chars', () => {
      expect(() => HexString64Schema.parse('g'.repeat(64))).toThrow();
    });
  });

  describe('HexString32Schema', () => {
    it('accepts valid 32-char hex', () => {
      const val = 'b'.repeat(32);
      expect(HexString32Schema.parse(val)).toBe(val);
    });

    it('rejects wrong length', () => {
      expect(() => HexString32Schema.parse('b'.repeat(31))).toThrow();
    });

    it('rejects non-hex', () => {
      expect(() => HexString32Schema.parse('z'.repeat(32))).toThrow();
    });
  });

  describe('DatetimeSchema', () => {
    it('accepts valid ISO 8601', () => {
      expect(DatetimeSchema.parse('2024-01-01T00:00:00.000Z')).toBeTruthy();
    });

    it('rejects garbage', () => {
      expect(() => DatetimeSchema.parse('not-a-date')).toThrow();
    });
  });

  describe('AddressSchema', () => {
    it('accepts valid 0x + 40 hex', () => {
      const addr = '0x' + 'aB'.repeat(20);
      expect(AddressSchema.parse(addr)).toBe(addr);
    });

    it('rejects missing 0x prefix', () => {
      expect(() => AddressSchema.parse('a'.repeat(40))).toThrow();
    });

    it('rejects wrong length', () => {
      expect(() => AddressSchema.parse('0x' + 'a'.repeat(39))).toThrow();
    });
  });

  describe('FileEntrySchema', () => {
    it('parses valid entry', () => {
      const entry = {
        path: 'encrypted_path',
        post_hash: 'a'.repeat(64),
        shared_with: ['pk1'],
      };
      expect(FileEntrySchema.parse(entry)).toEqual(entry);
    });

    it('defaults shared_with to []', () => {
      const entry = { path: 'p', post_hash: 'a'.repeat(64) };
      expect(FileEntrySchema.parse(entry).shared_with).toEqual([]);
    });

    it('rejects missing post_hash', () => {
      expect(() => FileEntrySchema.parse({ path: 'p' })).toThrow();
    });
  });

  describe('FileMetaEncryptedSchema', () => {
    it('parses valid encrypted meta', () => {
      const meta = {
        name: 'enc_name',
        path: 'enc_path',
        key: 'enc_key',
        iv: 'enc_iv',
        store_hash: 'enc_hash',
        size: 'enc_size',
        created_at: 'enc_date',
        deleted_at: null,
      };
      const parsed = FileMetaEncryptedSchema.parse(meta);
      expect(parsed.shared_keys).toEqual({});
      expect(parsed.name).toBe('enc_name');
    });

    it('defaults shared_keys to {}', () => {
      const meta = {
        name: 'n', path: 'p', key: 'k', iv: 'i',
        store_hash: 'h', size: 's', created_at: 'c', deleted_at: null,
      };
      expect(FileMetaEncryptedSchema.parse(meta).shared_keys).toEqual({});
    });
  });

  describe('FileMetaSchema', () => {
    const validMeta = {
      name: 'test.txt',
      path: '/docs/test.txt',
      key: 'a'.repeat(64),
      iv: 'b'.repeat(32),
      store_hash: 'c'.repeat(64),
      size: 1024,
      created_at: '2024-01-01T00:00:00.000Z',
      deleted_at: null,
    };

    it('parses valid meta', () => {
      const parsed = FileMetaSchema.parse(validMeta);
      expect(parsed.name).toBe('test.txt');
      expect(parsed.shared_keys).toEqual({});
    });

    it('rejects invalid key length', () => {
      expect(() => FileMetaSchema.parse({ ...validMeta, key: 'a'.repeat(32) })).toThrow();
    });

    it('rejects invalid iv length', () => {
      expect(() => FileMetaSchema.parse({ ...validMeta, iv: 'b'.repeat(64) })).toThrow();
    });
  });

  describe('ContactSchema', () => {
    it('parses valid contact', () => {
      const contact = {
        name: 'Alice',
        address: '0x' + 'a'.repeat(40),
        public_key: 'pk123',
      };
      expect(ContactSchema.parse(contact).name).toBe('Alice');
    });
  });

  describe('ContactsAggregateSchema', () => {
    it('parses with contacts', () => {
      const agg = {
        contacts: [{ name: 'A', address: '0x' + 'a'.repeat(40), public_key: 'pk' }],
      };
      expect(ContactsAggregateSchema.parse(agg).contacts).toHaveLength(1);
    });

    it('defaults contacts to []', () => {
      expect(ContactsAggregateSchema.parse({}).contacts).toEqual([]);
    });
  });

  describe('KnowledgeBaseSchema', () => {
    it('parses valid KB', () => {
      const kb = {
        name: 'My KB',
        created_at: '2024-01-01T00:00:00.000Z',
        updated_at: '2024-01-01T00:00:00.000Z',
      };
      const parsed = KnowledgeBaseSchema.parse(kb);
      expect(parsed.name).toBe('My KB');
      expect(parsed.file_paths).toEqual([]);
    });
  });

  describe('KnowledgeBasesAggregateSchema', () => {
    it('defaults knowledge_bases to []', () => {
      expect(KnowledgeBasesAggregateSchema.parse({}).knowledge_bases).toEqual([]);
    });
  });

  describe('CreditTransactionSchema', () => {
    it('parses valid transaction', () => {
      const tx = {
        id: 'tx1',
        amount: 100,
        type: 'top_up' as const,
        timestamp: 1700000000,
        description: 'Purchase',
      };
      expect(CreditTransactionSchema.parse(tx).type).toBe('top_up');
    });

    it('validates type enum', () => {
      const tx = {
        id: 'tx1', amount: 100, type: 'invalid',
        timestamp: 1700000000, description: 'x',
      };
      expect(() => CreditTransactionSchema.parse(tx)).toThrow();
    });

    it('accepts optional txHash', () => {
      const tx = {
        id: 'tx1', amount: 50, type: 'deduct' as const,
        timestamp: 1700000000, description: 'use', txHash: '0xabc',
      };
      expect(CreditTransactionSchema.parse(tx).txHash).toBe('0xabc');
    });
  });

  describe('UserCreditSchema', () => {
    it('parses with defaults', () => {
      const parsed = UserCreditSchema.parse({});
      expect(parsed.balance).toBe(0);
      expect(parsed.transactions).toEqual([]);
    });
  });

  describe('CreditAggregateSchema', () => {
    it('parses record of user credits', () => {
      const agg = {
        '0x123': { balance: 100, transactions: [] },
      };
      const parsed = CreditAggregateSchema.parse(agg);
      expect(parsed['0x123'].balance).toBe(100);
    });
  });

  describe('FileEntriesAggregateSchema', () => {
    it('defaults files to []', () => {
      expect(FileEntriesAggregateSchema.parse({}).files).toEqual([]);
    });
  });

  describe('SecurityAggregateSchema', () => {
    it('parses valid security aggregate', () => {
      const sec = {
        authorizations: [{
          address: '0x' + 'a'.repeat(40),
          chain: 'ETH',
        }],
      };
      expect(SecurityAggregateSchema.parse(sec).authorizations).toHaveLength(1);
    });

    it('accepts optional fields', () => {
      const sec = {
        authorizations: [{
          address: '0x' + 'a'.repeat(40),
          chain: 'ETH',
          channels: ['ch1'],
          post_types: ['bedrock_file'],
          aggregate_keys: ['key1'],
        }],
      };
      const parsed = SecurityAggregateSchema.parse(sec);
      expect(parsed.authorizations[0].channels).toEqual(['ch1']);
    });
  });

  describe('UserProfileSchema', () => {
    it('parses with optional username', () => {
      expect(UserProfileSchema.parse({ public_key: 'pk' }).username).toBeUndefined();
    });

    it('parses with username', () => {
      expect(UserProfileSchema.parse({ username: 'alice', public_key: 'pk' }).username).toBe('alice');
    });
  });

  describe('PublicFileMetaSchema', () => {
    it('parses valid public file meta', () => {
      const meta = {
        name: 'file.txt',
        size: 1024,
        created_at: '2024-01-01T00:00:00.000Z',
        store_hash: 'a'.repeat(64),
        username: 'alice',
      };
      expect(PublicFileMetaSchema.parse(meta).name).toBe('file.txt');
    });
  });
});
