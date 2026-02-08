import { AGGREGATE_KEYS } from '../src/types/schemas';

const mockAleph = {
  fetchAggregate: jest.fn(),
  createAggregate: jest.fn(),
  updateAggregate: jest.fn(),
};

const mockCoreInstance = {
  getAlephService: jest.fn().mockReturnValue(mockAleph),
  getMainAddress: jest.fn().mockReturnValue('0x' + 'aa'.repeat(20)),
  getSubAddress: jest.fn().mockReturnValue('0x' + 'bb'.repeat(20)),
  getPublicKey: jest.fn().mockReturnValue('mock_public_key'),
  getEncryptionKey: jest.fn().mockReturnValue(Buffer.alloc(32)),
  getSubAccountPrivateKey: jest.fn().mockReturnValue('mock_private_key'),
};

jest.mock('../src/client/bedrock-core', () => ({
  BedrockCore: {
    fromPrivateKey: jest.fn().mockResolvedValue(mockCoreInstance),
    fromProvider: jest.fn().mockResolvedValue(mockCoreInstance),
    fromSignature: jest.fn().mockResolvedValue(mockCoreInstance),
  },
}));

import { BedrockClient } from '../src/bedrock-client';

function resetMocks() {
  mockAleph.fetchAggregate.mockReset();
  mockAleph.createAggregate.mockReset();
  mockAleph.updateAggregate.mockReset();
  // Setup calls: fetchAggregate throws -> createAggregate succeeds
  mockAleph.fetchAggregate.mockRejectedValue(new Error('not found'));
  mockAleph.createAggregate.mockResolvedValue({ item_hash: 'agg' });
}

describe('BedrockClient', () => {
  beforeEach(() => {
    resetMocks();
  });

  describe('fromPrivateKey', () => {
    it('creates core, runs setup, returns client', async () => {
      const client = await BedrockClient.fromPrivateKey('0xabc123');
      expect(client).toBeInstanceOf(BedrockClient);
      expect(client.files).toBeDefined();
      expect(client.contacts).toBeDefined();
      expect(client.knowledgeBases).toBeDefined();
      expect(client.credits).toBeDefined();
      expect(mockAleph.createAggregate).toHaveBeenCalled();
    });
  });

  describe('fromProvider', () => {
    it('creates core from provider, runs setup', async () => {
      const client = await BedrockClient.fromProvider({});
      expect(client).toBeInstanceOf(BedrockClient);
    });
  });

  describe('fromSignature', () => {
    it('creates core from signature, runs setup', async () => {
      const client = await BedrockClient.fromSignature('sig', {});
      expect(client).toBeInstanceOf(BedrockClient);
    });
  });

  describe('getters', () => {
    it('delegates to core', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      expect(client.getMainAddress()).toBe('0x' + 'aa'.repeat(20));
      expect(client.getSubAddress()).toBe('0x' + 'bb'.repeat(20));
      expect(client.getPublicKey()).toBe('mock_public_key');
      expect(client.getEncryptionKey()).toEqual(Buffer.alloc(32));
    });
  });

  describe('resetFiles', () => {
    it('creates empty aggregate', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      mockAleph.createAggregate.mockClear();
      await client.resetFiles();
      expect(mockAleph.createAggregate).toHaveBeenCalledWith(AGGREGATE_KEYS.FILE_ENTRIES, expect.anything());
    });
  });

  describe('resetContacts', () => {
    it('creates empty aggregate', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      mockAleph.createAggregate.mockClear();
      await client.resetContacts();
      expect(mockAleph.createAggregate).toHaveBeenCalledWith(AGGREGATE_KEYS.CONTACTS, expect.anything());
    });
  });

  describe('resetKnowledgeBases', () => {
    it('creates empty aggregate', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      mockAleph.createAggregate.mockClear();
      await client.resetKnowledgeBases();
      expect(mockAleph.createAggregate).toHaveBeenCalledWith(AGGREGATE_KEYS.KNOWLEDGE_BASES, expect.anything());
    });
  });

  describe('resetAllData', () => {
    it('resets all 3 in parallel', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      mockAleph.createAggregate.mockClear();
      await client.resetAllData();
      expect(mockAleph.createAggregate).toHaveBeenCalledTimes(3);
    });
  });

  describe('setupUserProfile', () => {
    it('creates USER_PROFILE aggregate', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      mockAleph.createAggregate.mockClear();
      await client.setupUserProfile('alice');
      expect(mockAleph.createAggregate).toHaveBeenCalledWith(AGGREGATE_KEYS.USER_PROFILE, {
        username: 'alice',
        public_key: 'mock_public_key',
      });
    });
  });

  describe('getUserProfile', () => {
    it('fetches profile, returns data', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      mockAleph.fetchAggregate.mockResolvedValueOnce({ username: 'bob', public_key: 'pk' });
      const profile = await client.getUserProfile('0xaddr');
      expect(profile).toEqual({ username: 'bob', public_key: 'pk' });
    });

    it('returns null on error', async () => {
      const client = await BedrockClient.fromPrivateKey('0xkey');
      // fetchAggregate already rejects by default
      const profile = await client.getUserProfile('0xaddr');
      expect(profile).toBeNull();
    });
  });
});
