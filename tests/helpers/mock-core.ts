import { vi } from 'vitest';
import { PrivateKey } from 'eciesjs';

// Deterministic test keypair
export const TEST_PRIVATE_KEY_HEX = '1234567890123456789012345678901234567890123456789012345678901234';
export const TEST_ECIES_PRIVATE_KEY = PrivateKey.fromHex(TEST_PRIVATE_KEY_HEX);
export const TEST_PUBLIC_KEY = TEST_ECIES_PRIVATE_KEY.publicKey.compressed.toString('hex');
export const TEST_ADDRESS = '0xABCDEF1234567890ABCDEF1234567890ABCDEF12';
export const TEST_SUB_ADDRESS = '0x1111111111111111111111111111111111111111';
export const TEST_MAIN_ADDRESS = '0x2222222222222222222222222222222222222222';

export function createMockAlephService() {
  return {
    getAddress: vi.fn().mockReturnValue(TEST_SUB_ADDRESS),
    getPublicKey: vi.fn().mockReturnValue('mock_pub_key'),
    getClient: vi.fn(),
    getAccount: vi.fn(),
    // STORE
    uploadFile: vi.fn().mockResolvedValue({ item_hash: 'a'.repeat(64), size: 100 }),
    downloadFile: vi.fn().mockResolvedValue(new ArrayBuffer(0)),
    deleteFiles: vi.fn().mockResolvedValue({ item_hash: 'forget_hash' }),
    // AGGREGATE
    createAggregate: vi.fn().mockResolvedValue({ item_hash: 'agg_hash' }),
    fetchAggregate: vi.fn().mockResolvedValue({}),
    updateAggregate: vi.fn().mockImplementation(async (_key: string, _schema: any, cb: (content: any) => Promise<any>) => {
      // Default: invoke callback with empty object, can be overridden per-test
      await cb({});
      return { item_hash: 'updated_agg_hash' };
    }),
    // POST
    createPost: vi.fn().mockResolvedValue({ item_hash: 'b'.repeat(64) }),
    fetchPosts: vi.fn().mockResolvedValue([]),
    fetchPost: vi.fn().mockResolvedValue({}),
    updatePost: vi.fn().mockImplementation(async (_type: string, _hash: string, _addrs: string[], _schema: any, cb: (content: any) => Promise<any>) => {
      await cb({});
      return { item_hash: 'c'.repeat(64) };
    }),
  };
}

export function createMockCore(alephService?: ReturnType<typeof createMockAlephService>) {
  const mockAleph = alephService || createMockAlephService();

  return {
    getAlephService: vi.fn().mockReturnValue(mockAleph),
    getMainAccount: vi.fn().mockReturnValue({ address: TEST_MAIN_ADDRESS }),
    getSubAccount: vi.fn().mockReturnValue({ address: TEST_SUB_ADDRESS }),
    getMainAddress: vi.fn().mockReturnValue(TEST_MAIN_ADDRESS),
    getSubAddress: vi.fn().mockReturnValue(TEST_SUB_ADDRESS),
    getPublicKey: vi.fn().mockReturnValue(TEST_PUBLIC_KEY),
    getEncryptionKey: vi.fn().mockReturnValue(Buffer.from(TEST_ECIES_PRIVATE_KEY.secret)),
    getEncryptionPrivateKey: vi.fn().mockReturnValue(TEST_ECIES_PRIVATE_KEY),
    getSubAccountPrivateKey: vi.fn().mockReturnValue(TEST_ECIES_PRIVATE_KEY.toHex()),
    _mockAleph: mockAleph,
  };
}

export type MockCore = ReturnType<typeof createMockCore>;
export type MockAlephService = ReturnType<typeof createMockAlephService>;
