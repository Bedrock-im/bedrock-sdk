
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
    getAddress: jest.fn().mockReturnValue(TEST_SUB_ADDRESS),
    getPublicKey: jest.fn().mockReturnValue('mock_pub_key'),
    getClient: jest.fn(),
    getAccount: jest.fn(),
    // STORE
    uploadFile: jest.fn().mockResolvedValue({ item_hash: 'a'.repeat(64), size: 100 }),
    downloadFile: jest.fn().mockResolvedValue(new ArrayBuffer(0)),
    deleteFiles: jest.fn().mockResolvedValue({ item_hash: 'forget_hash' }),
    // AGGREGATE
    createAggregate: jest.fn().mockResolvedValue({ item_hash: 'agg_hash' }),
    fetchAggregate: jest.fn().mockResolvedValue({}),
    updateAggregate: jest.fn().mockImplementation(async (_key: string, _schema: any, cb: (content: any) => Promise<any>) => {
      // Default: invoke callback with empty object, can be overridden per-test
      await cb({});
      return { item_hash: 'updated_agg_hash' };
    }),
    // POST
    createPost: jest.fn().mockResolvedValue({ item_hash: 'b'.repeat(64) }),
    fetchPosts: jest.fn().mockResolvedValue([]),
    fetchPost: jest.fn().mockResolvedValue({}),
    updatePost: jest.fn().mockImplementation(async (_type: string, _hash: string, _addrs: string[], _schema: any, cb: (content: any) => Promise<any>) => {
      await cb({});
      return { item_hash: 'c'.repeat(64) };
    }),
  };
}

export function createMockCore(alephService?: ReturnType<typeof createMockAlephService>) {
  const mockAleph = alephService || createMockAlephService();

  return {
    getAlephService: jest.fn().mockReturnValue(mockAleph),
    getMainAccount: jest.fn().mockReturnValue({ address: TEST_MAIN_ADDRESS }),
    getSubAccount: jest.fn().mockReturnValue({ address: TEST_SUB_ADDRESS }),
    getMainAddress: jest.fn().mockReturnValue(TEST_MAIN_ADDRESS),
    getSubAddress: jest.fn().mockReturnValue(TEST_SUB_ADDRESS),
    getPublicKey: jest.fn().mockReturnValue(TEST_PUBLIC_KEY),
    getEncryptionKey: jest.fn().mockReturnValue(Buffer.from(TEST_ECIES_PRIVATE_KEY.secret)),
    getEncryptionPrivateKey: jest.fn().mockReturnValue(TEST_ECIES_PRIVATE_KEY),
    getSubAccountPrivateKey: jest.fn().mockReturnValue(TEST_ECIES_PRIVATE_KEY.toHex()),
    _mockAleph: mockAleph,
  };
}

export type MockCore = ReturnType<typeof createMockCore>;
export type MockAlephService = ReturnType<typeof createMockAlephService>;
