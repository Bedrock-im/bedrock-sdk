import { AuthenticationError } from '../src/types/errors';

// Mock external deps
jest.mock('@aleph-sdk/ethereum', () => ({
  importAccountFromPrivateKey: jest.fn((key: string) => ({
    address: '0x' + key.replace('0x', '').slice(0, 40).padEnd(40, '0'),
    publicKey: 'mock_eth_pub_key',
  })),
  getAccountFromProvider: jest.fn(),
}));

jest.mock('@aleph-sdk/client', () => ({
  AuthenticatedAlephHttpClient: jest.fn().mockImplementation(() => ({
    createStore: jest.fn(),
    createAggregate: jest.fn(),
    fetchAggregate: jest.fn(),
  })),
}));

jest.mock('web3', () => {
  let callCount = 0;
  const mock = {
    __esModule: true,
    default: {
      utils: {
        sha3: jest.fn((_input: string) => {
          // Return deterministic hex hashes
          callCount++;
          // Produce different valid 66-char hex strings each time
          return '0x' + callCount.toString(16).padStart(64, 'a');
        }),
      },
    },
  };
  return mock;
});

// Import after mocking
import { BedrockCore } from '../src/client/bedrock-core';

describe('BedrockCore', () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('fromPrivateKey', () => {
    it('creates main + sub accounts, AlephService', async () => {
      const core = await BedrockCore.fromPrivateKey('1234567890123456789012345678901234567890123456789012345678901234');
      expect(core.getMainAddress()).toBeTruthy();
      expect(core.getSubAddress()).toBeTruthy();
      expect(core.getAlephService()).toBeTruthy();
    });

    it('handles 0x prefix', async () => {
      const core = await BedrockCore.fromPrivateKey('0x1234567890123456789012345678901234567890123456789012345678901234');
      expect(core.getMainAddress()).toBeTruthy();
    });

    it('exposes getters correctly', async () => {
      const core = await BedrockCore.fromPrivateKey('ab'.repeat(32));
      expect(core.getMainAccount()).toBeDefined();
      expect(core.getSubAccount()).toBeDefined();
      expect(core.getEncryptionKey()).toBeInstanceOf(Buffer);
      expect(core.getEncryptionKey().length).toBe(32);
      expect(core.getEncryptionPrivateKey()).toBeDefined();
      expect(core.getPublicKey()).toMatch(/^[0-9a-f]+$/);
      expect(core.getSubAccountPrivateKey()).toMatch(/^[0-9a-f]+$/);
    });

    it('throws AuthenticationError on failure', async () => {
      const web3 = await import('web3');
      (web3.default.utils.sha3 as any).mockReturnValueOnce(null);

      await expect(BedrockCore.fromPrivateKey('bad')).rejects.toThrow(AuthenticationError);
    });
  });
});
