import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AuthenticationError } from '../src/types/errors';

// Mock external deps
vi.mock('@aleph-sdk/ethereum', () => ({
  importAccountFromPrivateKey: vi.fn((key: string) => ({
    address: '0x' + key.replace('0x', '').slice(0, 40).padEnd(40, '0'),
    publicKey: 'mock_eth_pub_key',
  })),
  getAccountFromProvider: vi.fn(),
}));

vi.mock('@aleph-sdk/client', () => ({
  AuthenticatedAlephHttpClient: vi.fn().mockImplementation(() => ({
    createStore: vi.fn(),
    createAggregate: vi.fn(),
    fetchAggregate: vi.fn(),
  })),
}));

vi.mock('web3', () => {
  let callCount = 0;
  return {
    default: {
      utils: {
        sha3: vi.fn((input: string) => {
          // Return deterministic hex hashes
          callCount++;
          // Produce different valid 66-char hex strings each time
          return '0x' + callCount.toString(16).padStart(64, 'a');
        }),
      },
    },
  };
});

// Import after mocking
import { BedrockCore } from '../src/client/bedrock-core';

describe('BedrockCore', () => {
  beforeEach(() => {
    vi.clearAllMocks();
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
