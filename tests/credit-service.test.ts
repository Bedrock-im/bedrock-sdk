import { describe, it, expect, beforeEach } from 'vitest';
import { CreditService } from '../src/services/credit-service';
import { AGGREGATE_KEYS } from '../src/types/schemas';
import { createMockCore, type MockCore } from './helpers/mock-core';

describe('CreditService', () => {
  let service: CreditService;
  let mockCore: MockCore;

  beforeEach(() => {
    mockCore = createMockCore();
    service = new CreditService(mockCore as any);
  });

  describe('getCreditBalance', () => {
    it('fetches aggregate from BACKEND_ADDRESS and returns user data', async () => {
      const userAddress = mockCore.getMainAddress();
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({
        [userAddress]: { balance: 500, transactions: [{ id: 't1', amount: 500, type: 'top_up', timestamp: 1, description: 'init' }] },
      });

      const result = await service.getCreditBalance();
      expect(result.balance).toBe(500);
      expect(result.transactions).toHaveLength(1);
      expect(mockCore._mockAleph.fetchAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.CREDITS,
        expect.anything(),
        '0x1234567890123456789012345678901234567890'
      );
    });

    it('returns {balance:0, transactions:[]} when user not in aggregate', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({
        '0xOtherUser': { balance: 100, transactions: [] },
      });

      const result = await service.getCreditBalance();
      expect(result).toEqual({ balance: 0, transactions: [] });
    });

    it('returns {balance:0, transactions:[]} on fetch error', async () => {
      mockCore._mockAleph.fetchAggregate.mockRejectedValue(new Error('network'));

      const result = await service.getCreditBalance();
      expect(result).toEqual({ balance: 0, transactions: [] });
    });
  });
});
