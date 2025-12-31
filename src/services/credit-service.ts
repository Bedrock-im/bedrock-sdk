import { BedrockCore } from '../client/bedrock-core';
import { UserCredit, CreditAggregateSchema, AGGREGATE_KEYS } from '../types/schemas';

/**
 * Service for managing user credits (read-only, backend-managed)
 */
export class CreditService {
  private core: BedrockCore;
  private static readonly BACKEND_ADDRESS = '0x1234567890123456789012345678901234567890';

  constructor(core: BedrockCore) {
    this.core = core;
  }

  /**
   * Get user's credit balance and transaction history
   * @returns User credit data with balance and transactions
   */
  async getCreditBalance(): Promise<UserCredit> {
    const aleph = this.core.getAlephService();
    const userAddress = this.core.getMainAddress();

    try {
      const creditAggregate = await aleph.fetchAggregate(
        AGGREGATE_KEYS.CREDITS,
        CreditAggregateSchema,
        CreditService.BACKEND_ADDRESS
      );

      return creditAggregate[userAddress] || { balance: 0, transactions: [] };
    } catch {
      // Graceful fallback if aggregate doesn't exist or user not found
      return { balance: 0, transactions: [] };
    }
  }
}
