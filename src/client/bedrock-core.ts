import { AuthenticatedAlephHttpClient } from '@aleph-sdk/client';
import { ETHAccount, getAccountFromProvider, importAccountFromPrivateKey } from '@aleph-sdk/ethereum';
import { PrivateKey } from 'eciesjs';
import web3 from 'web3';
import { AuthenticationError } from '../types/errors';
import {
  ALEPH_GENERAL_CHANNEL,
  BEDROCK_MESSAGE,
  SECURITY_AGGREGATE_KEY
} from '../types/schemas';
import { AlephService } from './aleph-service';

/**
 * Configuration for BedrockCore
 */
export interface BedrockCoreConfig {
  channel?: string;
  apiServer?: string;
}

/**
 * Core Bedrock functionality: authentication, sub-accounts, encryption key derivation
 */
export class BedrockCore {
  private mainAccount: ETHAccount;
  private subAccount: ETHAccount;
  private alephService: AlephService;
  private encryptionPrivateKey: PrivateKey;

  private constructor(
    mainAccount: ETHAccount,
    subAccount: ETHAccount,
    alephService: AlephService,
    encryptionPrivateKey: PrivateKey,
    _config: Required<BedrockCoreConfig>
  ) {
    this.mainAccount = mainAccount;
    this.subAccount = subAccount;
    this.alephService = alephService;
    this.encryptionPrivateKey = encryptionPrivateKey;
  }

  /**
   * Initialize from signature hash (matches Bedrock app pattern)
   * @param signatureHash - Signature hash from wallet
   * @param provider - EIP-1193 provider (for MetaMask/Rabby)
   * @param config - Optional configuration
   */
  static async fromSignature(
    signatureHash: string,
    provider: any,
    config?: BedrockCoreConfig
  ): Promise<BedrockCore> {
    try {
      const cfg = {
        channel: config?.channel || ALEPH_GENERAL_CHANNEL,
        apiServer: config?.apiServer || 'https://api2.aleph.im',
      };

      // Derive private key from signature
      const privateKey = web3.utils.sha3(signatureHash);
      if (!privateKey) {
        throw new AuthenticationError('Failed to derive private key from signature');
      }

      // Create encryption private key
      const encryptionPrivateKey = PrivateKey.fromHex(privateKey);

      // Get main account from provider
      // Handle different wallet types like the old service did
      let mainAccount: ETHAccount;

      if (provider?.id && ['io.rabby', 'io.metamask'].includes(provider.id)) {
        // For Rabby and MetaMask, use window.ethereum directly
        if (typeof window !== 'undefined' && (window as any).ethereum) {
          mainAccount = await getAccountFromProvider((window as any).ethereum);
        } else {
          throw new AuthenticationError('window.ethereum not available');
        }
      } else {
        // For other wallets or standard EIP-1193 providers
        mainAccount = await getAccountFromProvider(provider);
      }

      // Create sub-account
      const subAccount = importAccountFromPrivateKey(privateKey);

      // Setup security permissions
      await BedrockCore.setupSecurityPermissions(mainAccount, subAccount, cfg);

      // Create AlephService
      const alephService = new AlephService(subAccount, cfg.channel, cfg.apiServer);

      return new BedrockCore(mainAccount, subAccount, alephService, encryptionPrivateKey, cfg);
    } catch (error) {
      throw new AuthenticationError(`Failed to initialize from signature: ${(error as Error).message}`);
    }
  }

  /**
   * Create BedrockCore from a private key (for testing/CLI)
   * @param privateKey - Ethereum private key (hex string with or without 0x prefix)
   * @param config - Optional configuration
   */
  static async fromPrivateKey(privateKey: string, config?: BedrockCoreConfig): Promise<BedrockCore> {
    try {
      const cfg = {
        channel: config?.channel || ALEPH_GENERAL_CHANNEL,
        apiServer: config?.apiServer || 'https://api2.aleph.im',
      };

      // Ensure 0x prefix
      const key = privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`;

      // Create main account
      const mainAccount = importAccountFromPrivateKey(key);

      // For private key, we simulate signing by hashing the key + message
      const signatureHash = web3.utils.sha3(key + BEDROCK_MESSAGE);
      if (!signatureHash) {
        throw new AuthenticationError('Failed to derive signature');
      }

      const subPrivateKey = web3.utils.sha3(signatureHash);
      if (!subPrivateKey) {
        throw new AuthenticationError('Failed to derive sub-account key');
      }

      // Create encryption private key
      const encryptionPrivateKey = PrivateKey.fromHex(subPrivateKey);

      // Create sub-account
      const subAccount = importAccountFromPrivateKey(subPrivateKey);

      // Setup security permissions
      await BedrockCore.setupSecurityPermissions(mainAccount, subAccount, cfg);

      // Create AlephService
      const alephService = new AlephService(subAccount, cfg.channel, cfg.apiServer);

      return new BedrockCore(mainAccount, subAccount, alephService, encryptionPrivateKey, cfg);
    } catch (error) {
      throw new AuthenticationError(`Failed to import account: ${(error as Error).message}`);
    }
  }

  /**
   * Create BedrockCore from a wallet provider (e.g., MetaMask)
   * This will automatically request signature from the user
   * @param provider - EIP-1193 provider
   * @param config - Optional configuration
   */
  static async fromProvider(provider: any, config?: BedrockCoreConfig): Promise<BedrockCore> {
    try {
      // Request signature from user
      const accounts = await provider.request({ method: 'eth_requestAccounts' });
      if (!accounts || accounts.length === 0) {
        throw new AuthenticationError('No accounts found');
      }

      // Request signature
      const signature = await provider.request({
        method: 'personal_sign',
        params: [BEDROCK_MESSAGE, accounts[0]],
      });

      return await BedrockCore.fromSignature(signature, provider, config);
    } catch (error) {
      throw new AuthenticationError(`Failed to connect to provider: ${(error as Error).message}`);
    }
  }

  /**
   * Get the main account
   */
  getMainAccount(): ETHAccount {
    return this.mainAccount;
  }

  /**
   * Get the sub-account
   */
  getSubAccount(): ETHAccount {
    return this.subAccount;
  }

  /**
   * Get the AlephService instance
   */
  getAlephService(): AlephService {
    return this.alephService;
  }

  /**
   * Get the encryption key
   */
  getEncryptionKey(): Buffer {
    return Buffer.from(this.encryptionPrivateKey.secret);
  }

  /**
   * Get the encryption private key
   */
  getEncryptionPrivateKey(): PrivateKey {
    return this.encryptionPrivateKey;
  }

  /**
   * Get the main account's address
   */
  getMainAddress(): string {
    return this.mainAccount.address;
  }

  /**
   * Get the sub-account's address
   */
  getSubAddress(): string {
    return this.subAccount.address;
  }

  /**
   * Get the main account's public key
   */
  getPublicKey(): string {
    // Use encryption private key's compressed public key (matches old service)
    // This is derived from the signature and is consistent
    return this.encryptionPrivateKey.publicKey.compressed.toString('hex');
  }

  /**
   * Get the sub-account's private key (as hex string)
   */
  getSubAccountPrivateKey(): string {
    return this.encryptionPrivateKey.toHex();
  }

  // ============================================================================
  // Static helper methods
  // ============================================================================

  /**
   * Setup security permissions (matches Bedrock app pattern)
   */
  private static async setupSecurityPermissions(
    mainAccount: ETHAccount,
    subAccount: ETHAccount,
    config: Required<BedrockCoreConfig>
  ): Promise<void> {
    try {
      const accountClient = new AuthenticatedAlephHttpClient(mainAccount, config.apiServer);

      try {
        // Fetch existing security aggregate
        const securitySettings = await accountClient.fetchAggregate(
          mainAccount.address,
          SECURITY_AGGREGATE_KEY
        ) as any;

        // Check if sub-account is already authorized
        const authorizations = securitySettings?.authorizations || [];
        const isAuthorized = authorizations.find((auth: any) =>
          auth.address === subAccount.address &&
          auth.types === undefined &&
          auth.channels?.includes(config.channel)
        );

        if (!isAuthorized) {
          // Remove old authorizations for this sub-account and add new one
          const oldAuthorizations = authorizations.filter((a: any) => a.address !== subAccount.address);

          await accountClient.createAggregate({
            key: SECURITY_AGGREGATE_KEY,
            content: {
              authorizations: [
                ...oldAuthorizations,
                {
                  address: subAccount.address,
                  channels: [config.channel],
                },
              ],
            },
          });
        }
      } catch (_error) {
        // Security aggregate does not exist, create a new one
        await accountClient.createAggregate({
          key: SECURITY_AGGREGATE_KEY,
          content: {
            authorizations: [
              {
                address: subAccount.address,
                channels: [config.channel],
              },
            ],
          },
        });
      }
    } catch (error) {
      throw new AuthenticationError(`Failed to setup security permissions: ${(error as Error).message}`);
    }
  }
}
