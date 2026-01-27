/**
 * Bedrock SDK - TypeScript SDK for Bedrock decentralized cloud storage
 * powered by Aleph
 *
 * @packageDocumentation
 */

// Main client
export { BedrockClient } from './bedrock-client';

// Core classes
export { BedrockCore, BedrockCoreConfig } from './client/bedrock-core';
export { AlephService } from './client/aleph-service';

// Services
export { FileService, FileInput } from './services/file-service';
export { ContactService } from './services/contact-service';
export { KnowledgeBaseService } from './services/knowledge-base-service';
export { CreditService } from './services/credit-service';

// Encryption
export { EncryptionService, CryptoUtils } from './crypto/encryption';

// Types and schemas
export {
  // Constants
  BEDROCK_MESSAGE,
  SECURITY_AGGREGATE_KEY,
  ALEPH_GENERAL_CHANNEL,
  AGGREGATE_KEYS,
  POST_TYPES,

  // File types
  FileEntry,
  FileMeta,
  FileMetaEncrypted,
  FileFullInfo,
  FileEntrySchema,
  FileMetaSchema,
  FileMetaEncryptedSchema,
  FileEntriesAggregateSchema,

  // Public file types
  PublicFileMeta,
  PublicFileMetaSchema,

  // Contact types
  Contact,
  ContactSchema,
  ContactsAggregate,
  ContactsAggregateSchema,

  // User profile types
  UserProfile,
  UserProfileSchema,

  // Knowledge base types
  KnowledgeBase,
  KnowledgeBaseSchema,
  KnowledgeBasesAggregate,
  KnowledgeBasesAggregateSchema,

  // Credit types
  UserCredit,
  CreditTransaction,
  CreditAggregate,
  UserCreditSchema,
  CreditTransactionSchema,
  CreditAggregateSchema,

  // Security types
  SecurityAggregate,
  SecurityAggregateSchema,

  // Aleph message types
  AlephPostContent,
  AlephAggregateContent,
  AlephStoreMessage,
  AlephMessage,

  // Schema helpers
  HexString64Schema,
  HexString32Schema,
  DatetimeSchema,
  AddressSchema,
} from './types/schemas';

// Errors
export {
  BedrockError,
  AuthenticationError,
  EncryptionError,
  FileError,
  FileNotFoundError,
  ContactError,
  KnowledgeBaseError,
  CreditError,
  NetworkError,
  ValidationError,
} from './types/errors';

// Re-export Aleph SDK types for convenience
export type { Account } from '@aleph-sdk/account';
export { ETHAccount } from '@aleph-sdk/ethereum';
export { AlephHttpClient, AuthenticatedAlephHttpClient } from '@aleph-sdk/client';
