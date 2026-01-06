import { z } from 'zod';

// ============================================================================
// Constants
// ============================================================================

export const BEDROCK_MESSAGE = 'Bedrock.im';
export const SECURITY_AGGREGATE_KEY = 'security';
export const ALEPH_GENERAL_CHANNEL = 'BEDROCK_STORAGE';

export const AGGREGATE_KEYS = {
  FILE_ENTRIES: 'bedrock_file_entries',
  CONTACTS: 'bedrock_contacts',
  KNOWLEDGE_BASES: 'bedrock_knowledge_bases',
  CREDITS: 'credits',
} as const;

export const POST_TYPES = {
  FILE: 'bedrock_file',
  PUBLIC_FILE: 'bedrock_public_file',
} as const;

// ============================================================================
// Base Schemas
// ============================================================================

/**
 * 64-character hex string (32 bytes)
 */
export const HexString64Schema = z
  .string()
  .length(64)
  .regex(/^[0-9a-f]{64}$/);

/**
 * 32-character hex string (16 bytes)
 */
export const HexString32Schema = z
  .string()
  .length(32)
  .regex(/^[0-9a-f]{32}$/);

/**
 * ISO 8601 datetime string
 */
export const DatetimeSchema = z.string().datetime();

/**
 * Ethereum address
 */
export const AddressSchema = z.string().regex(/^0x[a-fA-F0-9]{40}$/);

// ============================================================================
// File Schemas
// ============================================================================

/**
 * File entry in the file index aggregate
 */
export const FileEntrySchema = z.object({
  path: z.string(), // Encrypted path
  post_hash: HexString64Schema,
  shared_with: z.array(z.string()).default([]), // Public keys of contacts
});

export type FileEntry = z.infer<typeof FileEntrySchema>;

/**
 * File metadata stored in POST messages
 */
export const FileMetaEncryptedSchema = z.object({
  name: z.string(), // Encrypted filename
  path: z.string(), // Encrypted path
  key: z.string(), // Encrypted AES key (ECIES encrypted)
  iv: z.string(), // Encrypted IV (ECIES encrypted)
  store_hash: z.string(), // Encrypted Aleph STORE hash
  size: z.string(), // Encrypted size
  created_at: z.string(), // Encrypted datetime
  deleted_at: z.string().nullable(), // Encrypted datetime or null
  shared_keys: z
    .record(
      z.string(),
      z.object({
        key: z.string(), // Encrypted key for recipient
        iv: z.string(), // Encrypted IV for recipient
      })
    )
    .default({}),
});

export type FileMetaEncrypted = z.infer<typeof FileMetaEncryptedSchema>;

/**
 * Decrypted file metadata
 */
export const FileMetaSchema = z.object({
  name: z.string(),
  path: z.string(),
  key: HexString64Schema,
  iv: HexString32Schema,
  store_hash: HexString64Schema,
  size: z.number(),
  created_at: DatetimeSchema,
  deleted_at: DatetimeSchema.nullable(),
  shared_keys: z
    .record(
      z.string(),
      z.object({
        key: HexString64Schema,
        iv: HexString32Schema,
      })
    )
    .default({}),
});

export type FileMeta = z.infer<typeof FileMetaSchema>;

/**
 * Combined file entry and metadata
 */
export type FileFullInfo = FileEntry & FileMeta;

/**
 * Public file metadata (unencrypted, accessible by anyone)
 */
export const PublicFileMetaSchema = z.object({
  name: z.string(),
  size: z.number(),
  created_at: DatetimeSchema,
  store_hash: HexString64Schema,
  username: z.string(),
});

export type PublicFileMeta = z.infer<typeof PublicFileMetaSchema>;

// ============================================================================
// Contact Schemas
// ============================================================================

/**
 * Contact information
 */
export const ContactSchema = z.object({
  name: z.string(),
  address: AddressSchema,
  public_key: z.string(), // Hex-encoded public key
});

export type Contact = z.infer<typeof ContactSchema>;

/**
 * Contacts aggregate
 */
export const ContactsAggregateSchema = z.object({
  contacts: z.array(ContactSchema).default([]),
});

export type ContactsAggregate = z.infer<typeof ContactsAggregateSchema>;

// ============================================================================
// Knowledge Base Schemas
// ============================================================================

/**
 * Knowledge base configuration
 */
export const KnowledgeBaseSchema = z.object({
  name: z.string(),
  file_paths: z.array(z.string()).default([]), // Encrypted paths
  created_at: DatetimeSchema,
  updated_at: DatetimeSchema,
});

export type KnowledgeBase = z.infer<typeof KnowledgeBaseSchema>;

/**
 * Knowledge bases aggregate
 */
export const KnowledgeBasesAggregateSchema = z.object({
  knowledge_bases: z.array(KnowledgeBaseSchema).default([]),
});

export type KnowledgeBasesAggregate = z.infer<typeof KnowledgeBasesAggregateSchema>;

// ============================================================================
// Credit Schemas
// ============================================================================

/**
 * Credit transaction record
 */
export const CreditTransactionSchema = z.object({
  id: z.string(),
  amount: z.number(),
  type: z.enum(['top_up', 'deduct']),
  timestamp: z.number(),
  description: z.string(),
  txHash: z.string().optional(),
});

export type CreditTransaction = z.infer<typeof CreditTransactionSchema>;

/**
 * User credit data
 */
export const UserCreditSchema = z.object({
  balance: z.number().default(0),
  transactions: z.array(CreditTransactionSchema).default([]),
});

export type UserCredit = z.infer<typeof UserCreditSchema>;

/**
 * Credit aggregate (backend-managed)
 */
export const CreditAggregateSchema = z.record(z.string(), UserCreditSchema);

export type CreditAggregate = z.infer<typeof CreditAggregateSchema>;

// ============================================================================
// File Entries Aggregate
// ============================================================================

/**
 * File entries aggregate
 */
export const FileEntriesAggregateSchema = z.object({
  files: z.array(FileEntrySchema).default([]),
});

export type FileEntriesAggregate = z.infer<typeof FileEntriesAggregateSchema>;

// ============================================================================
// Security Aggregate
// ============================================================================

/**
 * Sub-account authorization in security aggregate
 */
export const SecurityAggregateSchema = z.object({
  authorizations: z.array(
    z.object({
      address: AddressSchema,
      chain: z.string(),
      channels: z.array(z.string()).optional(),
      post_types: z.array(z.string()).optional(),
      aggregate_keys: z.array(z.string()).optional(),
    })
  ),
});

export type SecurityAggregate = z.infer<typeof SecurityAggregateSchema>;

// ============================================================================
// Aleph Message Types
// ============================================================================

/**
 * Aleph POST message content
 */
export interface AlephPostContent<T = unknown> {
  time: number;
  type: string;
  ref?: string;
  content: T;
}

/**
 * Aleph AGGREGATE content
 */
export interface AlephAggregateContent<T = unknown> {
  key: string;
  content: T;
}

/**
 * Aleph STORE message
 */
export interface AlephStoreMessage {
  item_hash: string;
  size: number;
}

/**
 * Generic Aleph message response
 */
export interface AlephMessage {
  chain: string;
  item_hash: string;
  sender: string;
  type: string;
  channel: string;
  confirmed: boolean;
  content: unknown;
  item_content: string;
  item_type: string;
  signature: string;
  size: number;
  time: number;
}
