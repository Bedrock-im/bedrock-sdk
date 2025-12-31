/**
 * Base error class for Bedrock SDK
 */
export class BedrockError extends Error {
  constructor(message: string, public code?: string) {
    super(message);
    this.name = 'BedrockError';
    Object.setPrototypeOf(this, BedrockError.prototype);
  }
}

/**
 * Authentication/authorization errors
 */
export class AuthenticationError extends BedrockError {
  constructor(message: string) {
    super(message, 'AUTH_ERROR');
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

/**
 * Encryption/decryption errors
 */
export class EncryptionError extends BedrockError {
  constructor(message: string) {
    super(message, 'ENCRYPTION_ERROR');
    this.name = 'EncryptionError';
    Object.setPrototypeOf(this, EncryptionError.prototype);
  }
}

/**
 * File operation errors
 */
export class FileError extends BedrockError {
  constructor(message: string) {
    super(message, 'FILE_ERROR');
    this.name = 'FileError';
    Object.setPrototypeOf(this, FileError.prototype);
  }
}

/**
 * File not found error
 */
export class FileNotFoundError extends FileError {
  constructor(path: string) {
    super(`File not found: ${path}`);
    this.name = 'FileNotFoundError';
    this.code = 'FILE_NOT_FOUND';
    Object.setPrototypeOf(this, FileNotFoundError.prototype);
  }
}

/**
 * Contact-related errors
 */
export class ContactError extends BedrockError {
  constructor(message: string) {
    super(message, 'CONTACT_ERROR');
    this.name = 'ContactError';
    Object.setPrototypeOf(this, ContactError.prototype);
  }
}

/**
 * Knowledge base errors
 */
export class KnowledgeBaseError extends BedrockError {
  constructor(message: string) {
    super(message, 'KB_ERROR');
    this.name = 'KnowledgeBaseError';
    Object.setPrototypeOf(this, KnowledgeBaseError.prototype);
  }
}

/**
 * Credit-related errors
 */
export class CreditError extends BedrockError {
  constructor(message: string) {
    super(message, 'CREDIT_ERROR');
    this.name = 'CreditError';
    Object.setPrototypeOf(this, CreditError.prototype);
  }
}

/**
 * Network/Aleph API errors
 */
export class NetworkError extends BedrockError {
  constructor(message: string) {
    super(message, 'NETWORK_ERROR');
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

/**
 * Validation errors
 */
export class ValidationError extends BedrockError {
  constructor(message: string) {
    super(message, 'VALIDATION_ERROR');
    this.name = 'ValidationError';
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}
