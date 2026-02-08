
import {
  BedrockError,
  AuthenticationError,
  EncryptionError,
  FileError,
  FileNotFoundError,
  FileConflictError,
  ContactError,
  KnowledgeBaseError,
  CreditError,
  NetworkError,
  ValidationError,
} from '../src/types/errors';

describe('Error classes', () => {
  describe('BedrockError', () => {
    it('sets message and name', () => {
      const err = new BedrockError('test');
      expect(err.message).toBe('test');
      expect(err.name).toBe('BedrockError');
      expect(err).toBeInstanceOf(Error);
    });

    it('accepts optional code', () => {
      const err = new BedrockError('test', 'CUSTOM');
      expect(err.code).toBe('CUSTOM');
    });
  });

  const errorCases: Array<[string, new (msg: string) => BedrockError, string, string]> = [
    ['AuthenticationError', AuthenticationError, 'AUTH_ERROR', 'AuthenticationError'],
    ['EncryptionError', EncryptionError, 'ENCRYPTION_ERROR', 'EncryptionError'],
    ['FileError', FileError, 'FILE_ERROR', 'FileError'],
    ['ContactError', ContactError, 'CONTACT_ERROR', 'ContactError'],
    ['KnowledgeBaseError', KnowledgeBaseError, 'KB_ERROR', 'KnowledgeBaseError'],
    ['CreditError', CreditError, 'CREDIT_ERROR', 'CreditError'],
    ['NetworkError', NetworkError, 'NETWORK_ERROR', 'NetworkError'],
    ['ValidationError', ValidationError, 'VALIDATION_ERROR', 'ValidationError'],
  ];

  for (const [label, ErrorClass, code, name] of errorCases) {
    describe(label, () => {
      it('sets code, name, and extends BedrockError', () => {
        const err = new ErrorClass('msg');
        expect(err.code).toBe(code);
        expect(err.name).toBe(name);
        expect(err.message).toBe('msg');
        expect(err).toBeInstanceOf(BedrockError);
        expect(err).toBeInstanceOf(Error);
      });
    });
  }

  describe('FileNotFoundError', () => {
    it('includes path in message, overrides code', () => {
      const err = new FileNotFoundError('/docs/file.txt');
      expect(err.message).toBe('File not found: /docs/file.txt');
      expect(err.code).toBe('FILE_NOT_FOUND');
      expect(err.name).toBe('FileNotFoundError');
    });

    it('prototype chain: FileNotFoundError -> FileError -> BedrockError -> Error', () => {
      const err = new FileNotFoundError('x');
      expect(err).toBeInstanceOf(FileNotFoundError);
      expect(err).toBeInstanceOf(FileError);
      expect(err).toBeInstanceOf(BedrockError);
      expect(err).toBeInstanceOf(Error);
    });
  });

  describe('FileConflictError', () => {
    it('includes path in message, overrides code', () => {
      const err = new FileConflictError('/docs/dup.txt');
      expect(err.message).toBe('File path conflict: /docs/dup.txt already exists');
      expect(err.code).toBe('FILE_CONFLICT');
      expect(err.name).toBe('FileConflictError');
    });

    it('prototype chain: FileConflictError -> FileError -> BedrockError -> Error', () => {
      const err = new FileConflictError('x');
      expect(err).toBeInstanceOf(FileConflictError);
      expect(err).toBeInstanceOf(FileError);
      expect(err).toBeInstanceOf(BedrockError);
      expect(err).toBeInstanceOf(Error);
    });
  });
});
