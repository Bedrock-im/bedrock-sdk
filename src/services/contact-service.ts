import { BedrockCore } from '../client/bedrock-core';
import {
  Contact,
  ContactsAggregateSchema,
  AGGREGATE_KEYS,
} from '../types/schemas';
import { ContactError } from '../types/errors';
import { FileService } from './file-service';
import type { FileFullInfo } from '../types/schemas';

/**
 * Contact service for managing contacts and shared files
 */
export class ContactService {
  private core: BedrockCore;
  private fileService: FileService;

  constructor(core: BedrockCore, fileService: FileService) {
    this.core = core;
    this.fileService = fileService;
  }

  /**
   * Initialize contacts aggregate if it doesn't exist
   */
  async setup(): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      await aleph.fetchAggregate(
        AGGREGATE_KEYS.CONTACTS,
        ContactsAggregateSchema
      );
    } catch {
      // Create empty aggregate if it doesn't exist
      await aleph.createAggregate(AGGREGATE_KEYS.CONTACTS, []);
    }
  }

  /**
   * Fetch all contacts
   */
  async listContacts(): Promise<Contact[]> {
    const aleph = this.core.getAlephService();

    try {
      const contacts = await aleph.fetchAggregate(
        AGGREGATE_KEYS.CONTACTS,
        ContactsAggregateSchema
      );
      return contacts;
    } catch (error) {
      throw new ContactError(`Failed to fetch contacts: ${(error as Error).message}`);
    }
  }

  /**
   * Get a contact by public key
   * @param publicKey - Contact's public key
   */
  async getContact(publicKey: string): Promise<Contact> {
    const contacts = await this.listContacts();
    const contact = contacts.find(c => c.public_key === publicKey);

    if (!contact) {
      throw new ContactError(`Contact not found: ${publicKey}`);
    }

    return contact;
  }

  /**
   * Get a contact by address
   * @param address - Contact's Ethereum address
   */
  async getContactByAddress(address: string): Promise<Contact> {
    const contacts = await this.listContacts();
    const contact = contacts.find(c => c.address.toLowerCase() === address.toLowerCase());

    if (!contact) {
      throw new ContactError(`Contact not found: ${address}`);
    }

    return contact;
  }

  /**
   * Add a new contact
   * @param name - Contact name
   * @param address - Contact's Ethereum address
   * @param publicKey - Contact's public key (hex string)
   */
  async addContact(name: string, address: string, publicKey: string): Promise<Contact> {
    const aleph = this.core.getAlephService();

    try {
      // Check if contact already exists
      const contacts = await this.listContacts();
      const existingContact = contacts.find(
        c => c.public_key === publicKey || c.address.toLowerCase() === address.toLowerCase()
      );

      if (existingContact) {
        throw new ContactError('Contact already exists');
      }

      // Create new contact
      const newContact: Contact = {
        name,
        address,
        public_key: publicKey,
      };

      // Add to contacts aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.CONTACTS,
        ContactsAggregateSchema,
        (currentContacts) => [...(currentContacts || []), newContact],
        true
      );

      return newContact;
    } catch (error) {
      if (error instanceof ContactError) {
        throw error;
      }
      throw new ContactError(`Failed to add contact: ${(error as Error).message}`);
    }
  }

  /**
   * Remove a contact
   * @param publicKey - Contact's public key
   */
  async removeContact(publicKey: string): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      // Verify contact exists
      await this.getContact(publicKey);

      // Remove from contacts aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.CONTACTS,
        ContactsAggregateSchema,
        (currentContacts) => (currentContacts || []).filter(c => c.public_key !== publicKey),
        true
      );
    } catch (error) {
      if (error instanceof ContactError) {
        throw error;
      }
      throw new ContactError(`Failed to remove contact: ${(error as Error).message}`);
    }
  }

  /**
   * Update a contact's name
   * @param publicKey - Contact's public key
   * @param newName - New name for the contact
   */
  async updateContactName(publicKey: string, newName: string): Promise<Contact> {
    const aleph = this.core.getAlephService();

    try {
      // Verify contact exists
      const existingContact = await this.getContact(publicKey);

      // Update contact
      const updatedContact: Contact = {
        ...existingContact,
        name: newName,
      };

      // Update in contacts aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.CONTACTS,
        ContactsAggregateSchema,
        (currentContacts) => (currentContacts || []).map(c =>
          c.public_key === publicKey ? updatedContact : c
        ),
        true
      );

      return updatedContact;
    } catch (error) {
      if (error instanceof ContactError) {
        throw error;
      }
      throw new ContactError(`Failed to update contact: ${(error as Error).message}`);
    }
  }

  /**
   * Fetch files shared by a contact
   * @param publicKey - Contact's public key
   */
  async getSharedFiles(publicKey: string): Promise<FileFullInfo[]> {
    try {
      // Verify contact exists
      await this.getContact(publicKey);

      // Fetch file entries
      const entries = await this.fileService.fetchFileEntries();

      // Filter entries shared with this contact
      const sharedEntries = entries.filter(entry =>
        entry.shared_with.includes(publicKey)
      );

      // Fetch metadata for shared files
      const files = await this.fileService.fetchFilesMetaFromEntries(sharedEntries);

      return files;
    } catch (error) {
      throw new ContactError(`Failed to fetch shared files: ${(error as Error).message}`);
    }
  }

  /**
   * Share a file with a contact
   * @param filePath - Path of the file to share
   * @param publicKey - Contact's public key
   */
  async shareFileWithContact(filePath: string, publicKey: string): Promise<void> {
    try {
      // Verify contact exists
      await this.getContact(publicKey);

      // Share the file
      await this.fileService.shareFile(filePath, publicKey);
    } catch (error) {
      throw new ContactError(`Failed to share file with contact: ${(error as Error).message}`);
    }
  }

  /**
   * Unshare a file with a contact
   * @param filePath - Path of the file to unshare
   * @param publicKey - Contact's public key
   */
  async unshareFileWithContact(filePath: string, publicKey: string): Promise<void> {
    try {
      // Verify contact exists
      await this.getContact(publicKey);

      // Unshare the file
      await this.fileService.unshareFile(filePath, publicKey);
    } catch (error) {
      throw new ContactError(`Failed to unshare file with contact: ${(error as Error).message}`);
    }
  }
}
