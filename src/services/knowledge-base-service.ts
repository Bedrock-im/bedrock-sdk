import { BedrockCore } from '../client/bedrock-core';
import {
  KnowledgeBase,
  KnowledgeBasesAggregateSchema,
  AGGREGATE_KEYS,
} from '../types/schemas';
import { KnowledgeBaseError } from '../types/errors';

/**
 * Knowledge base service for organizing files into collections
 */
export class KnowledgeBaseService {
  private core: BedrockCore;

  constructor(core: BedrockCore) {
    this.core = core;
  }

  /**
   * Initialize knowledge bases aggregate if it doesn't exist
   */
  async setup(): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      await aleph.fetchAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema
      );
    } catch {
      // Create empty aggregate if it doesn't exist
      await aleph.createAggregate(AGGREGATE_KEYS.KNOWLEDGE_BASES, { knowledge_bases: [] });
    }
  }

  /**
   * Fetch all knowledge bases
   */
  async listKnowledgeBases(): Promise<KnowledgeBase[]> {
    const aleph = this.core.getAlephService();

    try {
      const aggregate = await aleph.fetchAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema
      );
      return aggregate.knowledge_bases;
    } catch (error) {
      throw new KnowledgeBaseError(`Failed to fetch knowledge bases: ${(error as Error).message}`);
    }
  }

  /**
   * Get a knowledge base by name
   * @param name - Knowledge base name
   */
  async getKnowledgeBase(name: string): Promise<KnowledgeBase> {
    const kbs = await this.listKnowledgeBases();
    const kb = kbs.find(k => k.name === name);

    if (!kb) {
      throw new KnowledgeBaseError(`Knowledge base not found: ${name}`);
    }

    return kb;
  }

  /**
   * Create a new knowledge base
   * @param name - Knowledge base name
   * @param filePaths - Optional initial file paths
   */
  async createKnowledgeBase(name: string, filePaths: string[] = []): Promise<KnowledgeBase> {
    const aleph = this.core.getAlephService();

    try {
      // Check if knowledge base already exists
      const kbs = await this.listKnowledgeBases();
      const existingKb = kbs.find(k => k.name === name);

      if (existingKb) {
        throw new KnowledgeBaseError(`Knowledge base already exists: ${name}`);
      }

      // Create new knowledge base
      const now = new Date().toISOString();
      const newKb: KnowledgeBase = {
        name,
        file_paths: filePaths,
        created_at: now,
        updated_at: now,
      };

      // Add to knowledge bases aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema,
        async (aggregate) => ({
          knowledge_bases: [...aggregate.knowledge_bases, newKb]
        })
      );

      return newKb;
    } catch (error) {
      if (error instanceof KnowledgeBaseError) {
        throw error;
      }
      throw new KnowledgeBaseError(`Failed to create knowledge base: ${(error as Error).message}`);
    }
  }

  /**
   * Delete a knowledge base
   * @param name - Knowledge base name
   */
  async deleteKnowledgeBase(name: string): Promise<void> {
    const aleph = this.core.getAlephService();

    try {
      // Verify knowledge base exists
      await this.getKnowledgeBase(name);

      // Remove from knowledge bases aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema,
        async (aggregate) => ({
          knowledge_bases: aggregate.knowledge_bases.filter(k => k.name !== name)
        })
      );
    } catch (error) {
      if (error instanceof KnowledgeBaseError) {
        throw error;
      }
      throw new KnowledgeBaseError(`Failed to delete knowledge base: ${(error as Error).message}`);
    }
  }

  /**
   * Rename a knowledge base
   * @param oldName - Current name
   * @param newName - New name
   */
  async renameKnowledgeBase(oldName: string, newName: string): Promise<KnowledgeBase> {
    const aleph = this.core.getAlephService();

    try {
      // Verify old knowledge base exists
      const existingKb = await this.getKnowledgeBase(oldName);

      // Check if new name already exists
      const kbs = await this.listKnowledgeBases();
      if (kbs.some(k => k.name === newName)) {
        throw new KnowledgeBaseError(`Knowledge base already exists: ${newName}`);
      }

      // Update knowledge base
      const updatedKb: KnowledgeBase = {
        ...existingKb,
        name: newName,
        updated_at: new Date().toISOString(),
      };

      // Update in knowledge bases aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema,
        async (aggregate) => ({
          knowledge_bases: aggregate.knowledge_bases.map(k =>
            k.name === oldName ? updatedKb : k
          )
        })
      );

      return updatedKb;
    } catch (error) {
      if (error instanceof KnowledgeBaseError) {
        throw error;
      }
      throw new KnowledgeBaseError(`Failed to rename knowledge base: ${(error as Error).message}`);
    }
  }

  /**
   * Set the files in a knowledge base (replaces all existing files)
   * @param name - Knowledge base name
   * @param filePaths - File paths
   */
  async setFiles(name: string, filePaths: string[]): Promise<KnowledgeBase> {
    const aleph = this.core.getAlephService();

    try {
      // Verify knowledge base exists
      const existingKb = await this.getKnowledgeBase(name);

      // Update knowledge base
      const updatedKb: KnowledgeBase = {
        ...existingKb,
        file_paths: filePaths,
        updated_at: new Date().toISOString(),
      };

      // Update in knowledge bases aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema,
        async (aggregate) => ({
          knowledge_bases: aggregate.knowledge_bases.map(k =>
            k.name === name ? updatedKb : k
          )
        })
      );

      return updatedKb;
    } catch (error) {
      if (error instanceof KnowledgeBaseError) {
        throw error;
      }
      throw new KnowledgeBaseError(`Failed to set files: ${(error as Error).message}`);
    }
  }

  /**
   * Add files to a knowledge base
   * @param name - Knowledge base name
   * @param filePaths - File paths to add
   */
  async addFiles(name: string, filePaths: string[]): Promise<KnowledgeBase> {
    const aleph = this.core.getAlephService();

    try {
      // Verify knowledge base exists
      const existingKb = await this.getKnowledgeBase(name);

      // Add new file paths (avoid duplicates)
      const updatedFilePaths = [...new Set([...existingKb.file_paths, ...filePaths])];

      // Update knowledge base
      const updatedKb: KnowledgeBase = {
        ...existingKb,
        file_paths: updatedFilePaths,
        updated_at: new Date().toISOString(),
      };

      // Update in knowledge bases aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema,
        async (aggregate) => ({
          knowledge_bases: aggregate.knowledge_bases.map(k =>
            k.name === name ? updatedKb : k
          )
        })
      );

      return updatedKb;
    } catch (error) {
      if (error instanceof KnowledgeBaseError) {
        throw error;
      }
      throw new KnowledgeBaseError(`Failed to add files: ${(error as Error).message}`);
    }
  }

  /**
   * Remove files from a knowledge base
   * @param name - Knowledge base name
   * @param filePaths - File paths to remove
   */
  async removeFiles(name: string, filePaths: string[]): Promise<KnowledgeBase> {
    const aleph = this.core.getAlephService();

    try {
      // Verify knowledge base exists
      const existingKb = await this.getKnowledgeBase(name);

      // Remove file paths
      const updatedFilePaths = existingKb.file_paths.filter(
        path => !filePaths.includes(path)
      );

      // Update knowledge base
      const updatedKb: KnowledgeBase = {
        ...existingKb,
        file_paths: updatedFilePaths,
        updated_at: new Date().toISOString(),
      };

      // Update in knowledge bases aggregate
      await aleph.updateAggregate(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        KnowledgeBasesAggregateSchema,
        async (aggregate) => ({
          knowledge_bases: aggregate.knowledge_bases.map(k =>
            k.name === name ? updatedKb : k
          )
        })
      );

      return updatedKb;
    } catch (error) {
      if (error instanceof KnowledgeBaseError) {
        throw error;
      }
      throw new KnowledgeBaseError(`Failed to remove files: ${(error as Error).message}`);
    }
  }

  /**
   * Clear all files from a knowledge base
   * @param name - Knowledge base name
   */
  async clearFiles(name: string): Promise<KnowledgeBase> {
    return await this.setFiles(name, []);
  }
}
