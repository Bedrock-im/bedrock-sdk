
import { KnowledgeBaseService } from '../src/services/knowledge-base-service';
import { KnowledgeBaseError } from '../src/types/errors';
import { AGGREGATE_KEYS } from '../src/types/schemas';
import { createMockCore, type MockCore } from './helpers/mock-core';

describe('KnowledgeBaseService', () => {
  let service: KnowledgeBaseService;
  let mockCore: MockCore;

  const makeKb = (name: string, files: string[] = []) => ({
    name,
    file_paths: files,
    created_at: '2024-01-01T00:00:00.000Z',
    updated_at: '2024-01-01T00:00:00.000Z',
  });

  beforeEach(() => {
    mockCore = createMockCore();
    service = new KnowledgeBaseService(mockCore as any);

    // Default: empty aggregate
    mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [] });
    mockCore._mockAleph.updateAggregate.mockImplementation(
      async (_key: string, _schema: any, cb: (content: any) => Promise<any>) => {
        const currentData = await mockCore._mockAleph.fetchAggregate(AGGREGATE_KEYS.KNOWLEDGE_BASES, null as any);
        await cb(currentData);
        return { item_hash: 'updated' };
      }
    );
  });

  describe('setup', () => {
    it('fetches existing aggregate', async () => {
      await service.setup();
      expect(mockCore._mockAleph.fetchAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        expect.anything()
      );
    });

    it('creates empty aggregate on fetch failure', async () => {
      mockCore._mockAleph.fetchAggregate.mockRejectedValueOnce(new Error('not found'));
      await service.setup();
      expect(mockCore._mockAleph.createAggregate).toHaveBeenCalledWith(
        AGGREGATE_KEYS.KNOWLEDGE_BASES,
        { knowledge_bases: [] }
      );
    });
  });

  describe('listKnowledgeBases', () => {
    it('returns array from aggregate', async () => {
      const kb = makeKb('test');
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [kb] });
      const result = await service.listKnowledgeBases();
      expect(result).toEqual([kb]);
    });
  });

  describe('getKnowledgeBase', () => {
    it('returns match by name', async () => {
      const kb = makeKb('myKB');
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [kb] });
      const result = await service.getKnowledgeBase('myKB');
      expect(result.name).toBe('myKB');
    });

    it('throws KnowledgeBaseError if not found', async () => {
      await expect(service.getKnowledgeBase('missing')).rejects.toThrow(KnowledgeBaseError);
    });
  });

  describe('createKnowledgeBase', () => {
    it('creates with name + timestamps', async () => {
      const result = await service.createKnowledgeBase('newKB');
      expect(result.name).toBe('newKB');
      expect(result.created_at).toBeTruthy();
      expect(result.updated_at).toBeTruthy();
      expect(result.file_paths).toEqual([]);
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();
    });

    it('creates with initial file paths', async () => {
      const result = await service.createKnowledgeBase('kb', ['/a', '/b']);
      expect(result.file_paths).toEqual(['/a', '/b']);
    });

    it('throws if name exists', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('dup')] });
      await expect(service.createKnowledgeBase('dup')).rejects.toThrow(KnowledgeBaseError);
      await expect(service.createKnowledgeBase('dup')).rejects.toThrow('already exists');
    });
  });

  describe('deleteKnowledgeBase', () => {
    it('removes from aggregate', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('del')] });
      await service.deleteKnowledgeBase('del');
      expect(mockCore._mockAleph.updateAggregate).toHaveBeenCalled();
    });

    it('throws if not found', async () => {
      await expect(service.deleteKnowledgeBase('nope')).rejects.toThrow(KnowledgeBaseError);
    });
  });

  describe('renameKnowledgeBase', () => {
    it('updates name + updated_at', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('old')] });
      const result = await service.renameKnowledgeBase('old', 'new');
      expect(result.name).toBe('new');
      expect(result.updated_at).not.toBe('2024-01-01T00:00:00.000Z');
    });

    it('throws if old not found', async () => {
      await expect(service.renameKnowledgeBase('missing', 'new')).rejects.toThrow(KnowledgeBaseError);
    });

    it('throws if new name exists', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({
        knowledge_bases: [makeKb('old'), makeKb('taken')],
      });
      await expect(service.renameKnowledgeBase('old', 'taken')).rejects.toThrow(KnowledgeBaseError);
      await expect(service.renameKnowledgeBase('old', 'taken')).rejects.toThrow('already exists');
    });
  });

  describe('setFiles', () => {
    it('replaces file_paths', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('kb', ['/old'])] });
      const result = await service.setFiles('kb', ['/new1', '/new2']);
      expect(result.file_paths).toEqual(['/new1', '/new2']);
    });
  });

  describe('addFiles', () => {
    it('appends unique paths (deduplicates)', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('kb', ['/a'])] });
      const result = await service.addFiles('kb', ['/a', '/b']);
      expect(result.file_paths).toEqual(['/a', '/b']);
    });
  });

  describe('removeFiles', () => {
    it('filters out specified paths', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('kb', ['/a', '/b', '/c'])] });
      const result = await service.removeFiles('kb', ['/b']);
      expect(result.file_paths).toEqual(['/a', '/c']);
    });
  });

  describe('clearFiles', () => {
    it('delegates to setFiles([])', async () => {
      mockCore._mockAleph.fetchAggregate.mockResolvedValue({ knowledge_bases: [makeKb('kb', ['/a'])] });
      const result = await service.clearFiles('kb');
      expect(result.file_paths).toEqual([]);
    });
  });
});
