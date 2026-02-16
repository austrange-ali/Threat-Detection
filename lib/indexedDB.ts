import { openDB, DBSchema, IDBPDatabase } from 'idb';

interface TempScanDB extends DBSchema {
  scans: {
    key: string;
    value: {
      id: string;
      fileName: string;
      fileUrl?: string;
      scanUrl?: string;
      fileData?: string; // Base64 encoded file data
      timestamp: number;
      status: string;
      results?: any;
      isDangerous?: boolean; // Flag for dangerous files
      deleteAt?: number; // Timestamp for when to delete
    };
    indexes: { 'by-timestamp': number };
  };
}

const DB_NAME = 'ThreatDetectionDB';
const DB_VERSION = 1;
const STORE_NAME = 'scans';
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours for safe files
const DANGEROUS_FILE_AGE_MS = 5 * 60 * 1000; // 5 minutes for dangerous files

class IndexedDBManager {
  private dbPromise: Promise<IDBPDatabase<TempScanDB>>;

  constructor() {
    this.dbPromise = this.initDB();
    this.startAutoCleanup();
  }

  private async initDB(): Promise<IDBPDatabase<TempScanDB>> {
    return openDB<TempScanDB>(DB_NAME, DB_VERSION, {
      upgrade(db) {
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          const store = db.createObjectStore(STORE_NAME, { keyPath: 'id' });
          store.createIndex('by-timestamp', 'timestamp');
        }
      },
    });
  }

  async saveScan(scanData: {
    id: string;
    fileName: string;
    fileUrl?: string;
    scanUrl?: string;
    fileData?: string;
    status: string;
    results?: any;
    isDangerous?: boolean;
    deleteAt?: number;
  }) {
    const db = await this.dbPromise;
    await db.put(STORE_NAME, {
      ...scanData,
      timestamp: Date.now(),
    });
  }

  async getScan(id: string) {
    const db = await this.dbPromise;
    return db.get(STORE_NAME, id);
  }

  async getAllScans() {
    const db = await this.dbPromise;
    return db.getAll(STORE_NAME);
  }

  async updateScan(id: string, updates: Partial<{
    isDangerous: boolean;
    deleteAt: number;
    status: string;
    results: any;
  }>) {
    const db = await this.dbPromise;
    const existing = await db.get(STORE_NAME, id);
    
    if (existing) {
      await db.put(STORE_NAME, {
        ...existing,
        ...updates,
        timestamp: Date.now(), // Update timestamp
      });
    }
  }

  async deleteScan(id: string) {
    const db = await this.dbPromise;
    await db.delete(STORE_NAME, id);
  }

  async cleanupOldScans() {
    const db = await this.dbPromise;
    const allScans = await db.getAll(STORE_NAME);
    const now = Date.now();
    let deletedCount = 0;

    for (const scan of allScans) {
      // Check if file has a custom deleteAt timestamp
      if (scan.deleteAt && now >= scan.deleteAt) {
        await db.delete(STORE_NAME, scan.id);
        deletedCount++;
        console.log(`Deleted dangerous file: ${scan.fileName} (${scan.id})`);
      }
      // Otherwise use default 24-hour retention
      else if (!scan.deleteAt && now - scan.timestamp > MAX_AGE_MS) {
        await db.delete(STORE_NAME, scan.id);
        deletedCount++;
      }
    }

    console.log(`Cleaned up ${deletedCount} old scans from IndexedDB`);
    return deletedCount;
  }

  async clearAll() {
    const db = await this.dbPromise;
    await db.clear(STORE_NAME);
  }

  async getStorageInfo() {
    const db = await this.dbPromise;
    const allScans = await db.getAll(STORE_NAME);
    const now = Date.now();
    
    const stats = {
      total: allScans.length,
      old: allScans.filter(s => now - s.timestamp > MAX_AGE_MS).length,
      recent: allScans.filter(s => now - s.timestamp <= MAX_AGE_MS).length,
      oldestTimestamp: allScans.length > 0 ? Math.min(...allScans.map(s => s.timestamp)) : null,
      newestTimestamp: allScans.length > 0 ? Math.max(...allScans.map(s => s.timestamp)) : null,
    };

    return stats;
  }

  private startAutoCleanup() {
    // Run cleanup every 1 minute to catch dangerous files quickly
    setInterval(() => {
      this.cleanupOldScans().catch(console.error);
    }, 60 * 60 * 1000);

    // Also run cleanup on initialization
    this.cleanupOldScans().catch(console.error);
  }
}

// Singleton instance
let dbManager: IndexedDBManager | null = null;

export function getDBManager(): IndexedDBManager {
  if (typeof window === 'undefined') {
    throw new Error('IndexedDB can only be used in the browser');
  }
  
  if (!dbManager) {
    dbManager = new IndexedDBManager();
  }
  
  return dbManager;
}

export default IndexedDBManager;
