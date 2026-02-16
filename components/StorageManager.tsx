'use client';

import { useState, useEffect } from 'react';
import { getDBManager } from '@/lib/indexedDB';

export default function StorageManager() {
  const [stats, setStats] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    loadStats();
  }, []);

  const loadStats = async () => {
    try {
      const dbManager = getDBManager();
      const storageInfo = await dbManager.getStorageInfo();
      setStats(storageInfo);
    } catch (error) {
      console.error('Failed to load storage stats:', error);
    }
  };

  const handleCleanup = async () => {
    setIsLoading(true);
    try {
      const dbManager = getDBManager();
      const deleted = await dbManager.cleanupOldScans();
      alert(`Cleaned up ${deleted} old scan(s)`);
      await loadStats();
    } catch (error) {
      console.error('Cleanup failed:', error);
      alert('Failed to cleanup old scans');
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearAll = async () => {
    if (!confirm('Are you sure you want to delete all scan data from local storage?')) {
      return;
    }

    setIsLoading(true);
    try {
      const dbManager = getDBManager();
      await dbManager.clearAll();
      alert('All scan data cleared');
      await loadStats();
    } catch (error) {
      console.error('Clear all failed:', error);
      alert('Failed to clear all data');
    } finally {
      setIsLoading(false);
    }
  };

  if (!stats) {
    return (
      <div className="bg-white rounded-lg shadow-lg p-6">
        <p className="text-gray-600">Loading storage info...</p>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg shadow-lg p-6">
      <h3 className="text-xl font-bold mb-4 text-gray-800">Local Storage Manager</h3>
      
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-blue-50 p-4 rounded-lg">
          <p className="text-sm text-gray-600">Total Scans</p>
          <p className="text-2xl font-bold text-blue-600">{stats.total}</p>
        </div>
        <div className="bg-green-50 p-4 rounded-lg">
          <p className="text-sm text-gray-600">Recent</p>
          <p className="text-2xl font-bold text-green-600">{stats.recent}</p>
        </div>
        <div className="bg-yellow-50 p-4 rounded-lg">
          <p className="text-sm text-gray-600">Old (24h+)</p>
          <p className="text-2xl font-bold text-yellow-600">{stats.old}</p>
        </div>
        <div className="bg-purple-50 p-4 rounded-lg">
          <p className="text-sm text-gray-600">Status</p>
          <p className="text-lg font-semibold text-purple-600">
            {stats.old > 0 ? 'Cleanup Available' : 'Clean'}
          </p>
        </div>
      </div>

      {stats.oldestTimestamp && (
        <div className="mb-4 text-sm text-gray-600">
          <p>Oldest scan: {new Date(stats.oldestTimestamp).toLocaleString()}</p>
          <p>Newest scan: {new Date(stats.newestTimestamp).toLocaleString()}</p>
        </div>
      )}

      <div className="flex gap-3">
        <button
          onClick={handleCleanup}
          disabled={isLoading || stats.old === 0}
          className="px-4 py-2 bg-yellow-600 text-white rounded hover:bg-yellow-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {isLoading ? 'Cleaning...' : `Cleanup Old Scans (${stats.old})`}
        </button>
        
        <button
          onClick={handleClearAll}
          disabled={isLoading || stats.total === 0}
          className="px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          {isLoading ? 'Clearing...' : 'Clear All'}
        </button>

        <button
          onClick={loadStats}
          disabled={isLoading}
          className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
        >
          Refresh
        </button>
      </div>

      <div className="mt-4 p-3 bg-blue-50 rounded text-sm text-blue-800">
        <p className="font-semibold">ℹ️ Auto-Cleanup Enabled</p>
        <p className="mt-1">Scans older than 24 hours are automatically removed every hour.</p>
      </div>
    </div>
  );
}
