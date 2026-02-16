# Usage Examples

## Basic File Upload and Scan

```typescript
// Upload a file
const formData = new FormData();
formData.append('file', selectedFile);

const response = await fetch('/api/upload', {
  method: 'POST',
  body: formData,
});

const { scanId } = await response.json();

// Scan the file
await fetch('/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ scanId }),
});
```

## URL Scanning

```typescript
// Submit URL
const response = await fetch('/api/submit-url', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: 'https://example.com' }),
});

const { scanId } = await response.json();

// Scan the URL
await fetch('/api/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ scanId }),
});
```

## Working with IndexedDB

```typescript
import { getDBManager } from '@/lib/indexedDB';

// Get the database manager
const dbManager = getDBManager();

// Save a scan to IndexedDB
await dbManager.saveScan({
  id: 'scan-123',
  fileName: 'document.pdf',
  fileUrl: 'https://cloudinary.com/...',
  status: 'pending',
});

// Update scan status
await dbManager.updateScan('scan-123', {
  status: 'completed',
  results: { /* scan results */ },
});

// Get a specific scan
const scan = await dbManager.getScan('scan-123');

// Get all scans
const allScans = await dbManager.getAllScans();

// Get storage statistics
const stats = await dbManager.getStorageInfo();
console.log(`Total: ${stats.total}, Old: ${stats.old}`);

// Manual cleanup
const deletedCount = await dbManager.cleanupOldScans();
console.log(`Deleted ${deletedCount} old scans`);

// Clear all data
await dbManager.clearAll();
```

## Interpreting Scan Results

### VirusTotal Results

```typescript
{
  positives: 5,           // Number of engines that detected threats
  total: 70,             // Total number of engines
  scanId: "abc123",
  permalink: "https://virustotal.com/...",
  detections: [
    {
      engine: "Kaspersky",
      detected: true,
      result: "Trojan.Win32.Generic"
    },
    // ... more detections
  ]
}
```

**Interpretation:**
- `positives: 0` - Likely safe
- `positives: 1-3` - Suspicious, possible false positive
- `positives: 4+` - High risk, likely malicious

### Gemini AI Results

```typescript
{
  analysis: "Detailed threat analysis...",
  riskLevel: "high",    // low, medium, high, critical
  threats: [
    "Potential malware detected",
    "Suspicious file behavior"
  ],
  recommendations: [
    "Do not execute this file",
    "Scan with updated antivirus"
  ]
}
```

### Overall Threat Level

- **safe**: No threats detected
- **suspicious**: Some concerns, manual review recommended
- **dangerous**: High threat level, avoid using

## Example: Complete Scan Flow

```typescript
'use client';

import { useState } from 'react';
import { getDBManager } from '@/lib/indexedDB';

export function ScanExample() {
  const [status, setStatus] = useState('idle');

  const scanFile = async (file: File) => {
    const dbManager = getDBManager();

    try {
      // 1. Upload file
      setStatus('uploading');
      const formData = new FormData();
      formData.append('file', file);
      
      const uploadRes = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });
      const { scanId } = await uploadRes.json();

      // 2. Save to IndexedDB
      await dbManager.saveScan({
        id: scanId,
        fileName: file.name,
        status: 'pending',
      });

      // 3. Start scan
      setStatus('scanning');
      await dbManager.updateScan(scanId, { status: 'scanning' });
      
      const scanRes = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId }),
      });
      const { results } = await scanRes.json();

      // 4. Update with results
      setStatus('completed');
      await dbManager.updateScan(scanId, {
        status: 'completed',
        results,
      });

      return results;

    } catch (error) {
      setStatus('error');
      throw error;
    }
  };

  return (
    <div>
      <p>Status: {status}</p>
      {/* UI components */}
    </div>
  );
}
```

## Storage Manager Component Usage

```typescript
import StorageManager from '@/components/StorageManager';

export default function SettingsPage() {
  return (
    <div>
      <h1>Settings</h1>
      <StorageManager />
    </div>
  );
}
```

The StorageManager component provides:
- View storage statistics
- Manual cleanup trigger
- Clear all data option
- Auto-refresh capability

## Automatic Cleanup

IndexedDB automatically cleans up scans older than 24 hours:

```typescript
// In lib/indexedDB.ts
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// Cleanup runs every hour
setInterval(() => {
  this.cleanupOldScans().catch(console.error);
}, 60 * 60 * 1000);
```

To adjust the retention period, modify `MAX_AGE_MS` in `lib/indexedDB.ts`.

## Best Practices

1. **Rate Limiting**: VirusTotal free tier allows 4 requests/minute
2. **Error Handling**: Always wrap API calls in try-catch blocks
3. **User Feedback**: Show loading states during scans (can take 30-60 seconds)
4. **Storage Management**: Periodically check storage stats
5. **File Size**: Consider adding file size limits for uploads
6. **Validation**: Always validate URLs before scanning

## Common Patterns

### Retry Failed Scans

```typescript
async function scanWithRetry(scanId: string, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scanId }),
      });
      
      if (response.ok) return await response.json();
      
      if (i < maxRetries - 1) {
        await new Promise(resolve => setTimeout(resolve, 2000 * (i + 1)));
      }
    } catch (error) {
      if (i === maxRetries - 1) throw error;
    }
  }
}
```

### Batch URL Scanning

```typescript
async function scanUrls(urls: string[]) {
  const results = [];
  
  for (const url of urls) {
    // Submit URL
    const submitRes = await fetch('/api/submit-url', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
    });
    const { scanId } = await submitRes.json();
    
    // Wait to respect rate limits
    await new Promise(resolve => setTimeout(resolve, 15000)); // 15 seconds
    
    // Scan URL
    const scanRes = await fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scanId }),
    });
    
    results.push(await scanRes.json());
  }
  
  return results;
}
```
