'use client';

import { useState, useRef } from 'react';
import { getDBManager } from '@/lib/indexedDB';

interface FileUploaderProps {
  onScanComplete?: (scanId: string) => void;
}

export default function FileUploader({ onScanComplete }: FileUploaderProps = {}) {
  const [uploadType, setUploadType] = useState<'file' | 'url'>('file');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [url, setUrl] = useState('');
  const [isUploading, setIsUploading] = useState(false);
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setError(null);
    }
  };

  const handleFileUpload = async () => {
    if (!selectedFile) {
      setError('Please select a file');
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      // Step 1: Store file in IndexedDB
      const dbManager = getDBManager();
      const fileReader = new FileReader();
      
      const fileData = await new Promise<string>((resolve) => {
        fileReader.onload = (e) => resolve(e.target?.result as string);
        fileReader.readAsDataURL(selectedFile);
      });

      // Step 2: Create scan record
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Upload failed');
      }

      // Step 3: Save to IndexedDB with file data
      await dbManager.saveScan({
        id: data.scanId,
        fileName: data.fileName,
        status: 'pending',
        fileData: fileData, // Store file data in IndexedDB
      });

      setScanId(data.scanId);
      
      // Step 4: Start scanning with file data
      await handleScan(data.scanId, fileData);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to upload file');
      console.error('Upload error:', err);
    } finally {
      setIsUploading(false);
    }
  };

  const handleUrlSubmit = async () => {
    if (!url) {
      setError('Please enter a URL');
      return;
    }

    setIsUploading(true);
    setError(null);

    try {
      const response = await fetch('/api/submit-url', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'URL submission failed');
      }

      // Save to IndexedDB
      const dbManager = getDBManager();
      await dbManager.saveScan({
        id: data.scanId,
        fileName: 'URL Scan',
        scanUrl: data.url,
        status: 'pending',
      });

      setScanId(data.scanId);
      
      // Start scanning
      await handleScan(data.scanId);

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to submit URL');
      console.error('URL submission error:', err);
    } finally {
      setIsUploading(false);
    }
  };

  const handleScan = async (id: string, fileData?: string) => {
    setIsScanning(true);
    setError(null);

    try {
      const dbManager = getDBManager();
      await dbManager.updateScan(id, { status: 'scanning' });

      // Prepare request body
      const requestBody: { scanId: string; fileData?: string } = { scanId: id };
      
      // If file data exists, include it (for file scans)
      if (fileData) {
        // Extract base64 data from data URL
        const base64Data = fileData.split(',')[1];
        requestBody.fileData = base64Data;
      }

      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Scan failed');
      }

      // Update IndexedDB with results
      await dbManager.updateScan(id, {
        status: 'completed',
        results: data.results,
      });

      // If file is SAFE, upload to Cloudinary for permanent storage
      if (fileData && data.results.threatLevel === 'safe' && selectedFile) {
        try {
          const uploadFormData = new FormData();
          uploadFormData.append('file', selectedFile);
          uploadFormData.append('scanId', id);
          
          const uploadResponse = await fetch('/api/upload-to-cloud', {
            method: 'POST',
            body: uploadFormData,
          });
          
          if (!uploadResponse.ok) {
            const uploadError = await uploadResponse.json().catch(() => ({ error: 'Unknown error' }));
            console.warn('Cloud upload failed:', uploadResponse.status, uploadError);
          } else {
            console.log('✅ Safe file uploaded to permanent cloud storage');
          }
        } catch (uploadError) {
          console.error('Cloud upload error:', uploadError);
          // Don't throw - scan was successful
        }
      } else if (fileData && data.results.threatLevel === 'dangerous') {
        console.log('🚫 Dangerous file kept in IndexedDB only - will be auto-deleted in 5 minutes');
        
        // Mark file for deletion in 5 minutes
        const deleteAt = Date.now() + (5 * 60 * 1000); // 5 minutes from now
        await dbManager.updateScan(id, {
          isDangerous: true,
          deleteAt: deleteAt,
        });
      } else if (fileData && data.results.threatLevel === 'suspicious') {
        console.log('⚠️ Suspicious file kept in IndexedDB only - will be auto-deleted in 5 minutes');
        
        // Mark suspicious files for deletion in 5 minutes too
        const deleteAt = Date.now() + (5 * 60 * 1000);
        await dbManager.updateScan(id, {
          isDangerous: true,
          deleteAt: deleteAt,
        });
      }

      // Notify parent component
      if (onScanComplete) {
        onScanComplete(id);
      }

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to scan');
      console.error('Scan error:', err);
      
      const dbManager = getDBManager();
      await dbManager.updateScan(id, { status: 'error' });
    } finally {
      setIsScanning(false);
    }
  };

  const handleReset = () => {
    setSelectedFile(null);
    setUrl('');
    setScanId(null);
    setError(null);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto p-6 bg-white rounded-lg shadow-lg">
      <h2 className="text-2xl font-bold mb-6 text-gray-800">Threat Detection Scanner</h2>

      {/* Upload Type Toggle */}
      <div className="flex gap-4 mb-6">
        <button
          onClick={() => setUploadType('file')}
          className={`flex-1 py-3 px-6 rounded-lg font-semibold transition-colors ${
            uploadType === 'file'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          Upload File
        </button>
        <button
          onClick={() => setUploadType('url')}
          className={`flex-1 py-3 px-6 rounded-lg font-semibold transition-colors ${
            uploadType === 'url'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-200 text-gray-700 hover:bg-gray-300'
          }`}
        >
          Scan URL
        </button>
      </div>

      {/* File Upload Section */}
      {uploadType === 'file' && (
        <div className="space-y-4">
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center">
            <input
              ref={fileInputRef}
              type="file"
              onChange={handleFileSelect}
              className="hidden"
              id="file-input"
            />
            <label
              htmlFor="file-input"
              className="cursor-pointer flex flex-col items-center"
            >
              <svg
                className="w-16 h-16 text-gray-400 mb-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
                />
              </svg>
              <span className="text-lg text-gray-600">
                {selectedFile ? selectedFile.name : 'Click to select a file'}
              </span>
              <span className="text-sm text-gray-400 mt-2">
                or drag and drop
              </span>
            </label>
          </div>

          <button
            onClick={handleFileUpload}
            disabled={!selectedFile || isUploading || isScanning}
            className="w-full py-3 px-6 bg-green-600 text-white rounded-lg font-semibold hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {isUploading
              ? 'Uploading...'
              : isScanning
              ? 'Scanning...'
              : 'Upload & Scan'}
          </button>
        </div>
      )}

      {/* URL Scan Section */}
      {uploadType === 'url' && (
        <div className="space-y-4">
          <div>
            <label htmlFor="url-input" className="block text-sm font-medium text-gray-700 mb-2">
              Enter URL to scan
            </label>
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="example.com or https://example.com"
              className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          <button
            onClick={handleUrlSubmit}
            disabled={!url || isUploading || isScanning}
            className="w-full py-3 px-6 bg-green-600 text-white rounded-lg font-semibold hover:bg-green-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
          >
            {isUploading
              ? 'Submitting...'
              : isScanning
              ? 'Scanning...'
              : 'Scan URL'}
          </button>
        </div>
      )}

      {/* Error Message */}
      {error && (
        <div className="mt-4 p-4 bg-red-100 border border-red-400 text-red-700 rounded-lg">
          {error}
        </div>
      )}

      {/* Success Message */}
      {scanId && !isScanning && !error && (
        <div className="mt-4 p-4 bg-green-100 border border-green-400 text-green-700 rounded-lg">
          <p className="font-semibold">Scan completed!</p>
          <p className="text-sm mt-1">Scan ID: {scanId}</p>
          <button
            onClick={handleReset}
            className="mt-3 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700"
          >
            Scan Another
          </button>
        </div>
      )}

      {/* Loading Indicator */}
      {(isUploading || isScanning) && (
        <div className="mt-4 flex items-center justify-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          <span className="ml-3 text-gray-600">
            {isUploading ? 'Uploading...' : 'Scanning with VirusTotal & Gemini AI...'}
          </span>
        </div>
      )}
    </div>
  );
}
