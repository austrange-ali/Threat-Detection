'use client';

import { useState } from 'react';
import FileUploader from '@/components/FileUploader';
import ScanResults from '@/components/ScanResults';

export default function Home() {
  const [currentScanId, setCurrentScanId] = useState<string | null>(null);
  const [showResults, setShowResults] = useState(false);

  const handleScanComplete = (scanId: string) => {
    setCurrentScanId(scanId);
    setShowResults(true);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
      <div className="max-w-7xl mx-auto">
        <header className="text-center mb-12">
          <h1 className="text-4xl font-bold text-gray-900 mb-4">
            Threat Detection System
          </h1>
          <p className="text-lg text-gray-600">
            Powered by VirusTotal & Gemini AI
          </p>
        </header>

        <div className="space-y-8">
          {/* File Uploader */}
          <FileUploader onScanComplete={handleScanComplete} />

          {/* Scan Results */}
          {currentScanId && showResults && (
            <ScanResults scanId={currentScanId} />
          )}
        </div>

        {/* Info Section */}
        <div className="mt-12 bg-white rounded-lg shadow-lg p-6">
          <h2 className="text-xl font-bold mb-4 text-gray-800">Features</h2>
          <ul className="grid md:grid-cols-2 gap-4 text-gray-600">
            <li className="flex items-start gap-2">
              <svg className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>Real-time VirusTotal scanning with 70+ antivirus engines</span>
            </li>
            <li className="flex items-start gap-2">
              <svg className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>AI-powered threat analysis using Gemini</span>
            </li>
            <li className="flex items-start gap-2">
              <svg className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>Secure file storage with Cloudinary</span>
            </li>
            <li className="flex items-start gap-2">
              <svg className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>Local IndexedDB cache with automatic cleanup</span>
            </li>
            <li className="flex items-start gap-2">
              <svg className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>URL and file scanning support</span>
            </li>
            <li className="flex items-start gap-2">
              <svg className="w-6 h-6 text-green-600 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
              <span>MongoDB persistence for scan history</span>
            </li>
          </ul>
        </div>
      </div>
    </div>
  );
}
