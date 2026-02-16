'use client';

import { useState, useEffect } from 'react';
import { getDBManager } from '@/lib/indexedDB';

interface ScanResultsProps {
  scanId?: string;
}

interface ScanData {
  fileName: string;
  fileUrl?: string;
  scanUrl?: string;
  status: string;
  virusTotalResults?: {
    positives: number;
    total: number;
    permalink: string;
    detections: Array<{
      engine: string;
      detected: boolean;
      result: string | null;
    }>;
  };
  geminiResults?: {
    analysis: string;
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    threats: string[];
    recommendations: string[];
  };
  overallThreatLevel: 'safe' | 'suspicious' | 'dangerous';
}

export default function ScanResults({ scanId }: ScanResultsProps) {
  const [scanData, setScanData] = useState<ScanData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (scanId) {
      loadScanResults();
    }
  }, [scanId]);

  const loadScanResults = async () => {
    if (!scanId) return;

    setLoading(true);
    setError(null);

    try {
      // Always fetch from API for complete data
      const response = await fetch(`/api/results?scanId=${scanId}`);
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || 'Failed to load results');
      }

      console.log('Loaded scan data:', data.result);
      setScanData(data.result);

    } catch (err: any) {
      setError(err.message || 'Failed to load scan results');
      console.error('Load results error:', err);
    } finally {
      setLoading(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center p-8">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-4 bg-red-100 border border-red-400 text-red-700 rounded-lg">
        {error}
      </div>
    );
  }

  if (!scanData) {
    return null;
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'safe':
        return 'text-green-600 bg-green-100';
      case 'suspicious':
        return 'text-yellow-600 bg-yellow-100';
      case 'dangerous':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'low':
        return 'text-green-600 bg-green-100';
      case 'medium':
        return 'text-yellow-600 bg-yellow-100';
      case 'high':
        return 'text-orange-600 bg-orange-100';
      case 'critical':
        return 'text-red-600 bg-red-100';
      default:
        return 'text-gray-600 bg-gray-100';
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-lg p-6">
        <h2 className="text-2xl font-bold mb-4 text-gray-800">Scan Results</h2>
        <div className="space-y-2">
          <p className="text-gray-600">
            <span className="font-semibold">File:</span> {scanData.fileName}
          </p>
          {scanData.scanUrl && (
            <p className="text-gray-600">
              <span className="font-semibold">URL:</span>{' '}
              <a href={scanData.scanUrl} target="_blank" rel="noopener noreferrer" className="text-blue-600 hover:underline">
                {scanData.scanUrl}
              </a>
            </p>
          )}
          <div className="flex items-center gap-2">
            <span className="font-semibold text-gray-600">Overall Threat Level:</span>
            <span className={`px-3 py-1 rounded-full font-semibold uppercase text-sm ${getThreatColor(scanData.overallThreatLevel)}`}>
              {scanData.overallThreatLevel}
            </span>
          </div>
        </div>
      </div>

      {/* VirusTotal Results */}
      {scanData.virusTotalResults && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold mb-4 text-gray-800">VirusTotal Scan</h3>
          
          <div className="mb-4">
            <div className="flex items-center gap-4 mb-2">
              <span className="text-3xl font-bold text-gray-800">
                {scanData.virusTotalResults.positives}/{scanData.virusTotalResults.total}
              </span>
              <span className="text-gray-600">security vendors flagged this as malicious</span>
            </div>
            
            {scanData.virusTotalResults.permalink && (
              <a
                href={scanData.virusTotalResults.permalink}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline text-sm"
              >
                View full report on VirusTotal →
              </a>
            )}
          </div>

          {/* Detection Details */}
          {scanData.virusTotalResults.detections && scanData.virusTotalResults.detections.length > 0 && (
            <div>
              <h4 className="font-semibold mb-2 text-gray-700">Detection Details</h4>
              <div className="max-h-64 overflow-y-auto border border-gray-200 rounded">
                <table className="w-full text-sm">
                  <thead className="bg-gray-50 sticky top-0">
                    <tr>
                      <th className="px-4 py-2 text-left">Engine</th>
                      <th className="px-4 py-2 text-left">Result</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scanData.virusTotalResults.detections
                      .filter(d => d.detected)
                      .map((detection, index) => (
                        <tr key={index} className="border-t border-gray-200">
                          <td className="px-4 py-2">{detection.engine}</td>
                          <td className="px-4 py-2 text-red-600">{detection.result || 'Malicious'}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Gemini AI Analysis */}
      {scanData.geminiResults && (
        <div className="bg-white rounded-lg shadow-lg p-6">
          <h3 className="text-xl font-bold mb-4 text-gray-800">AI Security Analysis</h3>
          
          <div className="mb-4 flex items-center gap-2">
            <span className="font-semibold text-gray-600">Risk Level:</span>
            <span className={`px-3 py-1 rounded-full font-semibold uppercase text-sm ${getRiskColor(scanData.geminiResults.riskLevel)}`}>
              {scanData.geminiResults.riskLevel}
            </span>
          </div>

          <div className="space-y-4">
            <div>
              <h4 className="font-semibold mb-2 text-gray-700">Analysis</h4>
              <p className="text-gray-600 whitespace-pre-wrap">{scanData.geminiResults.analysis}</p>
            </div>

            {scanData.geminiResults.threats && scanData.geminiResults.threats.length > 0 && (
              <div>
                <h4 className="font-semibold mb-2 text-gray-700">Identified Threats</h4>
                <ul className="list-disc list-inside space-y-1">
                  {scanData.geminiResults.threats.map((threat, index) => (
                    <li key={index} className="text-gray-600">{threat}</li>
                  ))}
                </ul>
              </div>
            )}

            {scanData.geminiResults.recommendations && scanData.geminiResults.recommendations.length > 0 && (
              <div>
                <h4 className="font-semibold mb-2 text-gray-700">Recommendations</h4>
                <ul className="list-disc list-inside space-y-1">
                  {scanData.geminiResults.recommendations.map((rec, index) => (
                    <li key={index} className="text-gray-600">{rec}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
