import mongoose, { Schema, Document } from 'mongoose';

export interface IScanResult extends Document {
  fileName: string;
  fileUrl?: string;
  scanUrl?: string;
  fileType: string;
  fileSize: number;
  uploadedAt: Date;
  virusTotalResults?: {
    positives: number;
    total: number;
    scanId: string;
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
  cloudinaryUrl?: string;
  cloudinaryPublicId?: string;
  status: 'pending' | 'scanning' | 'completed' | 'error';
  overallThreatLevel: 'safe' | 'suspicious' | 'dangerous';
}

const ScanResultSchema: Schema = new Schema({
  fileName: {
    type: String,
    required: true,
  },
  fileUrl: {
    type: String,
  },
  scanUrl: {
    type: String,
  },
  fileType: {
    type: String,
    required: true,
  },
  fileSize: {
    type: Number,
    required: true,
  },
  uploadedAt: {
    type: Date,
    default: Date.now,
  },
  virusTotalResults: {
    positives: Number,
    total: Number,
    scanId: String,
    permalink: String,
    detections: [{
      engine: String,
      detected: Boolean,
      result: String,
    }],
  },
  geminiResults: {
    analysis: String,
    riskLevel: {
      type: String,
      enum: ['low', 'medium', 'high', 'critical'],
    },
    threats: [String],
    recommendations: [String],
  },
  cloudinaryUrl: String,
  cloudinaryPublicId: String,
  status: {
    type: String,
    enum: ['pending', 'scanning', 'completed', 'error'],
    default: 'pending',
  },
  overallThreatLevel: {
    type: String,
    enum: ['safe', 'suspicious', 'dangerous'],
    default: 'safe',
  },
});

export default mongoose.models.ScanResult || mongoose.model<IScanResult>('ScanResult', ScanResultSchema);
