# Threat Detection System

A Next.js-based threat detection system that scans files and URLs using VirusTotal and Gemini AI, with MongoDB persistence, Cloudinary storage, and IndexedDB caching with automatic cleanup.

## Features

- 🔍 **File & URL Scanning**: Upload files or submit URLs for comprehensive security analysis
- 🛡️ **VirusTotal Integration**: Leverage 70+ antivirus engines for malware detection
- 🤖 **AI-Powered Analysis**: Get intelligent threat assessments from Google's Gemini AI
- ☁️ **Cloudinary Storage**: Secure cloud storage for uploaded files
- 💾 **MongoDB Persistence**: Store scan history and results in MongoDB
- 🗄️ **IndexedDB Caching**: Local temporary storage with automatic cleanup (24-hour retention)
- 🎨 **Modern UI**: Clean, responsive interface built with Tailwind CSS

## Tech Stack

- **Frontend**: Next.js 15+ with TypeScript
- **Styling**: Tailwind CSS
- **Database**: MongoDB (via Mongoose)
- **Cloud Storage**: Cloudinary
- **Security Scanning**: VirusTotal API
- **AI Analysis**: Google Gemini AI
- **Local Storage**: IndexedDB (with automatic cleanup)

## Prerequisites

- Node.js 18+ installed
- MongoDB database (cloud via MongoDB Atlas)
- Cloudinary account
- VirusTotal API key
- Google Gemini API key

## Setup Instructions

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

The `.env` file has been pre-configured. You need to add your Gemini API key:

```env
# MongoDB - Already configured
MONGODB_URI=

# VirusTotal - Already configured
VIRUSTOTAL_API_KEY=

# Cloudinary - Already configured
CLOUDINARY_CLOUD_NAME=
CLOUDINARY_API_KEY=
CLOUDINARY_API_SECRET=

# Gemini AI - ADD YOUR KEY HERE
GEMINI_API_KEY=your_gemini_api_key_here
```

### 3. Get Gemini API Key

- Sign in with your Google account
- Create an API key for Gemini
- Copy and paste it into the `.env` file

### 4. Run the Development Server

```bash
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser.

## Project Structure

```
refsecuresme/
├── app/
│   ├── api/
│   │   ├── upload/route.ts          # File upload endpoint
│   │   ├── submit-url/route.ts      # URL submission endpoint
│   │   ├── scan/route.ts            # Scanning logic (VirusTotal + Gemini)
│   │   └── results/route.ts         # Get scan results
│   ├── layout.tsx
│   └── page.tsx                     # Main page
├── components/
│   ├── FileUploader.tsx             # File/URL upload component
│   ├── ScanResults.tsx              # Results display component
│   └── StorageManager.tsx           # IndexedDB cleanup utility
├── lib/
│   ├── mongodb.ts                   # MongoDB connection
│   └── indexedDB.ts                 # IndexedDB manager with auto-cleanup
├── models/
│   └── ScanResult.ts                # MongoDB schema
├── types/
│   └── global.d.ts                  # TypeScript definitions
└── .env                             # Environment variables
```

## How It Works

### 1. File/URL Upload
- User uploads a file or submits a URL
- Files are stored in Cloudinary
- Initial scan record created in MongoDB
- Scan data cached in IndexedDB

### 2. Scanning Process
- **VirusTotal Scan**: File/URL scanned by 70+ antivirus engines
- **Gemini AI Analysis**: AI evaluates threats and provides recommendations
- Results stored in both MongoDB and IndexedDB

### 3. IndexedDB Auto-Cleanup
- Scans older than 24 hours are automatically removed
- Cleanup runs hourly in the background
- Manual cleanup available via StorageManager component

### 4. Results Display
- Real-time status updates
- Comprehensive threat analysis
- Detection details from multiple engines
- AI-generated recommendations

## API Endpoints

### POST `/api/upload`
Upload a file for scanning
- **Body**: `multipart/form-data` with `file` field
- **Returns**: `{ scanId, fileName, fileUrl }`

### POST `/api/submit-url`
Submit a URL for scanning
- **Body**: `{ url: string }`
- **Returns**: `{ scanId, url }`

### POST `/api/scan`
Perform VirusTotal and Gemini scan
- **Body**: `{ scanId: string }`
- **Returns**: `{ results: { virusTotal, gemini, threatLevel } }`

### GET `/api/results?scanId={id}`
Get scan results
- **Query**: `scanId`
- **Returns**: `{ result: ScanResult }`

## IndexedDB Storage

The system uses IndexedDB for temporary caching with built-in cleanup:

```typescript
// Automatic cleanup of scans older than 24 hours
const MAX_AGE_MS = 24 * 60 * 60 * 1000; // 24 hours

// Cleanup runs automatically every hour
// Manual cleanup can be triggered:
const dbManager = getDBManager();
await dbManager.cleanupOldScans();
```

## Security Considerations

- API keys stored in environment variables
- File size limits enforced
- URL validation before scanning
- Automatic cleanup of old data
- MongoDB connection with proper authentication
- Cloudinary secure storage

## Troubleshooting

### VirusTotal API Limits
- Free tier: 4 requests per minute
- Wait between scans if you hit limits

### Gemini API Issues
- Ensure you have a valid API key
- Check your quota at Google AI Studio

### MongoDB Connection
- Database credentials are pre-configured
- Ensure your IP is whitelisted if accessing remotely

## Development Commands

```bash
# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## License

MIT

