import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import ScanResult from '@/models/ScanResult';

export async function POST(request: NextRequest) {
  try {
    await connectDB();

    const formData = await request.formData();
    const file = formData.get('file') as File;

    if (!file) {
      return NextResponse.json({ error: 'No file provided' }, { status: 400 });
    }

    // Create scan result in MongoDB WITHOUT Cloudinary upload
    // File will be stored in IndexedDB on client side
    const scanResult = await ScanResult.create({
      fileName: file.name,
      fileType: file.type,
      fileSize: file.size,
      status: 'pending',
    });

    return NextResponse.json({
      success: true,
      scanId: scanResult._id,
      fileName: file.name,
      message: 'File stored temporarily in browser. Scanning...',
    });

  } catch (error) {
    console.error('Upload error:', error);
    return NextResponse.json(
      { error: 'Failed to process file' },
      { status: 500 }
    );
  }
}
