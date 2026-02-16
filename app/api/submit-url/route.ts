import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import ScanResult from '@/models/ScanResult';

export async function POST(request: NextRequest) {
  try {
    await connectDB();

    let { url } = await request.json();

    if (!url) {
      return NextResponse.json({ error: 'No URL provided' }, { status: 400 });
    }

    // Add protocol if missing
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://' + url;
    }

    // Validate URL format
    try {
      new URL(url);
    } catch {
      return NextResponse.json({ error: 'Invalid URL format. Please enter a valid URL (e.g., https://example.com)' }, { status: 400 });
    }

    // Create scan result in MongoDB
    const scanResult = await ScanResult.create({
      fileName: 'URL Scan',
      scanUrl: url,
      fileType: 'url',
      fileSize: 0,
      status: 'pending',
    });

    return NextResponse.json({
      success: true,
      scanId: scanResult._id,
      url: url,
    });

  } catch (error) {
    console.error('URL submission error:', error);
    return NextResponse.json(
      { error: 'Failed to submit URL' },
      { status: 500 }
    );
  }
}
