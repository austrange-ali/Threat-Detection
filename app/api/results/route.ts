import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import ScanResult from '@/models/ScanResult';

export async function GET(request: NextRequest) {
  try {
    await connectDB();

    const searchParams = request.nextUrl.searchParams;
    const scanId = searchParams.get('scanId');

    if (!scanId) {
      return NextResponse.json({ error: 'No scan ID provided' }, { status: 400 });
    }

    const scanResult = await ScanResult.findById(scanId);

    if (!scanResult) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }

    return NextResponse.json({
      success: true,
      result: scanResult,
    });

  } catch (error) {
    console.error('Get results error:', error);
    return NextResponse.json(
      { error: 'Failed to retrieve results' },
      { status: 500 }
    );
  }
}
