import { NextRequest, NextResponse } from 'next/server';
import { v2 as cloudinary, UploadApiResponse } from 'cloudinary';
import connectDB from '@/lib/mongodb';
import ScanResult from '@/models/ScanResult';

// Configure Cloudinary
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

export async function POST(request: NextRequest) {
  try {
    // Validate Cloudinary configuration
    if (!process.env.CLOUDINARY_CLOUD_NAME || !process.env.CLOUDINARY_API_KEY || !process.env.CLOUDINARY_API_SECRET) {
      console.error('Cloudinary configuration missing');
      return NextResponse.json(
        { error: 'Cloud storage is not configured' },
        { status: 500 }
      );
    }

    await connectDB();

    const formData = await request.formData();
    const file = formData.get('file') as File;
    const scanId = formData.get('scanId') as string;

    if (!file || !scanId) {
      return NextResponse.json({ error: 'Missing file or scan ID' }, { status: 400 });
    }

    // Get scan result
    const scanResult = await ScanResult.findById(scanId);
    if (!scanResult) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }

    // Only upload if scan is completed and safe
    if (scanResult.status !== 'completed') {
      return NextResponse.json({ error: 'Scan not completed yet' }, { status: 400 });
    }

    if (scanResult.overallThreatLevel === 'dangerous') {
      return NextResponse.json({ 
        error: 'File is dangerous and cannot be stored permanently',
        threatLevel: 'dangerous' 
      }, { status: 403 });
    }

    // Convert file to buffer
    const bytes = await file.arrayBuffer();
    const buffer = Buffer.from(bytes);

    // Upload to Cloudinary
    const uploadResult = await new Promise<UploadApiResponse>((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        {
          resource_type: 'auto',
          folder: 'threat-scans',
        },
        (error, result) => {
          if (error) reject(error);
          else if (result) resolve(result);
          else reject(new Error('Upload failed - no result returned'));
        }
      ).end(buffer);
    });

    // Update scan result with Cloudinary info
    scanResult.cloudinaryUrl = uploadResult.secure_url;
    scanResult.cloudinaryPublicId = uploadResult.public_id;
    await scanResult.save();

    return NextResponse.json({
      success: true,
      fileUrl: uploadResult.secure_url,
      message: 'File uploaded to permanent storage',
    });

  } catch (error) {
    console.error('Cloud upload error:', error);
    return NextResponse.json(
      { error: 'Failed to upload to cloud storage' },
      { status: 500 }
    );
  }
}
