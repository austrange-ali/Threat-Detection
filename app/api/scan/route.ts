import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/mongodb';
import ScanResult from '@/models/ScanResult';
import { GoogleGenerativeAI } from '@google/generative-ai';

// Initialize Gemini AI
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');
const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY || '';

export async function POST(request: NextRequest) {
  try {
    await connectDB();

    const body = await request.json();
    const { scanId, fileData } = body;

    if (!scanId) {
      return NextResponse.json({ error: 'No scan ID provided' }, { status: 400 });
    }

    // Get scan result from database
    const scanResult = await ScanResult.findById(scanId);

    if (!scanResult) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }

    // Update status to scanning
    scanResult.status = 'scanning';
    await scanResult.save();

    // Perform VirusTotal scan
    let virusTotalData;
    try {
      if (scanResult.scanUrl) {
        // Scan URL
        virusTotalData = await scanUrlWithVirusTotal(scanResult.scanUrl);
      } else if (fileData) {
        // For files, scan using the file data sent from client
        virusTotalData = await scanFileData(fileData, scanResult.fileName);
      } else {
        console.log('No file data provided for scanning');
        virusTotalData = {
          positives: 0,
          total: 0,
          scanId: '',
          permalink: '',
          detections: [],
        };
      }
    } catch (vtError) {
      console.error('VirusTotal scan error:', vtError);
    }

    // Perform Gemini AI analysis
    let geminiData;
    try {
      geminiData = await analyzeWithGemini(scanResult, virusTotalData);
    } catch (geminiError) {
      console.error('Gemini analysis error:', geminiError);
    }

    // Determine overall threat level
    const threatLevel = determineThreatLevel(virusTotalData, geminiData);

    // Update scan result
    scanResult.virusTotalResults = virusTotalData;
    scanResult.geminiResults = geminiData;
    scanResult.overallThreatLevel = threatLevel;
    scanResult.status = 'completed';
    await scanResult.save();

    return NextResponse.json({
      success: true,
      scanId: scanResult._id,
      results: {
        virusTotal: virusTotalData,
        gemini: geminiData,
        threatLevel,
      },
    });

  } catch (error) {
    console.error('Scan error:', error);
    
    // Update status to error
    const { scanId } = await request.json();
    if (scanId) {
      const scanResult = await ScanResult.findById(scanId);
      if (scanResult) {
        scanResult.status = 'error';
        await scanResult.save();
      }
    }

    return NextResponse.json(
      { error: 'Failed to perform scan' },
      { status: 500 }
    );
  }
}

async function scanFileData(base64Data: string, fileName: string) {
  try {
    console.log(`\n=== SCANNING FILE ===`);
    console.log(`File name: ${fileName}`);
    console.log(`Base64 length: ${base64Data.length} characters`);
    
    // Convert base64 to binary
    const binaryString = atob(base64Data);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      bytes[i] = binaryString.charCodeAt(i);
    }
    const fileBlob = new Blob([bytes]);
    
    console.log(`File blob size: ${fileBlob.size} bytes (${(fileBlob.size / 1024).toFixed(2)} KB)`);

    // Upload file to VirusTotal for scanning
    const formData = new FormData();
    formData.append('file', fileBlob, fileName);

    console.log('Uploading to VirusTotal API...');
    const uploadResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
      },
      body: formData,
    });

    console.log(`VirusTotal upload response status: ${uploadResponse.status}`);
    
    if (!uploadResponse.ok) {
      const errorText = await uploadResponse.text();
      console.error('❌ VirusTotal file upload error:', uploadResponse.status, errorText);
      
      // If file already exists (409 Conflict), try to get existing report
      if (uploadResponse.status === 409) {
        const errorData = JSON.parse(errorText);
        const md5 = errorData.error?.message?.match(/[a-f0-9]{32}/)?.[0];
        
        if (md5) {
          console.log(`📋 File already scanned. Retrieving existing report for MD5: ${md5}`);
          
          // Get file report by MD5
          const reportResponse = await fetch(`https://www.virustotal.com/api/v3/files/${md5}`, {
            headers: {
              'x-apikey': VT_API_KEY,
            },
          });
          
          if (reportResponse.ok) {
            const reportData = await reportResponse.json();
            const stats = reportData.data?.attributes?.last_analysis_stats || {};
            const results = reportData.data?.attributes?.last_analysis_results || {};
            const sha256 = reportData.data?.attributes?.sha256;
            
            console.log(`✅ Retrieved existing scan report`);
            console.log(`\n=== DETECTION RESULTS ===`);
            console.log(`Malicious: ${stats.malicious || 0}`);
            console.log(`Suspicious: ${stats.suspicious || 0}`);
            console.log(`Undetected: ${stats.undetected || 0}`);
            console.log(`Total engines: ${Object.keys(results).length}`);
            
            const detections = [];
            for (const [engine, result] of Object.entries(results)) {
              const engineData = result as any;
              if (engineData.category === 'malicious' || engineData.category === 'suspicious') {
                console.log(`  ✓ ${engine}: ${engineData.result || engineData.category}`);
                detections.push({
                  engine,
                  detected: true,
                  result: engineData.result || engineData.category,
                });
              }
            }
            
            console.log(`\n🎯 Total threats detected: ${detections.length}/${Object.keys(results).length} engines`);
            
            const positives = (stats.malicious || 0) + (stats.suspicious || 0);
            const total = Object.keys(results).length;
            
            return {
              positives,
              total,
              scanId: sha256 || md5,
              permalink: `https://www.virustotal.com/gui/file/${sha256 || md5}`,
              detections,
            };
          }
        }
      }
      
      return {
        positives: 0,
        total: 0,
        scanId: '',
        permalink: '',
        detections: [],
      };
    }

    const uploadData = await uploadResponse.json();
    const analysisId = uploadData.data?.id;
    console.log(`✅ File uploaded successfully. Analysis ID: ${analysisId}`);

    // Poll for analysis completion (max 60 seconds)
    console.log('⏳ Waiting for VirusTotal analysis to complete...');
    let analysisData;
    let attempts = 0;
    const maxAttempts = 12; // 12 attempts x 5 seconds = 60 seconds max
    
    while (attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds between checks
      attempts++;
      
      const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: {
          'x-apikey': VT_API_KEY,
        },
      });

      if (!analysisResponse.ok) {
        console.error('❌ VirusTotal analysis check error:', analysisResponse.status);
        continue;
      }

      analysisData = await analysisResponse.json();
      const status = analysisData.data?.attributes?.status;
      
      console.log(`Attempt ${attempts}/${maxAttempts}: Analysis status = ${status}`);
      
      if (status === 'completed') {
        console.log('✅ Analysis completed!');
        break;
      }
    }

    if (!analysisData || analysisData.data?.attributes?.status !== 'completed') {
      console.error('⚠️ Analysis did not complete in time');
      return {
        positives: 0,
        total: 0,
        scanId: '',
        permalink: '',
        detections: [],
      };
    }

    const stats = analysisData.data?.attributes?.stats || {};
    const results = analysisData.data?.attributes?.results || {};
    
    console.log(`\n=== DETECTION RESULTS ===`);
    console.log(`Malicious: ${stats.malicious || 0}`);
    console.log(`Suspicious: ${stats.suspicious || 0}`);
    console.log(`Undetected: ${stats.undetected || 0}`);
    console.log(`Total engines: ${Object.keys(results).length}`);

    const detections = [];
    for (const [engine, result] of Object.entries(results)) {
      const engineData = result as any;
      if (engineData.category === 'malicious' || engineData.category === 'suspicious') {
        console.log(`  ✓ ${engine}: ${engineData.result || engineData.category}`);
        detections.push({
          engine,
          detected: true,
          result: engineData.result || engineData.category,
        });
      }
    }
    
    console.log(`\n🎯 Total threats detected: ${detections.length}/${Object.keys(results).length} engines`);

    const positives = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.keys(results).length;

    return {
      positives,
      total,
      scanId: analysisId || '',
      permalink: `https://www.virustotal.com/gui/file-analysis/${analysisId}`,
      detections,
    };
  } catch (error) {
    console.error('File scan error:', error);
    return {
      positives: 0,
      total: 0,
      scanId: '',
      permalink: '',
      detections: [],
    };
  }
}

async function scanFileFromUrl(fileUrl: string) {
  try {
    // Download file from Cloudinary
    const fileResponse = await fetch(fileUrl);
    if (!fileResponse.ok) {
      throw new Error('Failed to download file');
    }

    const fileBuffer = await fileResponse.arrayBuffer();
    const fileBlob = new Blob([fileBuffer]);

    // Upload file to VirusTotal for scanning
    const formData = new FormData();
    formData.append('file', fileBlob);

    const uploadResponse = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
      },
      body: formData,
    });

    if (!uploadResponse.ok) {
      console.error('VirusTotal file upload error:', uploadResponse.status);
      return {
        positives: 0,
        total: 0,
        scanId: '',
        permalink: '',
        detections: [],
      };
    }

    const uploadData = await uploadResponse.json();
    const analysisId = uploadData.data?.id;

    // Wait for analysis to complete
    await new Promise(resolve => setTimeout(resolve, 15000)); // Wait 15 seconds

    // Get analysis results
    const analysisResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: {
        'x-apikey': VT_API_KEY,
      },
    });

    if (!analysisResponse.ok) {
      console.error('VirusTotal analysis error:', analysisResponse.status);
      return {
        positives: 0,
        total: 0,
        scanId: '',
        permalink: '',
        detections: [],
      };
    }

    const analysisData = await analysisResponse.json();
    console.log('VirusTotal file analysis:', JSON.stringify(analysisData, null, 2));

    const stats = analysisData.data?.attributes?.stats || {};
    const results = analysisData.data?.attributes?.results || {};

    const detections = [];
    for (const [engine, result] of Object.entries(results)) {
      const engineData = result as any;
      if (engineData.category === 'malicious' || engineData.category === 'suspicious') {
        detections.push({
          engine,
          detected: true,
          result: engineData.result || engineData.category,
        });
      }
    }

    const positives = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.keys(results).length;

    return {
      positives,
      total,
      scanId: analysisId || '',
      permalink: `https://www.virustotal.com/gui/file-analysis/${analysisId}`,
      detections,
    };
  } catch (error) {
    console.error('File scan error:', error);
    return {
      positives: 0,
      total: 0,
      scanId: '',
      permalink: '',
      detections: [],
    };
  }
}

async function scanUrlWithVirusTotal(url: string) {
  try {
    // First, submit the URL for scanning
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!submitResponse.ok) {
      console.error('VirusTotal submit error:', submitResponse.status);
    }

    // Wait a bit for scan to process
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Encode URL for VirusTotal API
    const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
    
    // Use VirusTotal v3 API
    const response = await fetch(`https://www.virustotal.com/api/v3/urls/${urlId}`, {
      headers: {
        'x-apikey': VT_API_KEY,
      },
    });

    if (!response.ok) {
      console.error('VirusTotal API error:', response.status);
      // Return minimal data if API fails
      return {
        positives: 0,
        total: 0,
        scanId: '',
        permalink: `https://www.virustotal.com/gui/url/${urlId}`,
        detections: [],
      };
    }

    const data = await response.json();
    console.log('VirusTotal API response:', JSON.stringify(data, null, 2));

    const stats = data.data?.attributes?.last_analysis_stats || {};
    const results = data.data?.attributes?.last_analysis_results || {};

    const detections = [];
    for (const [engine, result] of Object.entries(results)) {
      const engineData = result as any;
      if (engineData.category === 'malicious' || engineData.category === 'suspicious') {
        detections.push({
          engine,
          detected: true,
          result: engineData.result || engineData.category,
        });
      }
    }

    const positives = (stats.malicious || 0) + (stats.suspicious || 0);
    const total = Object.keys(results).length;

    return {
      positives,
      total,
      scanId: data.data?.id || '',
      permalink: `https://www.virustotal.com/gui/url/${urlId}`,
      detections,
    };
  } catch (error) {
    console.error('VirusTotal scan error:', error);
    // Return minimal data instead of throwing
    return {
      positives: 0,
      total: 0,
      scanId: '',
      permalink: '',
      detections: [],
    };
  }
}

async function analyzeWithGemini(scanResult: any, virusTotalData: any) {
  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-pro' });

    // Determine if this is a file or URL scan
    const isFileScan = !scanResult.scanUrl;
    const targetName = scanResult.fileName || scanResult.scanUrl;
    
    const detectionCount = virusTotalData?.positives || 0;
    const totalEngines = virusTotalData?.total || 0;
    const detectionsList = virusTotalData?.detections?.slice(0, 10) || [];

    let prompt;
    
    if (isFileScan) {
      // File-specific analysis prompt with multi-role cybersecurity analysis
      prompt = `Act as a multi-faceted cybersecurity AI assistant. Perform a complete security analysis of this FILE by sequentially assuming the following four roles. For EVERY technical finding in roles 1-4, you MUST ALSO provide a simple, one-sentence explanation in plain language that a non-technical person could understand. Label this explanation clearly as "In simple terms:".

**FILE DETAILS:**
- File Name: ${targetName}
- File Type: ${scanResult.fileType || 'Unknown'}
- VirusTotal Detection: ${detectionCount}/${totalEngines} security engines flagged this file

**DETECTED THREATS FROM VIRUSTOTAL:**
${detectionsList.length > 0 ? detectionsList.map((d: any) => `- ${d.engine}: ${d.result}`).join('\n') : '- No threats detected'}

---

**YOUR ANALYSIS ROLES:**

**1. Malware Analysis Assistant:** 
Review the file based on its name, type, and detection results. Summarize its likely purpose and the step-by-step sequence of actions it would perform when executed. Provide this summary in bullet points. For each action, add "In simple terms:" followed by a one-sentence layman explanation.

**2. IOC Extractor:** 
Based on the file type and detections, identify potential Indicators of Compromise (IOCs). List them in JSON format with these exact keys: \`urls\`, \`ips\`, \`paths\`, \`registry_keys\`, \`strings\`. If a category has no findings, return an empty array for that key.

**3. Threat Intelligence Analyst:** 
Map the identified behaviors to the MITRE ATT&CK framework. For each malicious behavior, specify the likely Technique ID (e.g., T1059.003) and name. Present this as a markdown table with columns: 'Malicious Behavior', 'ATT&CK Technique ID & Name', and 'Technical Description'.

**4. Senior Incident Responder:** 
Synthesize all analysis to evaluate real-world risk. Provide ONE verdict: **High**, **Medium**, or **Low**. Justify in one paragraph considering data theft, system compromise, and network spread potential.

---

**OUTPUT FORMAT (STRICT JSON):**
{
  "analysis": "Comprehensive multi-role analysis following the structure above",
  "riskLevel": "low|medium|high|critical",
  "threats": ["Specific threat 1", "Specific threat 2"],
  "recommendations": ["File-specific action 1", "File-specific action 2"],
  "iocs": {
    "urls": [],
    "ips": [],
    "paths": [],
    "registry_keys": [],
    "strings": []
  },
  "mitreAttack": [
    {"behavior": "Behavior description", "techniqueId": "T1XXX.XXX", "techniqueName": "Name", "description": "Technical details"}
  ]
}

**CRITICAL INSTRUCTIONS:**
- This is a FILE analysis, not a website
- Use simple language with "In simple terms:" explanations
- Give file-specific recommendations (delete, don't execute, quarantine, etc.)
- Use emojis for clarity (✅ ⚠️ 🚫)
- Extract all possible IOCs from detections
- Map behaviors to MITRE ATT&CK framework`;
    } else {
      // URL-specific analysis prompt with multi-role analysis
      prompt = `Act as a multi-faceted cybersecurity AI assistant. Perform a complete security analysis of this URL/WEBSITE by sequentially assuming the following four roles. For EVERY technical finding, provide simple explanations that non-technical users can understand.

**URL DETAILS:**
- URL: ${targetName}
- VirusTotal Detection: ${detectionCount}/${totalEngines} security vendors flagged this URL

**DETECTED THREATS FROM VIRUSTOTAL:**
${detectionsList.length > 0 ? detectionsList.map((d: any) => `- ${d.engine}: ${d.result}`).join('\n') : '- No threats detected'}

---

**YOUR ANALYSIS ROLES:**

**1. Web Threat Analyst:** 
Review the URL and detection results. Summarize the likely purpose of this website and what happens if someone visits it. Provide bullet points with "In simple terms:" explanations.

**2. IOC Extractor:** 
Identify IOCs from the URL (domains, IPs, suspicious paths). Provide JSON with keys: \`urls\`, \`ips\`, \`paths\`, \`registry_keys\`, \`strings\`.

**3. Threat Intelligence Analyst:** 
Map web-based threats to MITRE ATT&CK framework (focus on Initial Access, Execution, Credential Access techniques). Provide markdown table with: 'Malicious Behavior', 'ATT&CK Technique ID & Name', 'Technical Description'.

**4. Senior Incident Responder:** 
Evaluate real-world risk if a user visits this URL. Provide verdict: **High**, **Medium**, or **Low**. Justify considering phishing, malware download, data theft potential.

---

**OUTPUT FORMAT (STRICT JSON):**
{
  "analysis": "Comprehensive multi-role analysis following structure above",
  "riskLevel": "low|medium|high|critical",
  "threats": ["Specific threat 1", "Specific threat 2"],
  "recommendations": ["URL-specific action 1", "URL-specific action 2"],
  "iocs": {
    "urls": [],
    "ips": [],
    "paths": [],
    "registry_keys": [],
    "strings": []
  },
  "mitreAttack": [
    {"behavior": "Behavior description", "techniqueId": "T1XXX.XXX", "techniqueName": "Name", "description": "Technical details"}
  ]
}

**CRITICAL INSTRUCTIONS:**
- This is a WEBSITE/URL analysis, not a file
- Use simple language with clear explanations
- Give URL-specific recommendations (don't click, don't visit, report phishing, etc.)
- Use emojis for clarity (✅ ⚠️ 🚫)
- Extract all domains, IPs from the URL
- Map web threats to relevant MITRE techniques`;
    }

    const result = await model.generateContent(prompt);
    const response = await result.response;
    const text = response.text();
    
    // Try to parse JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }

    // Fallback if JSON not found
    return {
      analysis: text,
      riskLevel: virusTotalData?.positives > 5 ? 'high' : virusTotalData?.positives > 2 ? 'medium' : 'low',
      threats: [],
      recommendations: ['Review the detailed analysis', 'Exercise caution'],
    };
  } catch (error) {
    console.error('Gemini parsing error:', error);
    // Return detailed fallback based on VirusTotal results
    const positives = virusTotalData?.positives || 0;
    const total = virusTotalData?.total || 0;
    const isFileScan = !scanResult.scanUrl;
    const targetName = scanResult.fileName || scanResult.scanUrl;
    const detectionsList = virusTotalData?.detections || [];
    
    let analysis = '';
    let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
    const threats = [];
    const recommendations = [];

    if (isFileScan) {
      // FILE-SPECIFIC FALLBACK ANALYSIS
      if (positives === 0) {
        analysis = `✅ Good News! None of the ${total} security scanners detected any threats in this file. The file appears to be safe.`;
        riskLevel = 'low';
        threats.push('No threats detected');
        recommendations.push(
          '✓ The file appears clean',
          '✓ Still verify the source before opening',
          '✓ Make sure you trust who sent you this file'
        );
      } else if (positives <= 3) {
        analysis = `⚠️ Warning: ${positives} out of ${total} security scanners flagged this file. This could be:\n\n• A false positive (safe file wrongly detected)\n• Early stage malware not widely recognized\n• Potentially unwanted program (PUP)\n\nBe cautious before opening this file.`;
        riskLevel = 'medium';
        threats.push('Low detection count - possible false positive or new threat', 'Detected as: ' + detectionsList.slice(0, 3).map((d: any) => d.result).join(', '));
        recommendations.push(
          '⚠️ Don\'t open this file unless you\'re certain it\'s safe',
          '⚠️ Verify the source - did you expect to receive this file?',
          '⚠️ Check the file extension matches what you expect',
          '⚠️ Consider uploading to VirusTotal directly for more info',
          '✓ When in doubt, delete the file'
        );
      } else if (positives <= 10) {
        analysis = `🚨 Danger! ${positives} out of ${total} security scanners detected malware in this file.\n\n⚠️ This file likely contains:\n• Trojan or virus that can harm your computer\n• Malicious code that steals information\n• Ransomware or spyware\n\n❌ DO NOT open or execute this file!`;
        riskLevel = 'high';
        
        // Extract threat types from detections
        const threatTypes = new Set<string>();
        detectionsList.slice(0, 10).forEach((d: any) => {
          const result = d.result.toLowerCase();
          if (result.includes('trojan')) threatTypes.add('Trojan');
          if (result.includes('backdoor')) threatTypes.add('Backdoor');
          if (result.includes('ransomware')) threatTypes.add('Ransomware');
          if (result.includes('webshell')) threatTypes.add('Webshell');
          if (result.includes('virus')) threatTypes.add('Virus');
          if (result.includes('worm')) threatTypes.add('Worm');
          if (result.includes('spyware')) threatTypes.add('Spyware');
        });
        
        threats.push(
          `Multiple security systems detected malware (${positives}/${total} engines)`,
          'Contains malicious code that can harm your system',
          threatTypes.size > 0 ? 'Identified as: ' + Array.from(threatTypes).join(', ') : 'Various malware types detected'
        );
        
        recommendations.push(
          '🚫 DO NOT open, run, or execute this file',
          '🚫 Delete this file immediately',
          '🚫 Do not extract it if it\'s a zip/archive',
          '⚠️ Empty your Recycle Bin after deleting',
          '⚠️ If you got this via email, mark it as spam',
          '⚠️ Run a full antivirus scan on your computer',
          '✓ Report the source if you know where it came from'
        );
      } else {
        analysis = `🚫 CRITICAL THREAT! ${positives} out of ${total} security scanners confirmed this file contains dangerous malware.\n\n⚠️ This file is HIGHLY MALICIOUS:\n• Contains destructive malware or ransomware\n• Will infect your computer if opened\n• May steal all your personal data and passwords\n• Could spread to other files and networks\n\n🚫 DELETE THIS FILE IMMEDIATELY!`;
        riskLevel = 'critical';
        
        // Extract all threat types
        const threatTypes = new Set<string>();
        detectionsList.forEach((d: any) => {
          const result = d.result.toLowerCase();
          if (result.includes('trojan')) threatTypes.add('Trojan');
          if (result.includes('backdoor')) threatTypes.add('Backdoor');
          if (result.includes('ransomware')) threatTypes.add('Ransomware');
          if (result.includes('webshell')) threatTypes.add('Webshell/Remote Shell');
          if (result.includes('virus')) threatTypes.add('Virus');
          if (result.includes('worm')) threatTypes.add('Worm');
          if (result.includes('spyware')) threatTypes.add('Spyware');
          if (result.includes('rootkit')) threatTypes.add('Rootkit');
        });
        
        threats.push(
          `CONFIRMED MALICIOUS - ${positives}/${total} engines detected threats!`,
          'Highly dangerous malware confirmed by multiple vendors',
          threatTypes.size > 0 ? 'Contains: ' + Array.from(threatTypes).join(', ') : 'Multiple malware types detected',
          'Will damage your system if executed',
          'May steal passwords, banking info, and personal data'
        );
        
        recommendations.push(
          '🚫 DELETE this file RIGHT NOW - do not open it!',
          '🚫 NEVER execute, run, or open this file',
          '🚫 Empty Recycle Bin immediately after deletion',
          '⚠️ If file is in a zip, delete the entire archive',
          '⚠️ Run a FULL antivirus scan immediately',
          '⚠️ Change your passwords if this file was on your system for a while',
          '⚠️ Disconnect from network if you opened the file',
          '✓ Report to your IT security team immediately',
          '✓ Consider professional malware removal if you opened it'
        );
      }
    } else {
      // URL-SPECIFIC FALLBACK ANALYSIS (existing code)
      if (positives === 0) {
        analysis = `✅ Good News! None of the ${total} security scanners found anything suspicious about this URL. It appears to be safe to visit.`;
        riskLevel = 'low';
        threats.push('No threats detected');
        recommendations.push(
        '✓ The link appears safe to click',
        '✓ Still verify the URL matches what you expect',
        '✓ Make sure it starts with https:// for secure connection'
      );
    } else if (positives <= 3) {
      analysis = `⚠️ Warning: ${positives} out of ${total} security scanners flagged this URL as suspicious. Before clicking:\n\n• Check if the website address looks correct\n• See if it's trying to imitate a real company (like "g00gle" instead of "google")\n• This could be a phishing attempt or a new threat that not all scanners caught yet`;
      riskLevel = 'medium';
      threats.push('Some security scanners detected issues', 'Possible phishing or fake website');
      recommendations.push(
        '⚠️ Think twice before clicking this link',
        '⚠️ Check if the website name looks weird or misspelled',
        '⚠️ Don\'t enter any passwords or personal information',
        '⚠️ If someone sent you this link, ask them if it\'s really from them',
        '⚠️ Look for signs like: unusual spelling, extra characters, or strange domain extensions'
      );
    } else if (positives <= 10) {
      analysis = `🚨 Danger! ${positives} out of ${total} security scanners detected serious threats. This is very likely a malicious website.\n\n⚠️ What this might be:\n• Fake login page stealing passwords (Phishing)\n• Website that downloads viruses to your computer\n• Scam site trying to steal your money or information\n\n❌ DO NOT click this link or visit this website!`;
      riskLevel = 'high';
      threats.push('Multiple security systems detected this as dangerous', 'Likely phishing scam or malware distribution', 'Could steal your passwords or personal information');
      recommendations.push(
        '❌ DO NOT click this link',
        '❌ DO NOT enter any usernames, passwords, or personal info',
        '❌ If you received this in an email or message, it\'s probably a scam',
        '⚠️ Delete the message containing this link',
        '⚠️ If it claims to be from your bank or a company, contact them directly using their official website',
        '✓ Report this to your IT department if you received it at work'
      );
    } else {
      analysis = `🚫 CRITICAL THREAT! ${positives} out of ${total} security scanners confirmed this is a malicious website.\n\n⚠️ This is a CONFIRMED SCAM/ATTACK:\n• This website is designed to steal your information\n• It may download viruses or malware to your device\n• It's pretending to be a legitimate website to trick you\n\n🚫 NEVER visit this website or click this link!`;
      riskLevel = 'critical';
      threats.push('CONFIRMED MALICIOUS - This is definitely dangerous!', 'Designed to steal passwords and personal information', 'May install viruses on your computer', 'Impersonating legitimate websites');
      recommendations.push(
        '🚫 NEVER click this link under any circumstances',
        '🚫 DO NOT enter ANY information if you accidentally opened it',
        '🚫 If you clicked it, close the browser immediately',
        '⚠️ This is a confirmed scam - don\'t trust anything on this website',
        '⚠️ If you entered any passwords, change them immediately',
        '⚠️ Warn others if you received this link in a message',
        '✓ Report this to your IT security team or local authorities',
        '✓ Run a virus scan on your computer if you visited this site'
      );
    }
    }


    return {
      analysis,
      riskLevel,
      threats,
      recommendations,
    };
  }
}

function determineThreatLevel(virusTotalData: any, geminiData: any): 'safe' | 'suspicious' | 'dangerous' {
  const positives = virusTotalData?.positives || 0;
  const riskLevel = geminiData?.riskLevel || 'low';

  if (positives === 0 && (riskLevel === 'low')) {
    return 'safe';
  } else if (positives > 5 || riskLevel === 'high' || riskLevel === 'critical') {
    return 'dangerous';
  } else {
    return 'suspicious';
  }
}
