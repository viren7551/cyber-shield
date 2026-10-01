import { embedData, extractData, analyzeImage } from '../utils/stegoEngine.js';
import { StegoLogService } from '../models/StegoLog.js';

export const encodeImage = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please provide a carrier image file.' });
    }

    const { secretText, password } = req.body;
    if (!secretText || secretText.trim().length === 0) {
      return res.status(400).json({ error: 'Please enter secret text to hide.' });
    }

    const { stegoImageBuffer, metadata } = await embedData(
      req.file.buffer,
      secretText,
      password || ''
    );

    // Save log entry to MongoDB / fallback service
    await StegoLogService.createLog({
      action: 'ENCODE',
      fileName: req.file.originalname || 'carrier.png',
      fileSize: req.file.size,
      payloadSize: metadata.payloadSize,
      imageDimensions: {
        width: metadata.width,
        height: metadata.height
      },
      isEncrypted: metadata.isEncrypted,
      status: 'SUCCESS',
      details: `Embedded ${metadata.payloadSize} bytes (${metadata.alteredPixelPercentage}% altered pixels).`
    });

    const base64Image = `data:image/png;base64,${stegoImageBuffer.toString('base64')}`;

    return res.status(200).json({
      success: true,
      message: 'Secret successfully embedded into image.',
      imageDataUrl: base64Image,
      metadata
    });
  } catch (err) {
    console.error('[StegoController Encode Error]:', err);
    await StegoLogService.createLog({
      action: 'ENCODE',
      fileName: req.file?.originalname || 'unknown',
      fileSize: req.file?.size || 0,
      payloadSize: req.body?.secretText?.length || 0,
      isEncrypted: Boolean(req.body?.password),
      status: 'FAILED',
      details: err.message
    });

    return res.status(400).json({
      success: false,
      error: err.message || 'Failed to embed data into image.'
    });
  }
};

export const decodeImage = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload an image to inspect.' });
    }

    const { password } = req.body;
    const result = await extractData(req.file.buffer, password || '');

    await StegoLogService.createLog({
      action: 'DECODE',
      fileName: req.file.originalname || 'stego.png',
      fileSize: req.file.size,
      payloadSize: result.payloadSize || 0,
      imageDimensions: result.imageInfo ? {
        width: result.imageInfo.width,
        height: result.imageInfo.height
      } : undefined,
      isEncrypted: result.isEncrypted,
      status: 'SUCCESS',
      details: result.requiresPassword
        ? 'Payload locked with password'
        : `Extracted ${result.payloadSize} bytes successfully`
    });

    return res.status(200).json({
      success: true,
      ...result
    });
  } catch (err) {
    console.error('[StegoController Decode Error]:', err);
    await StegoLogService.createLog({
      action: 'DECODE',
      fileName: req.file?.originalname || 'unknown',
      fileSize: req.file?.size || 0,
      isEncrypted: Boolean(req.body?.password),
      status: 'FAILED',
      details: err.message
    });

    return res.status(400).json({
      success: false,
      error: err.message || 'Failed to extract hidden data.'
    });
  }
};

export const analyzeImageHandler = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload an image to analyze.' });
    }

    const analysis = await analyzeImage(req.file.buffer);

    await StegoLogService.createLog({
      action: 'ANALYZE',
      fileName: req.file.originalname,
      fileSize: req.file.size,
      imageDimensions: {
        width: analysis.width,
        height: analysis.height
      },
      status: 'SUCCESS',
      details: `Analyzed capacity: ${analysis.capacity.formattedCapacity}. Stego header present: ${analysis.stegoAnalysis.hasCyberShieldHeader}`
    });

    return res.status(200).json({
      success: true,
      analysis
    });
  } catch (err) {
    console.error('[StegoController Analyze Error]:', err);
    return res.status(400).json({
      success: false,
      error: err.message || 'Failed to analyze image.'
    });
  }
};

export const getLogs = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 30;
    const logs = await StegoLogService.getRecentLogs(limit);
    return res.status(200).json({ success: true, logs });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const clearLogs = async (req, res) => {
  try {
    await StegoLogService.clearLogs();
    return res.status(200).json({ success: true, message: 'Audit logs cleared.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};
