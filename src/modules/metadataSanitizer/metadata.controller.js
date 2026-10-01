import { parseImageMetadata, sanitizeImageMetadata, generateSampleExifImage } from './metadata.engine.js';
import { MetadataLogService } from './metadata.model.js';

export const sampleImageHandler = async (req, res) => {
  try {
    const buffer = await generateSampleExifImage();
    res.setHeader('Content-Type', 'image/jpeg');
    res.setHeader('Content-Disposition', 'inline; filename="sample_iphone15_exif.jpg"');
    return res.status(200).send(buffer);
  } catch (err) {
    console.error('[MetadataController Sample Error]:', err);
    return res.status(500).json({ success: false, error: err.message || 'Failed to generate sample image.' });
  }
};

export const extractMetadataHandler = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload an image file to inspect.' });
    }

    const metadata = await parseImageMetadata(req.file.buffer, req.file.originalname);

    await MetadataLogService.createLog({
      action: 'INSPECT',
      fileName: req.file.originalname,
      fileSize: req.file.size,
      format: metadata.format,
      tagsFound: metadata.tagCount,
      hasGps: Boolean(metadata.gps),
      details: `Extracted ${metadata.tagCount} metadata tags. Privacy Risk: ${metadata.privacyRisk}`
    });

    return res.status(200).json({
      success: true,
      metadata
    });
  } catch (err) {
    console.error('[MetadataController Extract Error]:', err);
    return res.status(500).json({ success: false, error: err.message || 'Failed to extract metadata.' });
  }
};

export const sanitizeImageHandler = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Please upload an image to sanitize.' });
    }

    const result = await sanitizeImageMetadata(req.file.buffer);
    const base64Sanitized = `data:${result.mimeType};base64,${result.sanitizedBuffer.toString('base64')}`;

    await MetadataLogService.createLog({
      action: 'SANITIZE',
      fileName: req.file.originalname,
      fileSize: req.file.size,
      format: result.format,
      bytesSaved: result.bytesSaved,
      details: `Stripped 100% EXIF & GPS metadata. Reduced file size by ${result.savingsPercent}% (${result.bytesSaved} bytes saved).`
    });

    return res.status(200).json({
      success: true,
      message: 'All metadata, EXIF, and GPS location tags permanently removed.',
      imageDataUrl: base64Sanitized,
      stats: {
        originalSize: result.originalSize,
        newSize: result.newSize,
        formattedOriginalSize: result.formattedOriginalSize,
        formattedNewSize: result.formattedNewSize,
        bytesSaved: result.bytesSaved,
        savingsPercent: result.savingsPercent,
        format: result.format
      }
    });
  } catch (err) {
    console.error('[MetadataController Sanitize Error]:', err);
    return res.status(500).json({ success: false, error: err.message || 'Failed to sanitize image.' });
  }
};

export const getMetadataLogs = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 30;
    const logs = await MetadataLogService.getRecentLogs(limit);
    return res.status(200).json({ success: true, logs });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};

export const clearMetadataLogs = async (req, res) => {
  try {
    await MetadataLogService.clearLogs();
    return res.status(200).json({ success: true, message: 'Metadata logs cleared.' });
  } catch (err) {
    return res.status(500).json({ success: false, error: err.message });
  }
};
