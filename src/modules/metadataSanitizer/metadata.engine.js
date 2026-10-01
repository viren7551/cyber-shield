import sharp from 'sharp';
import exifReader from 'exif-reader';

export async function parseImageMetadata(imageBuffer, originalFilename = 'image.jpg') {
  const image = sharp(imageBuffer);
  const meta = await image.metadata();

  let exifData = null;

  // 1. Attempt reading EXIF via sharp's meta.exif
  if (meta.exif) {
    try {
      exifData = exifReader(meta.exif);
    } catch (err) {
      // If parsing fails due to offset or header alignment, search for standard markers
      exifData = attemptExifFallback(meta.exif);
    }
  }

  // 2. If no exifData found yet, scan the raw imageBuffer for EXIF segments
  if (!exifData) {
    exifData = attemptExifFallback(imageBuffer);
  }

  // 3. Extract XMP metadata if available
  const xmpData = meta.xmp ? parseXmpMetadata(meta.xmp) : null;

  // Read tags safely supporting both casing conventions
  const imageTags = exifData ? (exifData.Image || exifData.image || {}) : {};
  const photoTags = exifData ? (exifData.Photo || exifData.photo || exifData.exif || {}) : {};
  const gpsTags = exifData ? (exifData.GPSInfo || exifData.gps || exifData.GPS || {}) : {};
  const thumbnailTags = exifData ? (exifData.Thumbnail || exifData.thumbnail || {}) : {};
  const iopTags = exifData ? (exifData.Iop || exifData.iop || {}) : {};

  // Camera details
  const cameraDetails = {
    make: imageTags.Make || xmpData?.make || null,
    model: imageTags.Model || xmpData?.model || null,
    software: imageTags.Software || xmpData?.software || imageTags.ProcessingSoftware || null,
    orientation: formatOrientation(imageTags.Orientation),
    artist: imageTags.Artist || xmpData?.artist || null,
    copyright: imageTags.Copyright || xmpData?.copyright || null,
    serialNumber: photoTags.BodySerialNumber || photoTags.CameraSerialNumber || null
  };

  // Capture settings
  const captureSettings = {
    iso: formatIso(photoTags.ISOSpeedRatings || photoTags.ISOSpeed || photoTags.RecommendedExposureIndex || photoTags.ISO || xmpData?.iso),
    fNumber: formatFNumber(photoTags.FNumber || photoTags.ApertureValue || xmpData?.fNumber),
    exposureTime: formatExposureTime(photoTags.ExposureTime || photoTags.ShutterSpeedValue || xmpData?.exposureTime),
    focalLength: formatFocalLength(photoTags.FocalLength || photoTags.FocalLengthIn35mmFilm || xmpData?.focalLength),
    lensModel: photoTags.LensModel || photoTags.LensMake || xmpData?.lens || null,
    flash: formatFlash(photoTags.Flash),
    whiteBalance: formatWhiteBalance(photoTags.WhiteBalance),
    meteringMode: formatMeteringMode(photoTags.MeteringMode),
    exposureProgram: formatExposureProgram(photoTags.ExposureProgram)
  };

  // Embedded timestamps
  const timestamps = {
    original: formatDate(photoTags.DateTimeOriginal || xmpData?.originalDate || null),
    digitized: formatDate(photoTags.DateTimeDigitized || null),
    modified: formatDate(imageTags.DateTime || imageTags.ModifyDate || xmpData?.modifyDate || null)
  };

  // Geolocation
  let parsedGps = null;
  const gpsLat = convertDMSToDD(gpsTags.GPSLatitude, gpsTags.GPSLatitudeRef) ?? (xmpData?.gpsLatitude ? parseXmpCoord(xmpData.gpsLatitude) : null);
  const gpsLon = convertDMSToDD(gpsTags.GPSLongitude, gpsTags.GPSLongitudeRef) ?? (xmpData?.gpsLongitude ? parseXmpCoord(xmpData.gpsLongitude) : null);

  if (gpsLat != null && gpsLon != null) {
    let altitude = null;
    if (gpsTags.GPSAltitude != null) {
      let altNum = Number(gpsTags.GPSAltitude);
      if (!isNaN(altNum)) {
        if (gpsTags.GPSAltitudeRef === 1) altNum = -altNum;
        altitude = `${Math.round(altNum)}m`;
      }
    }

    let timestamp = null;
    if (gpsTags.GPSDateStamp) {
      timestamp = String(gpsTags.GPSDateStamp);
      if (Array.isArray(gpsTags.GPSTimeStamp)) {
        const h = String(Math.floor(gpsTags.GPSTimeStamp[0] || 0)).padStart(2, '0');
        const m = String(Math.floor(gpsTags.GPSTimeStamp[1] || 0)).padStart(2, '0');
        const s = String(Math.floor(gpsTags.GPSTimeStamp[2] || 0)).padStart(2, '0');
        timestamp += ` ${h}:${m}:${s} UTC`;
      }
    }

    parsedGps = {
      latitude: gpsLat,
      longitude: gpsLon,
      altitude,
      timestamp,
      mapsUrl: `https://www.google.com/maps?q=${gpsLat},${gpsLon}`
    };
  }

  // Build complete list of all raw extracted tags
  const allTags = [];
  const addGroupTags = (groupName, obj) => {
    if (!obj || typeof obj !== 'object') return;
    for (const [key, val] of Object.entries(obj)) {
      if (val != null && val !== '') {
        allTags.push({
          group: groupName,
          name: key,
          value: cleanTagValue(val)
        });
      }
    }
  };

  addGroupTags('Camera & Device', imageTags);
  addGroupTags('Exposure & Lens', photoTags);
  addGroupTags('GPS & Geolocation', gpsTags);
  addGroupTags('Interoperability', iopTags);
  addGroupTags('Thumbnail Header', thumbnailTags);

  if (xmpData) {
    for (const [key, val] of Object.entries(xmpData)) {
      if (val && !allTags.some(t => t.name.toLowerCase() === key.toLowerCase())) {
        allTags.push({
          group: 'XMP Extensible Metadata',
          name: key,
          value: cleanTagValue(val)
        });
      }
    }
  }

  const metadataTagCount = allTags.length;

  // Determine privacy risk level
  let privacyRisk = 'Low';
  const riskFactors = [];

  if (parsedGps) {
    privacyRisk = 'Critical';
    riskFactors.push('Precise satellite GPS coordinates exposed');
  }

  if (cameraDetails?.model) {
    if (privacyRisk !== 'Critical') privacyRisk = 'Medium';
    riskFactors.push(`Hardware signature detected (${cameraDetails.make ? cameraDetails.make + ' ' : ''}${cameraDetails.model})`);
  }

  if (cameraDetails?.serialNumber) {
    if (privacyRisk !== 'Critical') privacyRisk = 'High';
    riskFactors.push(`Device unique serial number exposed (${cameraDetails.serialNumber})`);
  }

  if (timestamps?.original) {
    riskFactors.push(`Exact capture timestamp exposed (${timestamps.original})`);
  }

  return {
    filename: originalFilename,
    fileSize: imageBuffer.length,
    formattedFileSize: formatBytes(imageBuffer.length),
    format: meta.format?.toUpperCase() || 'UNKNOWN',
    width: meta.width || 0,
    height: meta.height || 0,
    colorSpace: meta.space || 'srgb',
    channels: meta.channels || 3,
    density: meta.density || 72,
    hasAlpha: Boolean(meta.hasAlpha),
    hasProfile: Boolean(meta.hasProfile),
    metadataBlocks: {
      hasExif: Boolean(meta.exif || exifData),
      hasIcc: Boolean(meta.icc),
      hasIptc: Boolean(meta.iptc),
      hasXmp: Boolean(meta.xmp)
    },
    tagCount: metadataTagCount,
    allTags,
    privacyRisk,
    riskFactors,
    cameraDetails,
    captureSettings,
    timestamps,
    gps: parsedGps
  };
}

/**
 * Strips all metadata, EXIF, GPS, and profiles from an image buffer
 */
export async function sanitizeImageMetadata(imageBuffer, originalFormat = 'jpeg') {
  const image = sharp(imageBuffer);
  const meta = await image.metadata();

  let sanitizedBuffer;
  const targetFormat = meta.format || originalFormat;

  if (targetFormat === 'png') {
    sanitizedBuffer = await image.rotate().png({ compressionLevel: 9 }).toBuffer();
  } else if (targetFormat === 'webp') {
    sanitizedBuffer = await image.rotate().webp({ quality: 90 }).toBuffer();
  } else {
    // Default to high quality JPEG
    sanitizedBuffer = await image.rotate().jpeg({ quality: 92 }).toBuffer();
  }

  const originalSize = imageBuffer.length;
  const newSize = sanitizedBuffer.length;
  const bytesSaved = Math.max(0, originalSize - newSize);
  const savingsPercent = originalSize > 0 ? ((bytesSaved / originalSize) * 100).toFixed(1) : '0.0';

  return {
    sanitizedBuffer,
    mimeType: `image/${targetFormat}`,
    originalSize,
    newSize,
    formattedOriginalSize: formatBytes(originalSize),
    formattedNewSize: formatBytes(newSize),
    bytesSaved,
    savingsPercent,
    format: targetFormat.toUpperCase()
  };
}

/**
 * Generates a sample JPEG image with rich realistic EXIF and GPS tags for demonstration
 */
export async function generateSampleExifImage() {
  return await sharp({
    create: { width: 1920, height: 1080, channels: 3, background: { r: 30, g: 70, b: 120 } }
  })
  .withExif({
    IFD0: {
      Make: 'Apple',
      Model: 'iPhone 15 Pro Max',
      Software: 'iOS 17.5.1',
      DateTime: '2024:05:20 14:15:22'
    },
    IFD2: {
      ISOSpeedRatings: '64',
      FNumber: '178/100',
      ExposureTime: '1/240',
      FocalLength: '678/100',
      LensModel: 'iPhone 15 Pro Max back triple camera 6.78mm f/1.78',
      DateTimeOriginal: '2024:05:20 14:15:22'
    },
    IFD3: {
      GPSLatitudeRef: 'N',
      GPSLatitude: '48/1 51/1 298/10',
      GPSLongitudeRef: 'E',
      GPSLongitude: '2/1 17/1 402/10',
      GPSAltitude: '35/1'
    }
  })
  .jpeg({ quality: 90 })
  .toBuffer();
}

/**
 * Attempts fallback EXIF parsing if the standard header slice fails
 */
function attemptExifFallback(buffer) {
  if (!buffer || !Buffer.isBuffer(buffer)) return null;

  // Try finding "Exif\0\0"
  const exifIdx = buffer.indexOf(Buffer.from([0x45, 0x78, 0x69, 0x66, 0x00, 0x00]));
  if (exifIdx !== -1) {
    try {
      return exifReader(buffer.slice(exifIdx));
    } catch (e) {}
  }

  // Try TIFF Little-Endian header "II*\0"
  const tiffLeIdx = buffer.indexOf(Buffer.from([0x49, 0x49, 0x2a, 0x00]));
  if (tiffLeIdx !== -1) {
    try {
      return exifReader(buffer.slice(tiffLeIdx));
    } catch (e) {}
  }

  // Try TIFF Big-Endian header "MM\0*"
  const tiffBeIdx = buffer.indexOf(Buffer.from([0x4d, 0x4d, 0x00, 0x2a]));
  if (tiffBeIdx !== -1) {
    try {
      return exifReader(buffer.slice(tiffBeIdx));
    } catch (e) {}
  }

  return null;
}

/**
 * Parses XMP packet buffer for standard photographic tags
 */
function parseXmpMetadata(xmpBuffer) {
  if (!xmpBuffer || !Buffer.isBuffer(xmpBuffer)) return null;
  const str = xmpBuffer.toString('utf8');

  const extractTag = (tag) => {
    const elemRegex = new RegExp(`<[^:]*?:?${tag}[^>]*>([\\s\\S]*?)<\\/[^:]*?:?${tag}>`, 'i');
    const elemMatch = str.match(elemRegex);
    if (elemMatch) {
      const clean = elemMatch[1].replace(/<[^>]+>/g, '').trim();
      if (clean) return clean;
    }
    const attrRegex = new RegExp(`(?:tiff|exif|xmp|photoshop|dc|aux):${tag}\\s*=\\s*["']([^"']+)["']`, 'i');
    const attrMatch = str.match(attrRegex);
    if (attrMatch && attrMatch[1].trim()) return attrMatch[1].trim();
    return null;
  };

  const data = {
    make: extractTag('Make'),
    model: extractTag('Model'),
    software: extractTag('Software') || extractTag('CreatorTool'),
    originalDate: extractTag('DateTimeOriginal') || extractTag('DateCreated') || extractTag('CreateDate'),
    modifyDate: extractTag('ModifyDate'),
    lens: extractTag('LensModel') || extractTag('Lens'),
    iso: extractTag('ISOSpeedRatings') || extractTag('PhotographicSensitivity') || extractTag('ISO'),
    fNumber: extractTag('FNumber'),
    exposureTime: extractTag('ExposureTime'),
    focalLength: extractTag('FocalLength'),
    gpsLatitude: extractTag('GPSLatitude'),
    gpsLongitude: extractTag('GPSLongitude'),
    artist: extractTag('creator') || extractTag('Artist'),
    copyright: extractTag('rights') || extractTag('Copyright')
  };

  const hasAny = Object.values(data).some(Boolean);
  return hasAny ? data : null;
}

function parseXmpCoord(val) {
  if (!val) return null;
  val = String(val).trim();
  const m = val.match(/^(\d+),([0-9.]+)([NSEW])$/i);
  if (m) {
    let dd = parseFloat(m[1]) + parseFloat(m[2]) / 60;
    if (m[3].toUpperCase() === 'S' || m[3].toUpperCase() === 'W') dd = -dd;
    return parseFloat(dd.toFixed(6));
  }
  const num = parseFloat(val);
  return isNaN(num) ? null : parseFloat(num.toFixed(6));
}

function convertDMSToDD(dms, ref) {
  if (dms == null) return null;
  let dd = null;
  if (typeof dms === 'number') {
    dd = dms;
  } else if (Array.isArray(dms) && dms.length >= 3) {
    const deg = Number(dms[0]);
    const min = Number(dms[1]);
    const sec = Number(dms[2]);
    if (!isNaN(deg) && !isNaN(min) && !isNaN(sec)) {
      dd = deg + min / 60 + sec / 3600;
    }
  } else if (typeof dms === 'string') {
    const parts = dms.trim().split(/[\s,]+/);
    if (parts.length >= 3) {
      const deg = parseFloat(parts[0]);
      const min = parseFloat(parts[1]);
      const sec = parseFloat(parts[2]);
      if (!isNaN(deg) && !isNaN(min) && !isNaN(sec)) {
        dd = deg + min / 60 + sec / 3600;
      }
    } else {
      const num = parseFloat(dms);
      if (!isNaN(num)) dd = num;
    }
  }

  if (dd == null || isNaN(dd)) return null;

  if (ref) {
    const r = String(ref).trim().toUpperCase();
    if (r === 'S' || r === 'W' || r.startsWith('S') || r.startsWith('W')) {
      if (dd > 0) dd = dd * -1;
    }
  }

  return parseFloat(dd.toFixed(6));
}

function formatIso(isoVal) {
  if (isoVal == null) return null;
  if (Array.isArray(isoVal)) isoVal = isoVal[0];
  return String(isoVal);
}

function formatFNumber(f) {
  if (f == null) return null;
  if (typeof f === 'string' && f.toLowerCase().startsWith('f/')) return f;
  const num = Number(f);
  if (isNaN(num)) return String(f);
  return `f/${num % 1 === 0 ? num : num.toFixed(1)}`;
}

function formatExposureTime(exp) {
  if (exp == null) return null;
  const num = Number(exp);
  if (isNaN(num) || num <= 0) return String(exp);
  if (num >= 1) return `${num}s`;
  const denom = Math.round(1 / num);
  return `1/${denom}s`;
}

function formatFocalLength(fl) {
  if (fl == null) return null;
  if (typeof fl === 'string' && fl.endsWith('mm')) return fl;
  const num = Number(fl);
  if (isNaN(num)) return String(fl);
  return `${num % 1 === 0 ? num : num.toFixed(1)}mm`;
}

function formatFlash(flash) {
  if (flash == null) return null;
  if (typeof flash === 'number') {
    return (flash & 1) ? 'Flash fired' : 'Flash did not fire';
  }
  return String(flash);
}

function formatWhiteBalance(wb) {
  if (wb == null) return null;
  if (wb === 0 || wb === '0') return 'Auto';
  if (wb === 1 || wb === '1') return 'Manual';
  return String(wb);
}

function formatOrientation(ori) {
  if (ori == null) return null;
  const map = {
    1: 'Horizontal (normal)',
    2: 'Mirror horizontal',
    3: 'Rotate 180°',
    4: 'Mirror vertical',
    5: 'Mirror horizontal and rotate 270° CW',
    6: 'Rotate 90° CW',
    7: 'Mirror horizontal and rotate 90° CW',
    8: 'Rotate 270° CW'
  };
  return map[ori] || String(ori);
}

function formatExposureProgram(prog) {
  if (prog == null) return null;
  const map = {
    1: 'Manual',
    2: 'Normal program',
    3: 'Aperture priority',
    4: 'Shutter priority',
    5: 'Creative program',
    6: 'Action program',
    7: 'Portrait mode',
    8: 'Landscape mode'
  };
  return map[prog] || String(prog);
}

function formatMeteringMode(mm) {
  if (mm == null) return null;
  const map = {
    1: 'Average',
    2: 'Center-weighted average',
    3: 'Spot',
    4: 'Multi-spot',
    5: 'Multi-segment / Pattern',
    6: 'Partial'
  };
  return map[mm] || String(mm);
}

function formatDate(val) {
  if (!val) return null;
  if (val instanceof Date && !isNaN(val.getTime())) {
    return val.toLocaleString();
  }
  const str = String(val).trim();
  const exifMatch = str.match(/^(\d{4}):(\d{2}):(\d{2})\s+(\d{2}):(\d{2}):(\d{2})$/);
  if (exifMatch) {
    const d = new Date(Date.UTC(exifMatch[1], exifMatch[2] - 1, exifMatch[3], exifMatch[4], exifMatch[5], exifMatch[6]));
    if (!isNaN(d.getTime())) return d.toLocaleString();
  }
  const d = new Date(str);
  if (!isNaN(d.getTime())) return d.toLocaleString();
  return str;
}

function cleanTagValue(val) {
  if (val == null) return '';
  if (val instanceof Date) return val.toLocaleString();
  if (Buffer.isBuffer(val)) {
    const str = val.toString('utf8');
    if (/^[\x20-\x7E]+$/.test(str)) return str;
    return '0x' + val.toString('hex');
  }
  if (Array.isArray(val)) {
    return val.map(cleanTagValue).join(', ');
  }
  if (typeof val === 'object') {
    return JSON.stringify(val);
  }
  return String(val);
}

function formatBytes(bytes) {
  if (!bytes) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}
