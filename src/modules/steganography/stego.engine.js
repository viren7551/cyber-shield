import sharp from 'sharp';
import exifReader from 'exif-reader';
import { encryptPayload, decryptPayload } from './stego.crypto.js';

const MAGIC_HEADER = Buffer.from('CSHD'); // CyberShield Header (4 bytes)
const HEADER_SIZE = 9; // 4 magic + 1 flags + 4 length = 9 bytes (72 bits)

/**
 * Calculates theoretical maximum carrier capacity based on 1 bit per RGB channel.
 */
export function calculateCapacity(width, height) {
  const totalRgbChannels = width * height * 3;
  const availableBits = totalRgbChannels - (HEADER_SIZE * 8);
  const maxPayloadBytes = Math.max(0, Math.floor(availableBits / 8));
  return {
    width,
    height,
    totalPixels: width * height,
    totalChannelBits: totalRgbChannels,
    headerBytes: HEADER_SIZE,
    maxPayloadBytes,
    formattedCapacity: formatBytes(maxPayloadBytes)
  };
}

/**
 * Formats byte values into human-readable strings (B, KB, MB, GB).
 */
export function formatBytes(bytes, decimals = 2) {
  if (!bytes || bytes <= 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const safeI = Math.min(i, sizes.length - 1);
  return parseFloat((bytes / Math.pow(k, safeI)).toFixed(dm)) + ' ' + sizes[safeI];
}

/**
 * Checks whether a given buffer consists largely of readable UTF-8 / ASCII text.
 */
function isPrintableText(buf, minRatio = 0.82) {
  if (!buf || buf.length === 0) return false;
  let printable = 0;
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    // Printable ASCII, tab, newline, carriage return
    if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
      printable++;
    } else if (b >= 192 && b <= 244) {
      // Possible UTF-8 multibyte lead byte
      printable++;
    }
  }
  return (printable / buf.length) >= minRatio;
}

/**
 * Embeds data using the CyberShield Steganography Protocol.
 * Preserved for full backward compatibility and secure internal encoding.
 */
export async function embedData(imageBuffer, secretText, password = '') {
  const image = sharp(imageBuffer);
  const metadata = await image.metadata();
  const { width, height } = metadata;

  if (!width || !height) {
    throw new Error('Could not read image dimensions.');
  }

  const { data: rawPixels, info } = await image.ensureAlpha().raw().toBuffer({ resolveWithObject: true });

  let payloadBuffer = Buffer.from(secretText, 'utf8');
  const isEncrypted = Boolean(password && password.trim().length > 0);

  if (isEncrypted) {
    payloadBuffer = encryptPayload(payloadBuffer, password.trim());
  }

  const payloadLength = payloadBuffer.length;
  const totalNeededBytes = HEADER_SIZE + payloadLength;
  const totalNeededBits = totalNeededBytes * 8;

  const totalAvailableBits = width * height * 3;
  if (totalNeededBits > totalAvailableBits) {
    const maxBytes = Math.floor((totalAvailableBits - (HEADER_SIZE * 8)) / 8);
    throw new Error(
      `Image is too small for this payload. Capacity: ${formatBytes(maxBytes)}, required: ${formatBytes(payloadLength)}.`
    );
  }

  const flags = isEncrypted ? 1 : 0;
  const headerBuf = Buffer.alloc(HEADER_SIZE);
  MAGIC_HEADER.copy(headerBuf, 0);
  headerBuf.writeUInt8(flags, 4);
  headerBuf.writeUInt32BE(payloadLength, 5);

  const fullStream = Buffer.concat([headerBuf, payloadBuffer]);

  const bits = [];
  for (let i = 0; i < fullStream.length; i++) {
    const byte = fullStream[i];
    for (let bitIdx = 7; bitIdx >= 0; bitIdx--) {
      bits.push((byte >> bitIdx) & 1);
    }
  }

  let bitIndex = 0;
  const totalBitsToEmbed = bits.length;
  let alteredPixelsCount = 0;

  for (let i = 0; i < rawPixels.length && bitIndex < totalBitsToEmbed; i += 4) {
    let pixelChanged = false;
    for (let c = 0; c < 3; c++) {
      if (bitIndex < totalBitsToEmbed) {
        const currentVal = rawPixels[i + c];
        const bit = bits[bitIndex++];
        const newVal = (currentVal & 0xFE) | bit;
        if (newVal !== currentVal) {
          pixelChanged = true;
        }
        rawPixels[i + c] = newVal;
      }
    }
    if (pixelChanged) {
      alteredPixelsCount++;
    }
  }

  const stegoPngBuffer = await sharp(rawPixels, {
    raw: {
      width: info.width,
      height: info.height,
      channels: 4
    }
  }).png({ compressionLevel: 6 }).toBuffer();

  const capacityInfo = calculateCapacity(width, height);
  const alteredPixelPercentage = ((alteredPixelsCount / (width * height)) * 100).toFixed(3);

  return {
    stegoImageBuffer: stegoPngBuffer,
    metadata: {
      width,
      height,
      originalFormat: metadata.format,
      payloadSize: payloadBuffer.length,
      isEncrypted,
      alteredPixelsCount,
      alteredPixelPercentage,
      capacity: capacityInfo
    }
  };
}

/**
 * Analyzes trailing/appended bytes to identify hidden archives or text.
 */
function analyzeTrailingBytes(trailing) {
  if (!trailing || trailing.length === 0) return { hasAppendedData: false };

  // 1. ZIP Archive
  if (trailing.length >= 4 && trailing.subarray(0, 4).equals(Buffer.from([0x50, 0x4B, 0x03, 0x04]))) {
    let filename = '';
    try {
      if (trailing.length >= 30) {
        const nameLen = trailing.readUInt16LE(26);
        if (30 + nameLen <= trailing.length) {
          filename = trailing.subarray(30, 30 + nameLen).toString('utf8');
        }
      }
    } catch (_) {}
    return {
      type: 'ZIP_ARCHIVE',
      description: 'Embedded ZIP Archive' + (filename ? ` (Contains: ${filename})` : ''),
      filename: filename || 'embedded_payload.zip',
      preview: `ZIP Archive (${formatBytes(trailing.length)})` + (filename ? ` - File: ${filename}` : ''),
      rawData: trailing
    };
  }

  // 2. 7-Zip
  if (trailing.length >= 6 && trailing.subarray(0, 6).equals(Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))) {
    return {
      type: '7Z_ARCHIVE',
      description: 'Embedded 7-Zip Archive',
      filename: 'embedded_payload.7z',
      preview: `7-Zip Archive (${formatBytes(trailing.length)})`,
      rawData: trailing
    };
  }

  // 3. RAR
  if (trailing.length >= 4 && trailing.subarray(0, 4).equals(Buffer.from('Rar!'))) {
    return {
      type: 'RAR_ARCHIVE',
      description: 'Embedded RAR Archive',
      filename: 'embedded_payload.rar',
      preview: `RAR Archive (${formatBytes(trailing.length)})`,
      rawData: trailing
    };
  }

  // 4. PDF
  if (trailing.length >= 5 && trailing.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
    return {
      type: 'PDF_DOCUMENT',
      description: 'Embedded PDF Document',
      filename: 'embedded_document.pdf',
      preview: `PDF Document (${formatBytes(trailing.length)})`,
      rawData: trailing
    };
  }

  // 5. Gzip
  if (trailing.length >= 2 && trailing[0] === 0x1F && trailing[1] === 0x8B) {
    return {
      type: 'GZIP_ARCHIVE',
      description: 'Embedded Gzip Archive',
      filename: 'embedded_payload.gz',
      preview: `Gzip Archive (${formatBytes(trailing.length)})`,
      rawData: trailing
    };
  }

  // 6. Plaintext UTF-8 / ASCII
  if (isPrintableText(trailing, 0.75) && trailing.length >= 2) {
    const text = trailing.toString('utf8').trim();
    return {
      type: 'PLAINTEXT',
      description: 'Plaintext Hidden Message (Appended EOF)',
      text,
      preview: text.length > 200 ? text.substring(0, 200) + '...' : text,
      rawData: trailing
    };
  }

  // 7. Generic Binary
  return {
    type: 'BINARY_PAYLOAD',
    description: `Binary Trailing Payload (${formatBytes(trailing.length)})`,
    preview: `Binary data: ${trailing.subarray(0, 16).toString('hex')}...`,
    rawData: trailing
  };
}

/**
 * Detects Appended Data / EOF Steganography across PNG, JPEG, GIF, and WebP.
 */
export function detectAppendedData(imageBuffer) {
  if (!imageBuffer || imageBuffer.length < 16) {
    return { hasAppendedData: false };
  }

  // 1. PNG inspection (IEND chunk)
  const PNG_SIG = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  if (imageBuffer.subarray(0, 8).equals(PNG_SIG)) {
    let offset = 8;
    while (offset + 8 <= imageBuffer.length) {
      const chunkLen = imageBuffer.readUInt32BE(offset);
      const chunkType = imageBuffer.toString('ascii', offset + 4, offset + 8);
      if (chunkType === 'IEND') {
        const eofOffset = offset + 12; // 4 len + 4 type + 4 CRC
        if (imageBuffer.length > eofOffset) {
          const trailing = imageBuffer.subarray(eofOffset);
          const analyzed = analyzeTrailingBytes(trailing);
          return {
            hasAppendedData: true,
            format: 'PNG',
            offset: eofOffset,
            size: trailing.length,
            formattedSize: formatBytes(trailing.length),
            ...analyzed
          };
        }
        return { hasAppendedData: false, format: 'PNG' };
      }
      offset += 12 + chunkLen;
    }
  }

  // 2. JPEG inspection (Last FF D9 marker)
  if (imageBuffer[0] === 0xFF && imageBuffer[1] === 0xD8) {
    let lastEof = -1;
    for (let i = imageBuffer.length - 2; i >= 2; i--) {
      if (imageBuffer[i] === 0xFF && imageBuffer[i + 1] === 0xD9) {
        lastEof = i + 2;
        break;
      }
    }
    if (lastEof !== -1 && imageBuffer.length > lastEof) {
      const trailing = imageBuffer.subarray(lastEof);
      const analyzed = analyzeTrailingBytes(trailing);
      return {
        hasAppendedData: true,
        format: 'JPEG',
        offset: lastEof,
        size: trailing.length,
        formattedSize: formatBytes(trailing.length),
        ...analyzed
      };
    }
    return { hasAppendedData: false, format: 'JPEG' };
  }

  // 3. GIF inspection (Trailer 0x3B)
  const gifSig = imageBuffer.subarray(0, 6).toString('ascii');
  if (gifSig === 'GIF87a' || gifSig === 'GIF89a') {
    let lastEof = -1;
    for (let i = imageBuffer.length - 1; i >= 6; i--) {
      if (imageBuffer[i] === 0x3B) {
        lastEof = i + 1;
        break;
      }
    }
    if (lastEof !== -1 && imageBuffer.length > lastEof) {
      const trailing = imageBuffer.subarray(lastEof);
      const analyzed = analyzeTrailingBytes(trailing);
      return {
        hasAppendedData: true,
        format: 'GIF',
        offset: lastEof,
        size: trailing.length,
        formattedSize: formatBytes(trailing.length),
        ...analyzed
      };
    }
    return { hasAppendedData: false, format: 'GIF' };
  }

  // 4. WebP inspection (RIFF length)
  if (imageBuffer.subarray(0, 4).toString('ascii') === 'RIFF' &&
      imageBuffer.length >= 12 &&
      imageBuffer.subarray(8, 12).toString('ascii') === 'WEBP') {
    const riffSize = imageBuffer.readUInt32LE(4) + 8;
    if (imageBuffer.length > riffSize) {
      const trailing = imageBuffer.subarray(riffSize);
      const analyzed = analyzeTrailingBytes(trailing);
      return {
        hasAppendedData: true,
        format: 'WEBP',
        offset: riffSize,
        size: trailing.length,
        formattedSize: formatBytes(trailing.length),
        ...analyzed
      };
    }
    return { hasAppendedData: false, format: 'WEBP' };
  }

  return { hasAppendedData: false };
}

/**
 * Detects metadata-level steganography (e.g., hidden comments, base64 strings in EXIF).
 */
export function detectExifStego(metadata) {
  if (!metadata || !metadata.exif) return { detected: false };

  try {
    const parsed = exifReader(metadata.exif);
    const suspiciousFields = [];

    const testValue = (tag, val) => {
      if (!val) return;
      let str = typeof val === 'string' ? val : (Buffer.isBuffer(val) ? val.toString('utf8') : String(val));
      str = str.replace(/\0/g, '').trim();
      if (!str) return;

      // Base64 hidden string check
      if (str.length >= 24 && /^[A-Za-z0-9+/=]+$/.test(str) && str.length % 4 === 0) {
        try {
          const decoded = Buffer.from(str, 'base64').toString('utf8');
          if (isPrintableText(Buffer.from(decoded))) {
            suspiciousFields.push({ tag, type: 'BASE64_SECRET', preview: decoded, raw: str });
            return;
          }
        } catch (_) {}
      }

      // Suspicious keywords or unusually long text fields
      if (str.length >= 40 || /flag\{|secret|password|cipher|cshd/i.test(str)) {
        suspiciousFields.push({ tag, type: 'TEXT_METADATA', preview: str, raw: str });
      }
    };

    if (parsed.image) {
      testValue('ImageDescription', parsed.image.ImageDescription);
      testValue('Artist', parsed.image.Artist);
      testValue('Copyright', parsed.image.Copyright);
      testValue('XPComment', parsed.image.XPComment);
    }
    if (parsed.exif) {
      testValue('UserComment', parsed.exif.UserComment);
    }

    if (suspiciousFields.length > 0) {
      const best = suspiciousFields[0];
      return {
        detected: true,
        field: best.tag,
        type: best.type,
        preview: best.preview,
        text: best.preview,
        allFields: suspiciousFields
      };
    }
  } catch (_) {
    // Graceful fallback on malformed EXIF
  }

  return { detected: false };
}

/**
 * Extracts sequential LSB bytes from raw RGBA pixel data.
 */
function extractLsbBytesFromPixels(rawPixels, maxBytes = 131072, msbFirst = true, channels = 3) {
  const bytes = [];
  let byteVal = 0;
  let bitCount = 0;

  for (let i = 0; i < rawPixels.length && bytes.length < maxBytes; i += 4) {
    for (let c = 0; c < channels && bytes.length < maxBytes; c++) {
      const bit = rawPixels[i + c] & 1;
      if (msbFirst) {
        byteVal = (byteVal << 1) | bit;
      } else {
        byteVal = byteVal | (bit << bitCount);
      }
      bitCount++;
      if (bitCount === 8) {
        bytes.push(byteVal);
        byteVal = 0;
        bitCount = 0;
      }
    }
  }

  return Buffer.from(bytes);
}

/**
 * Scans extracted LSB byte stream for recognized steganography signatures,
 * headers, length-prefixed text, null-terminated strings, and delimiters.
 */
function scanLsbStream(bytes, maxCapacity = 500000) {
  if (!bytes || bytes.length < 4) return null;

  // 1. CyberShield Magic Header ('CSHD')
  if (bytes.length >= 9 && bytes.subarray(0, 4).equals(MAGIC_HEADER)) {
    const isEncrypted = (bytes[4] & 1) === 1;
    const len = bytes.readUInt32BE(5);
    return {
      detected: true,
      type: 'CYBERSHIELD',
      format: isEncrypted ? 'CyberShield AES-256 Protocol' : 'CyberShield Plaintext Protocol',
      isEncrypted,
      payloadLength: len,
      headerSize: 9
    };
  }

  // 2. OpenStego Signature
  if (bytes.length >= 9 && bytes.subarray(0, 9).toString('ascii') === 'OPENSTEGO') {
    return {
      detected: true,
      type: 'OPENSTEGO',
      format: 'OpenStego Signature Header',
      payloadLength: 0,
      preview: 'OpenStego container detected'
    };
  }

  // 3. Embedded File Headers at Byte 0
  // ZIP
  if (bytes.length >= 4 && bytes.subarray(0, 4).equals(Buffer.from([0x50, 0x4B, 0x03, 0x04]))) {
    return {
      detected: true,
      type: 'EMBEDDED_ZIP',
      format: 'Embedded ZIP Archive in LSB',
      preview: 'ZIP Archive header found at LSB offset 0'
    };
  }
  // 7-Zip
  if (bytes.length >= 6 && bytes.subarray(0, 6).equals(Buffer.from([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]))) {
    return {
      detected: true,
      type: 'EMBEDDED_7Z',
      format: 'Embedded 7-Zip Archive in LSB',
      preview: '7-Zip Archive header found at LSB offset 0'
    };
  }
  // PDF
  if (bytes.length >= 5 && bytes.subarray(0, 5).equals(Buffer.from('%PDF-'))) {
    return {
      detected: true,
      type: 'EMBEDDED_PDF',
      format: 'Embedded PDF Document in LSB',
      preview: 'PDF Document header found at LSB offset 0'
    };
  }

  // 4. 32-bit Big-Endian Length-Prefixed String
  const beLen = bytes.readUInt32BE(0);
  if (beLen >= 3 && beLen <= Math.min(bytes.length - 4, maxCapacity, 100000)) {
    const slice = bytes.subarray(4, 4 + beLen);
    if (isPrintableText(slice, 0.85)) {
      const text = slice.toString('utf8');
      return {
        detected: true,
        type: 'LENGTH_PREFIX_32_BE',
        format: 'Generic 32-bit BE Length-Prefixed Text',
        payloadLength: beLen,
        text,
        preview: text.length > 200 ? text.substring(0, 200) + '...' : text
      };
    }
  }

  // 5. 32-bit Little-Endian Length-Prefixed String
  const leLen = bytes.readUInt32LE(0);
  if (leLen >= 3 && leLen <= Math.min(bytes.length - 4, maxCapacity, 100000)) {
    const slice = bytes.subarray(4, 4 + leLen);
    if (isPrintableText(slice, 0.85)) {
      const text = slice.toString('utf8');
      return {
        detected: true,
        type: 'LENGTH_PREFIX_32_LE',
        format: 'Generic 32-bit LE Length-Prefixed Text',
        payloadLength: leLen,
        text,
        preview: text.length > 200 ? text.substring(0, 200) + '...' : text
      };
    }
  }

  // 6. 16-bit Big-Endian Length-Prefixed String
  const be16Len = bytes.readUInt16BE(0);
  if (be16Len >= 3 && be16Len <= Math.min(bytes.length - 2, maxCapacity, 65535)) {
    const slice = bytes.subarray(2, 2 + be16Len);
    if (isPrintableText(slice, 0.85)) {
      const text = slice.toString('utf8');
      return {
        detected: true,
        type: 'LENGTH_PREFIX_16',
        format: 'Generic 16-bit Length-Prefixed Text',
        payloadLength: be16Len,
        text,
        preview: text.length > 200 ? text.substring(0, 200) + '...' : text
      };
    }
  }

  // 7. Null-Terminated UTF-8 String
  const nullIdx = bytes.indexOf(0);
  if (nullIdx >= 3 && nullIdx <= Math.min(bytes.length, 30000)) {
    const slice = bytes.subarray(0, nullIdx);
    if (isPrintableText(slice, 0.85)) {
      const text = slice.toString('utf8');
      return {
        detected: true,
        type: 'NULL_TERMINATED',
        format: 'Null-Terminated UTF-8 String',
        payloadLength: nullIdx,
        text,
        preview: text.length > 200 ? text.substring(0, 200) + '...' : text
      };
    }
  }

  // 8. Delimiter-Terminated String
  const delimiters = ['###', '---END---', '$$$', '@@@', '%END%'];
  for (const delim of delimiters) {
    const dIdx = bytes.indexOf(Buffer.from(delim));
    if (dIdx >= 3 && dIdx <= Math.min(bytes.length, 30000)) {
      const slice = bytes.subarray(0, dIdx);
      if (isPrintableText(slice, 0.85)) {
        const text = slice.toString('utf8');
        return {
          detected: true,
          type: 'DELIMITER_TERMINATED',
          format: `Delimiter-Terminated String ('${delim}')`,
          payloadLength: dIdx,
          text,
          preview: text.length > 200 ? text.substring(0, 200) + '...' : text
        };
      }
    }
  }

  // 9. Continuous Plaintext Run from Byte 0
  let runLen = 0;
  while (runLen < bytes.length && runLen < 15000) {
    const b = bytes[runLen];
    if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) {
      runLen++;
    } else {
      break;
    }
  }
  if (runLen >= 8) {
    const slice = bytes.subarray(0, runLen);
    const text = slice.toString('utf8');
    return {
      detected: true,
      type: 'PLAINTEXT_RUN',
      format: 'Continuous Plaintext LSB Run',
      payloadLength: runLen,
      text,
      preview: text.length > 200 ? text.substring(0, 200) + '...' : text
    };
  }

  return null;
}

/**
 * Scans raw pixels for any generic LSB text or recognized headers across bit orders.
 */
export function scanGenericLsbPayloads(rawPixels, width, height, maxCapacity) {
  // Test 1: Standard MSB-first RGB sequential (covers ~90% of tools)
  const msbBytes = extractLsbBytesFromPixels(rawPixels, 65536, true, 3);
  const msbResult = scanLsbStream(msbBytes, maxCapacity);
  if (msbResult) {
    return { ...msbResult, bitOrder: 'MSB_FIRST' };
  }

  // Test 2: LSB-first RGB sequential
  const lsbBytes = extractLsbBytesFromPixels(rawPixels, 65536, false, 3);
  const lsbResult = scanLsbStream(lsbBytes, maxCapacity);
  if (lsbResult) {
    return { ...lsbResult, bitOrder: 'LSB_FIRST' };
  }

  return { detected: false };
}

/**
 * Wilson-Hilferty transformation to approximate Chi-Square CDF / p-value.
 */
function chiSquarePValue(chi2, df) {
  if (df <= 0) return 0;
  if (chi2 <= 0) return 1;
  const z = (Math.pow(chi2 / df, 1 / 3) - (1 - 2 / (9 * df))) / Math.sqrt(2 / (9 * df));
  const t = 1 / (1 + 0.2316419 * Math.abs(z));
  const d = 0.3989423 * Math.exp(-z * z / 2);
  const prob = d * t * (0.3193815 + t * (-0.3565638 + t * (1.781478 + t * (-1.821256 + t * 1.330274))));
  return z > 0 ? prob : 1 - prob;
}

/**
 * Performs Statistical Steganalysis using:
 * 1. Westfeld & Pfitzmann PoVs (Pairs of Values) Chi-Square test
 * 2. Block-by-block PoVs analysis to detect partial image embedding
 * 3. LSB Bitplane Shannon Entropy test
 */
export function performStatisticalSteganalysis(rawPixels, width, height) {
  const totalPixels = width * height;
  const numBlocks = Math.max(4, Math.min(10, Math.floor(totalPixels / 2000)));
  const blockSize = Math.floor(rawPixels.length / (numBlocks * 4)) * 4;

  let stegoBlockCount = 0;
  let totalChi2 = 0;
  let totalDf = 0;

  // Block-by-block inspection
  const blockStats = [];
  for (let b = 0; b < numBlocks; b++) {
    const start = b * blockSize;
    const end = Math.min(start + blockSize, rawPixels.length);
    const counts = new Array(256).fill(0);

    for (let i = start; i < end; i += 4) {
      for (let c = 0; c < 3; c++) {
        counts[rawPixels[i + c]]++;
      }
    }

    let chi2 = 0;
    let df = 0;
    for (let k = 0; k < 128; k++) {
      const sum = counts[2 * k] + counts[2 * k + 1];
      if (sum > 6) {
        const expected = sum / 2;
        chi2 += Math.pow(counts[2 * k] - expected, 2) / expected;
        df++;
      }
    }

    totalChi2 += chi2;
    totalDf += df;

    const ratio = df > 0 ? chi2 / df : 2.0;
    // When LSB is equalized by steganography, ratio collapses < 1.2
    const isBlockStego = ratio < 1.15 && df >= 40;
    if (isBlockStego) {
      stegoBlockCount++;
    }

    blockStats.push({ block: b, ratio: ratio.toFixed(2), isBlockStego });
  }

  // Global Chi-Square
  const globalRatio = totalDf > 0 ? totalChi2 / totalDf : 2.0;
  const pVal = chiSquarePValue(totalChi2, totalDf);

  // Steganography Probability Calculation
  let stegoProbability = 0;
  if (globalRatio < 1.1) {
    stegoProbability = Math.min(99.5, Math.round((1 - (globalRatio / 1.1)) * 40 + 60));
  } else if (stegoBlockCount > 0) {
    const blockFraction = stegoBlockCount / numBlocks;
    stegoProbability = Math.min(98.0, Math.round(blockFraction * 85 + 10));
  } else if (globalRatio < 1.5) {
    stegoProbability = Math.max(5, Math.round((1.5 - globalRatio) * 30));
  } else {
    stegoProbability = Math.max(0.5, Math.round(Math.min(5, (1 / globalRatio) * 5)));
  }

  // LSB Shannon Entropy Calculation
  let bit0 = 0;
  let bit1 = 0;
  const sampleLimit = Math.min(rawPixels.length, 40000);
  for (let i = 0; i < sampleLimit; i += 4) {
    for (let c = 0; c < 3; c++) {
      if ((rawPixels[i + c] & 1) === 1) bit1++;
      else bit0++;
    }
  }

  const totalBits = bit0 + bit1;
  let bitEntropy = 0;
  if (totalBits > 0) {
    const p0 = bit0 / totalBits;
    const p1 = bit1 / totalBits;
    if (p0 > 0) bitEntropy -= p0 * Math.log2(p0);
    if (p1 > 0) bitEntropy -= p1 * Math.log2(p1);
  }

  const isSuspicious = stegoProbability >= 70 || (stegoBlockCount >= 2 && bitEntropy > 0.992);
  const estimatedPayloadBytes = Math.round((stegoBlockCount / numBlocks) * ((totalPixels * 3) / 8));

  return {
    chiSquare: {
      score: totalChi2.toFixed(1),
      degreesOfFreedom: totalDf,
      ratio: globalRatio.toFixed(2),
      stegoProbability: Math.min(99.9, Math.max(0.1, stegoProbability)),
      stegoBlocksDetected: stegoBlockCount,
      totalBlocksAnalyzed: numBlocks
    },
    entropy: {
      lsbBitEntropy: parseFloat(bitEntropy.toFixed(4)),
      isNearRandom: bitEntropy > 0.99
    },
    isSuspicious,
    estimatedPayloadBytes,
    formattedEstimatedPayload: formatBytes(estimatedPayloadBytes)
  };
}

/**
 * Comprehensive Steganography Analysis:
 * Combines CyberShield protocol detection, Appended EOF inspection, Generic LSB scanning,
 * EXIF metadata analysis, and Statistical Chi-Square/Entropy steganalysis.
 */
export async function analyzeImage(imageBuffer) {
  const image = sharp(imageBuffer);
  const metadata = await image.metadata();
  const { width, height, format, space, channels, size } = metadata;

  if (!width || !height) {
    throw new Error('Invalid image: Could not read dimensions.');
  }

  const capacity = calculateCapacity(width, height);
  const { data: rawPixels } = await image.ensureAlpha().raw().toBuffer({ resolveWithObject: true });

  // 1. Appended EOF Polyglot Check
  const appendedData = detectAppendedData(imageBuffer);

  // 2. EXIF Metadata Stego Check
  const exifStego = detectExifStego(metadata);

  // 3. Generic LSB & CyberShield Stream Check
  const genericLsb = scanGenericLsbPayloads(rawPixels, width, height, capacity.maxPayloadBytes);

  // 4. Statistical Steganalysis (Chi-Square & Shannon Entropy)
  const statistical = performStatisticalSteganalysis(rawPixels, width, height);

  // Synthesize detection verdict
  let detected = false;
  let detectionType = 'NONE';
  let title = 'Clean Carrier (No Steganography Detected)';
  let confidence = '0%';
  let confidenceLevel = 'NONE';
  let methodDescription = 'Deep inspection showed no CyberShield headers, generic LSB streams, appended EOF data, or statistical anomalies.';
  let previewText = null;
  let detectedPayloadSize = 0;
  let isEncrypted = false;
  let hasCyberShieldHeader = false;

  if (genericLsb.detected && genericLsb.type === 'CYBERSHIELD') {
    detected = true;
    hasCyberShieldHeader = true;
    isEncrypted = genericLsb.isEncrypted;
    detectionType = 'CYBERSHIELD';
    title = 'CyberShield Stego Signature Detected';
    confidence = '100%';
    confidenceLevel = 'HIGH';
    detectedPayloadSize = genericLsb.payloadLength;
    methodDescription = `Image carries a CyberShield protocol payload of ${formatBytes(genericLsb.payloadLength)} (${isEncrypted ? 'AES-256 Encrypted' : 'Plaintext'}).`;
  } else if (appendedData.hasAppendedData) {
    detected = true;
    detectionType = 'APPENDED_EOF';
    title = `Appended EOF Steganography Detected (${appendedData.format})`;
    confidence = '100%';
    confidenceLevel = 'HIGH';
    detectedPayloadSize = appendedData.size;
    previewText = appendedData.preview || appendedData.text || null;
    methodDescription = `Detected ${formatBytes(appendedData.size)} of trailing polyglot data appended after the ${appendedData.format} EOF marker (${appendedData.description}).`;
  } else if (genericLsb.detected && genericLsb.type !== 'CYBERSHIELD') {
    detected = true;
    detectionType = 'GENERIC_LSB';
    title = `Generic LSB Steganography Detected (${genericLsb.format})`;
    confidence = '98.5%';
    confidenceLevel = 'HIGH';
    detectedPayloadSize = genericLsb.payloadLength || 0;
    previewText = genericLsb.preview || genericLsb.text || null;
    methodDescription = `Detected readable text or structured stego payload embedded via sequential LSB replacement (${genericLsb.format}).`;
  } else if (exifStego.detected) {
    detected = true;
    detectionType = 'METADATA_EXIF';
    title = `EXIF Metadata Steganography Detected (${exifStego.field})`;
    confidence = '95%';
    confidenceLevel = 'HIGH';
    previewText = exifStego.preview;
    detectedPayloadSize = exifStego.preview?.length || 0;
    methodDescription = `Detected hidden payload or encoded string within EXIF tag '${exifStego.field}'.`;
  } else if (statistical.isSuspicious) {
    detected = true;
    detectionType = 'STATISTICAL_LSB';
    title = 'External Stego Tool Detected (Statistical LSB Anomaly)';
    confidence = `${statistical.chiSquare.stegoProbability}%`;
    confidenceLevel = statistical.chiSquare.stegoProbability >= 85 ? 'HIGH' : 'MEDIUM';
    detectedPayloadSize = statistical.estimatedPayloadBytes;
    methodDescription = `Chi-Square analysis (${statistical.chiSquare.score} / ${statistical.chiSquare.degreesOfFreedom} df) and high LSB entropy (${statistical.entropy.lsbBitEntropy}) indicate an encrypted or compressed payload from a third-party stego tool (e.g., Steghide, OpenStego, or custom cipher).`;
  }

  return {
    format,
    width,
    height,
    colorSpace: space,
    channels,
    fileSize: size || imageBuffer.length,
    formattedFileSize: formatBytes(size || imageBuffer.length),
    capacity,
    stegoAnalysis: {
      // Backward-compatible fields
      hasCyberShieldHeader,
      isEncrypted,
      detectedPayloadSize,
      formattedDetectedSize: formatBytes(detectedPayloadSize),

      // Multi-format detection fields
      detected,
      detectionType,
      title,
      confidence,
      confidenceLevel,
      methodDescription,
      previewText,
      recommendation: detected
        ? (detectionType === 'CYBERSHIELD' && isEncrypted
            ? 'This payload is encrypted. Head to the Decode tab with the decryption key to extract.'
            : 'Extract the full recovered message in the Decode tab.')
        : 'Carrier image is clean. You can safely embed secret data in this image.',
      breakdown: {
        cyberShield: {
          checked: true,
          detected: hasCyberShieldHeader,
          isEncrypted,
          payloadSize: detectedPayloadSize
        },
        appendedData: {
          checked: true,
          detected: appendedData.hasAppendedData,
          size: appendedData.size || 0,
          formattedSize: appendedData.formattedSize || '0 Bytes',
          format: appendedData.format || null,
          description: appendedData.description || 'Clean boundary'
        },
        genericLsb: {
          checked: true,
          detected: genericLsb.detected && genericLsb.type !== 'CYBERSHIELD',
          format: genericLsb.format || 'No generic LSB strings',
          payloadLength: genericLsb.payloadLength || 0
        },
        metadataExif: {
          checked: true,
          detected: exifStego.detected,
          field: exifStego.field || null
        },
        statistical: {
          checked: true,
          chiSquareScore: statistical.chiSquare.score,
          degreesOfFreedom: statistical.chiSquare.degreesOfFreedom,
          stegoProbability: statistical.chiSquare.stegoProbability,
          lsbEntropy: statistical.entropy.lsbBitEntropy,
          isSuspicious: statistical.isSuspicious,
          estimatedPayloadBytes: statistical.estimatedPayloadBytes,
          formattedEstimatedPayload: statistical.formattedEstimatedPayload
        }
      }
    }
  };
}

/**
 * Universal Extraction Engine:
 * Extracts hidden data from CyberShield protocols, Generic LSB payloads, Appended EOF trail polyglots,
 * and EXIF metadata. If an encrypted external tool is detected, returns structured forensic details.
 */
export async function extractData(imageBuffer, password = '') {
  const image = sharp(imageBuffer);
  const metadata = await image.metadata();
  const { width, height } = metadata;

  if (!width || !height) {
    throw new Error('Invalid image: Could not read dimensions.');
  }

  const { data: rawPixels } = await image.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
  const totalRgbBits = width * height * 3;
  const headerBitsNeeded = HEADER_SIZE * 8;

  // ==========================================
  // Layer 1: Check CyberShield Magic Header
  // ==========================================
  if (totalRgbBits >= headerBitsNeeded) {
    let bitIndex = 0;
    let byteVal = 0;
    let bitInByteCount = 0;
    const extractedHeaderBytes = [];

    for (let i = 0; i < rawPixels.length && extractedHeaderBytes.length < HEADER_SIZE; i += 4) {
      for (let c = 0; c < 3; c++) {
        if (extractedHeaderBytes.length < HEADER_SIZE) {
          const bit = rawPixels[i + c] & 1;
          byteVal = (byteVal << 1) | bit;
          bitInByteCount++;
          bitIndex++;

          if (bitInByteCount === 8) {
            extractedHeaderBytes.push(byteVal);
            byteVal = 0;
            bitInByteCount = 0;
          }
        }
      }
    }

    const headerBuf = Buffer.from(extractedHeaderBytes);
    const magic = headerBuf.subarray(0, 4);

    if (magic.equals(MAGIC_HEADER)) {
      const flags = headerBuf.readUInt8(4);
      const isEncrypted = (flags & 1) === 1;
      const payloadLength = headerBuf.readUInt32BE(5);

      const maxPossibleBytes = Math.floor((totalRgbBits - headerBitsNeeded) / 8);
      if (payloadLength <= 0 || payloadLength > maxPossibleBytes) {
        throw new Error(`Corrupted CyberShield header or invalid payload size (${payloadLength} bytes).`);
      }

      if (isEncrypted && (!password || password.trim().length === 0)) {
        return {
          isEncrypted: true,
          requiresPassword: true,
          methodName: 'CyberShield Protocol (AES-256-GCM)',
          message: 'This payload is encrypted with a password. Please provide the secret key to decrypt.',
          payloadLength
        };
      }

      const extractedPayloadBytes = [];
      byteVal = 0;
      bitInByteCount = 0;

      for (let i = 0; i < rawPixels.length && extractedPayloadBytes.length < payloadLength; i += 4) {
        for (let c = 0; c < 3; c++) {
          if (bitIndex > 0) {
            bitIndex--;
            continue;
          }

          if (extractedPayloadBytes.length < payloadLength) {
            const bit = rawPixels[i + c] & 1;
            byteVal = (byteVal << 1) | bit;
            bitInByteCount++;

            if (bitInByteCount === 8) {
              extractedPayloadBytes.push(byteVal);
              byteVal = 0;
              bitInByteCount = 0;
            }
          }
        }
      }

      let finalPayload = Buffer.from(extractedPayloadBytes);
      if (isEncrypted) {
        finalPayload = decryptPayload(finalPayload, password.trim());
      }

      return {
        success: true,
        isEncrypted,
        methodName: isEncrypted ? 'CyberShield Protocol (Decrypted)' : 'CyberShield Protocol (Plaintext)',
        detectionType: 'CYBERSHIELD',
        secretText: finalPayload.toString('utf8'),
        payloadSize: finalPayload.length,
        imageInfo: {
          width,
          height,
          format: metadata.format
        }
      };
    }
  }

  // ==========================================
  // Layer 2: Check Appended EOF Steganography
  // ==========================================
  const appendedData = detectAppendedData(imageBuffer);
  if (appendedData.hasAppendedData) {
    if (appendedData.type === 'PLAINTEXT') {
      return {
        success: true,
        isEncrypted: false,
        methodName: `Appended EOF Steganography (${appendedData.format})`,
        detectionType: 'APPENDED_EOF',
        secretText: appendedData.text,
        payloadSize: appendedData.size,
        imageInfo: { width, height, format: metadata.format }
      };
    }

    if (appendedData.type === 'ZIP_ARCHIVE' || appendedData.type === '7Z_ARCHIVE' || appendedData.type === 'RAR_ARCHIVE') {
      const b64 = appendedData.rawData.toString('base64');
      return {
        success: true,
        isEncrypted: false,
        methodName: `Appended EOF Steganography (${appendedData.description})`,
        detectionType: 'APPENDED_EOF',
        secretText: `[Hidden Archive Recovered]\n\nFile Type: ${appendedData.description}\nSize: ${formatBytes(appendedData.size)}\nFilename: ${appendedData.filename || 'archive.zip'}`,
        downloadFileName: appendedData.filename || 'extracted_payload.zip',
        downloadDataUrl: `data:application/octet-stream;base64,${b64}`,
        payloadSize: appendedData.size,
        imageInfo: { width, height, format: metadata.format }
      };
    }

    // Generic binary trailing data
    return {
      success: true,
      isEncrypted: false,
      methodName: `Appended EOF Steganography (${appendedData.format})`,
      detectionType: 'APPENDED_EOF',
      secretText: `[Trailing Binary Data Recovered]\n\nSize: ${formatBytes(appendedData.size)}\nHex Dump (First 128 bytes):\n${appendedData.rawData.subarray(0, 128).toString('hex')}`,
      payloadSize: appendedData.size,
      imageInfo: { width, height, format: metadata.format }
    };
  }

  // ==========================================
  // Layer 3: Check Generic LSB Steganography
  // ==========================================
  const genericLsb = scanGenericLsbPayloads(rawPixels, width, height, Math.floor(totalRgbBits / 8));
  if (genericLsb.detected && genericLsb.text) {
    return {
      success: true,
      isEncrypted: false,
      methodName: `Generic LSB Steganography (${genericLsb.format})`,
      detectionType: 'GENERIC_LSB',
      secretText: genericLsb.text,
      payloadSize: Buffer.byteLength(genericLsb.text, 'utf8'),
      imageInfo: { width, height, format: metadata.format }
    };
  }

  // ==========================================
  // Layer 4: Check EXIF Metadata Steganography
  // ==========================================
  const exifStego = detectExifStego(metadata);
  if (exifStego.detected && exifStego.preview) {
    return {
      success: true,
      isEncrypted: false,
      methodName: `EXIF Metadata Steganography (${exifStego.field})`,
      detectionType: 'METADATA_EXIF',
      secretText: exifStego.preview,
      payloadSize: Buffer.byteLength(exifStego.preview, 'utf8'),
      imageInfo: { width, height, format: metadata.format }
    };
  }

  // ==========================================
  // Layer 5: Statistical Steganalysis for External / Encrypted Tools
  // ==========================================
  const statistical = performStatisticalSteganalysis(rawPixels, width, height);
  if (statistical.isSuspicious) {
    // Extract first 128 bytes of LSB bitstream to show hex dump
    const rawLsbSample = extractLsbBytesFromPixels(rawPixels, 128, true, 3);
    const hexDump = rawLsbSample.toString('hex').match(/.{1,2}/g)?.join(' ') || '';

    return {
      success: true,
      isEncrypted: true,
      isExternalTool: true,
      requiresPassword: true,
      methodName: 'External Stego Tool (Statistical Detection)',
      detectionType: 'STATISTICAL_LSB',
      message: `Steganographic payload detected (${statistical.chiSquare.stegoProbability}% confidence via Chi-Square analysis). The data appears to be encrypted or compressed using an external tool (e.g. Steghide, OpenStego, or custom cipher).`,
      secretText: `[Encrypted / High-Entropy Steganography Detected]\n\nConfidence: ${statistical.chiSquare.stegoProbability}%\nDetection Method: Chi-Square PoVs Steganalysis\nEstimated Payload Size: ~${statistical.formattedEstimatedPayload}\nLSB Entropy: ${statistical.entropy.lsbBitEntropy} / 1.0000\n\nRaw Bitstream Hex Dump (Sample):\n${hexDump}`,
      payloadSize: statistical.estimatedPayloadBytes,
      imageInfo: { width, height, format: metadata.format }
    };
  }

  // If absolutely no steganographic signatures or anomalies were found
  throw new Error('No steganographic payload or LSB anomalies detected in this image. The carrier appears clean.');
}
