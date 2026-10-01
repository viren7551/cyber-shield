import sharp from 'sharp';
import { encryptPayload, decryptPayload } from './cryptoUtils.js';

const MAGIC_HEADER = Buffer.from('CSHD'); // CyberShield Header (4 bytes)
const HEADER_SIZE = 9; // 4 magic + 1 flags + 4 length = 9 bytes (72 bits)

/**
 * Calculates carrier capacity for raw RGBA buffer
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

export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

/**
 * Embed secret text/data into an image buffer
 */
export async function embedData(imageBuffer, secretText, password = '') {
  // Convert image to raw RGBA
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

  const totalAvailableBits = width * height * 3; // R, G, B channels
  if (totalNeededBits > totalAvailableBits) {
    const maxBytes = Math.floor((totalAvailableBits - (HEADER_SIZE * 8)) / 8);
    throw new Error(
      `Image is too small for this payload. Capacity: ${formatBytes(maxBytes)}, required: ${formatBytes(payloadLength)}.`
    );
  }

  // Construct complete stream: [MAGIC(4)][FLAGS(1)][LENGTH(4)][PAYLOAD]
  const flags = isEncrypted ? 1 : 0;
  const headerBuf = Buffer.alloc(HEADER_SIZE);
  MAGIC_HEADER.copy(headerBuf, 0);
  headerBuf.writeUInt8(flags, 4);
  headerBuf.writeUInt32BE(payloadLength, 5);

  const fullStream = Buffer.concat([headerBuf, payloadBuffer]);

  // Convert fullStream into bit array
  const bits = [];
  for (let i = 0; i < fullStream.length; i++) {
    const byte = fullStream[i];
    for (let bitIdx = 7; bitIdx >= 0; bitIdx--) {
      bits.push((byte >> bitIdx) & 1);
    }
  }

  // Modify LSB of R, G, B channels in rawPixels
  let bitIndex = 0;
  const totalBitsToEmbed = bits.length;
  let alteredPixelsCount = 0;

  for (let i = 0; i < rawPixels.length && bitIndex < totalBitsToEmbed; i += 4) {
    // rawPixels[i] = R, rawPixels[i+1] = G, rawPixels[i+2] = B, rawPixels[i+3] = Alpha
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

  // Encode altered raw pixels to PNG (lossless is required for steganography)
  const stegoPngBuffer = await sharp(rawPixels, {
    raw: {
      width: info.width,
      height: info.height,
      channels: 4
    }
  }).png({ compressionLevel: 6 }).toBuffer();

  // Metrics
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
 * Extract secret text/data from an image buffer
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

  if (totalRgbBits < headerBitsNeeded) {
    throw new Error('Image too small to contain CyberShield header.');
  }

  // Extract first 72 bits for header
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

  if (!magic.equals(MAGIC_HEADER)) {
    throw new Error('No CyberShield steganographic payload detected in this image.');
  }

  const flags = headerBuf.readUInt8(4);
  const isEncrypted = (flags & 1) === 1;
  const payloadLength = headerBuf.readUInt32BE(5);

  const maxPossibleBytes = Math.floor((totalRgbBits - headerBitsNeeded) / 8);
  if (payloadLength <= 0 || payloadLength > maxPossibleBytes) {
    throw new Error(`Corrupted steganography header or invalid payload size (${payloadLength} bytes).`);
  }

  // Extract payload bytes
  const extractedPayloadBytes = [];
  byteVal = 0;
  bitInByteCount = 0;

  for (let i = 0; i < rawPixels.length && extractedPayloadBytes.length < payloadLength; i += 4) {
    for (let c = 0; c < 3; c++) {
      // Skip the bits already consumed by the header
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
    if (!password || password.trim().length === 0) {
      return {
        isEncrypted: true,
        requiresPassword: true,
        message: 'This payload is encrypted with a password. Please provide the secret key to decrypt.',
        payloadLength
      };
    }
    finalPayload = decryptPayload(finalPayload, password.trim());
  }

  const secretText = finalPayload.toString('utf8');

  return {
    success: true,
    isEncrypted,
    secretText,
    payloadSize: finalPayload.length,
    imageInfo: {
      width,
      height,
      format: metadata.format
    }
  };
}

/**
 * Inspect image metadata and stego capacity without embedding
 */
export async function analyzeImage(imageBuffer) {
  const image = sharp(imageBuffer);
  const metadata = await image.metadata();
  const { width, height, format, space, channels, size } = metadata;

  const capacity = calculateCapacity(width, height);

  // Check if it already contains CyberShield header
  let hasCyberShieldHeader = false;
  let isEncrypted = false;
  let detectedPayloadSize = 0;

  try {
    const { data: rawPixels } = await image.ensureAlpha().raw().toBuffer({ resolveWithObject: true });
    if (rawPixels.length >= HEADER_SIZE * 4) {
      let byteVal = 0;
      let bitCount = 0;
      const headerBytes = [];
      for (let i = 0; i < rawPixels.length && headerBytes.length < HEADER_SIZE; i += 4) {
        for (let c = 0; c < 3; c++) {
          if (headerBytes.length < HEADER_SIZE) {
            byteVal = (byteVal << 1) | (rawPixels[i + c] & 1);
            bitCount++;
            if (bitCount === 8) {
              headerBytes.push(byteVal);
              byteVal = 0;
              bitCount = 0;
            }
          }
        }
      }
      const headerBuf = Buffer.from(headerBytes);
      if (headerBuf.subarray(0, 4).equals(MAGIC_HEADER)) {
        hasCyberShieldHeader = true;
        isEncrypted = (headerBuf.readUInt8(4) & 1) === 1;
        detectedPayloadSize = headerBuf.readUInt32BE(5);
      }
    }
  } catch (e) {
    // If analysis fails, proceed with default false
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
      hasCyberShieldHeader,
      isEncrypted,
      detectedPayloadSize,
      formattedDetectedSize: formatBytes(detectedPayloadSize)
    }
  };
}
