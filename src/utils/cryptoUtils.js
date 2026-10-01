import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const KEY_LEN = 32; // 256 bits
const IV_LEN = 12;  // 96 bits for GCM
const SALT_LEN = 16;
const ITERATIONS = 100000;

/**
 * Encrypt a buffer or UTF-8 string with a password using AES-256-GCM
 */
export function encryptPayload(dataBuffer, password) {
  const salt = crypto.randomBytes(SALT_LEN);
  const iv = crypto.randomBytes(IV_LEN);
  const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const ciphertext = Buffer.concat([cipher.update(dataBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Packed format: [salt(16)][iv(12)][authTag(16)][ciphertext]
  return Buffer.concat([salt, iv, authTag, ciphertext]);
}

/**
 * Decrypt encrypted payload buffer with password
 */
export function decryptPayload(packedBuffer, password) {
  if (packedBuffer.length < SALT_LEN + IV_LEN + 16) {
    throw new Error('Encrypted payload too short or corrupted');
  }

  const salt = packedBuffer.subarray(0, SALT_LEN);
  const iv = packedBuffer.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const authTag = packedBuffer.subarray(SALT_LEN + IV_LEN, SALT_LEN + IV_LEN + 16);
  const ciphertext = packedBuffer.subarray(SALT_LEN + IV_LEN + 16);

  const key = crypto.pbkdf2Sync(password, salt, ITERATIONS, KEY_LEN, 'sha256');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error('Decryption failed. Incorrect password or data corrupted.');
  }
}
