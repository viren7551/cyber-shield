import crypto from 'crypto';

// Top common leaked passwords / sequences for instant local penalty
const COMMON_PATTERNS = [
  'password', '123456', '12345678', 'qwerty', 'admin', 'welcome', 'login',
  '123456789', '12345', 'pass123', 'iloveyou', 'secret', 'monkey', 'dragon'
];

/**
 * Calculate Shannon entropy and character pool
 */
export function calculateEntropy(password) {
  if (!password) return { entropyBits: 0, poolSize: 0 };

  let poolSize = 0;
  if (/[a-z]/.test(password)) poolSize += 26;
  if (/[A-Z]/.test(password)) poolSize += 26;
  if (/[0-9]/.test(password)) poolSize += 10;
  if (/[^a-zA-Z0-9]/.test(password)) poolSize += 33;

  const length = password.length;
  let rawEntropy = length * (poolSize > 0 ? Math.log2(poolSize) : 0);

  // Pattern penalty
  const lower = password.toLowerCase();
  for (const pat of COMMON_PATTERNS) {
    if (lower.includes(pat)) {
      rawEntropy = Math.max(10, rawEntropy - 20);
    }
  }

  // Repetition penalty
  const uniqueChars = new Set(password).size;
  const repetitionFactor = uniqueChars / length;
  const entropyBits = Math.max(0, Math.round(rawEntropy * repetitionFactor));

  return { entropyBits, poolSize, uniqueChars };
}

/**
 * Estimate crack time for different attack speeds
 */
export function estimateCrackTime(entropyBits) {
  // Total possible combinations = 2^entropy
  const combinations = Math.pow(2, entropyBits);

  // Attack models:
  // 1. Online Throttled (100 guesses / sec)
  // 2. Slow Hash - Argon2/Bcrypt (10,000 guesses / sec)
  // 3. Fast GPU Hashcat Cluster - NTLM/MD5 (100,000,000,000 guesses / sec = 100 GH/s)
  const secondsOnline = combinations / 100;
  const secondsSlowHash = combinations / 10000;
  const secondsFastGpu = combinations / 100000000000;

  return {
    online: formatDuration(secondsOnline),
    offlineSlow: formatDuration(secondsSlowHash),
    offlineFast: formatDuration(secondsFastGpu),
    secondsFastGpu
  };
}

export function formatDuration(seconds) {
  if (seconds < 1) return 'Instant';
  if (seconds < 60) return `${Math.round(seconds)} seconds`;
  const minutes = seconds / 60;
  if (minutes < 60) return `${Math.round(minutes)} minutes`;
  const hours = minutes / 60;
  if (hours < 24) return `${Math.round(hours)} hours`;
  const days = hours / 24;
  if (days < 30) return `${Math.round(days)} days`;
  const months = days / 30;
  if (months < 12) return `${Math.round(months)} months`;
  const years = days / 365;
  if (years < 100) return `${Math.round(years)} years`;
  if (years < 10000) return `${Math.round(years / 1000)}k years`;
  if (years < 1000000) return `${Math.round(years / 1000)}k years`;
  return 'Centuries+';
}

/**
 * Calculate overall security score (0-100) and grade
 */
export function computeScore(password, entropyBits, isBreached) {
  if (!password || password.length === 0) {
    return { score: 0, grade: 'F', strength: 'Very Weak' };
  }

  let score = 0;

  // Length points (up to 40)
  score += Math.min(40, password.length * 3);

  // Diversity points (up to 30)
  if (/[a-z]/.test(password)) score += 6;
  if (/[A-Z]/.test(password)) score += 8;
  if (/[0-9]/.test(password)) score += 8;
  if (/[^a-zA-Z0-9]/.test(password)) score += 8;

  // Entropy bonus (up to 30)
  score += Math.min(30, Math.round(entropyBits * 0.4));

  // Cap at 100
  score = Math.min(100, Math.max(5, score));

  // If found in a public breach, severely penalize grade
  if (isBreached) {
    score = Math.min(25, score);
  }

  let grade = 'F';
  let strength = 'Very Weak';

  if (score >= 90) {
    grade = 'A+';
    strength = 'Very Strong';
  } else if (score >= 75) {
    grade = 'A';
    strength = 'Strong';
  } else if (score >= 60) {
    grade = 'B';
    strength = 'Good';
  } else if (score >= 45) {
    grade = 'C';
    strength = 'Fair';
  } else if (score >= 30) {
    grade = 'D';
    strength = 'Weak';
  }

  return { score, grade, strength };
}

/**
 * Privacy-preserving breach check using k-Anonymity SHA-1 lookup
 */
export async function checkBreachKAnonymity(password) {
  try {
    const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    // Query HIBP range API with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3500);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      signal: controller.signal,
      headers: { 'Add-Padding': 'true' } // Extra privacy padding
    });
    clearTimeout(timeoutId);

    if (!res.ok) {
      return { checked: false, isBreached: false, breachCount: 0, offlineFallback: true };
    }

    const text = await res.text();
    const lines = text.split('\r\n');

    for (const line of lines) {
      const [hashSuffix, countStr] = line.split(':');
      if (hashSuffix === suffix) {
        const count = parseInt(countStr, 10);
        return { checked: true, isBreached: true, breachCount: count, hashPrefix: prefix };
      }
    }

    return { checked: true, isBreached: false, breachCount: 0, hashPrefix: prefix };
  } catch (err) {
    // Check local high-risk dictionary as fallback
    const isCommon = COMMON_PATTERNS.some((p) => password.toLowerCase().includes(p));
    return {
      checked: true,
      isBreached: isCommon,
      breachCount: isCommon ? 50000 : 0,
      offlineFallback: true
    };
  }
}

/**
 * Cryptographically secure random password generator
 */
export function generatePassword(options = {}) {
  const {
    length = 16,
    uppercase = true,
    lowercase = true,
    numbers = true,
    symbols = true,
    excludeAmbiguous = true
  } = options;

  let chars = '';
  if (lowercase) chars += excludeAmbiguous ? 'abcdefghjkmnpqrstuvwxyz' : 'abcdefghijklmnopqrstuvwxyz';
  if (uppercase) chars += excludeAmbiguous ? 'ABCDEFGHJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  if (numbers) chars += excludeAmbiguous ? '23456789' : '0123456789';
  if (symbols) chars += '!@#$%^&*()_+~|}{[]:;?><,.-=';

  if (!chars) chars = 'abcdefghjkmnpqrstuvwxyz23456789';

  const randomBytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[randomBytes[i] % chars.length];
  }

  return result;
}
