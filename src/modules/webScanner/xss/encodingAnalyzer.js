/**
 * CyberShield Web Security Scanner - Output Encoding Analyzer
 * Compares injected probe characters (< > " ' &) against returned representations
 * in the actual server response, precisely scoped to the reflected injection window
 * to avoid false matches on the application's existing HTML tags.
 */

export const ENCODING_STATUS = {
  SAFE_ENCODED: 'SAFE_ENCODED',
  UNENCODED: 'UNENCODED',
  PARTIALLY_ENCODED: 'PARTIALLY_ENCODED',
  NOT_REFLECTED: 'NOT_REFLECTED',
  CANARY_ONLY: 'CANARY_ONLY'
};

/**
 * Checks if a string contains a raw ampersand that is NOT part of a valid HTML entity.
 */
function hasRawAmpersand(str) {
  const stripped = str.replace(/&(?:[a-zA-Z0-9]+|#[0-9]{1,6}|#[xX][0-9a-fA-F]{1,6});/g, '');
  return stripped.includes('&');
}

/**
 * Analyzes the output encoding of user-controlled input reflected in an HTTP response.
 *
 * @param {string} responseBody - The full HTTP response body
 * @param {string} markerPrefix - The base canary token prefix (e.g., XSSSCAN_12345)
 * @param {string} injectedSuffix - Special probe characters injected after the marker (default: '\'"><csxss>&')
 * @returns {object} Encoding analysis result
 */
export function analyzeOutputEncoding(responseBody, markerPrefix, injectedSuffix = '\'"><csxss>&') {
  if (!responseBody || typeof responseBody !== 'string' || !markerPrefix) {
    return {
      status: ENCODING_STATUS.NOT_REFLECTED,
      encoding: 'UNKNOWN',
      reflectionFound: false,
      hasUnencodedMetas: false,
      isProperlyEncoded: false,
      unencodedChars: [],
      encodedChars: [],
      transformations: {},
      details: 'No response body or marker provided.'
    };
  }

  const markerIdx = responseBody.indexOf(markerPrefix);
  if (markerIdx === -1) {
    return {
      status: ENCODING_STATUS.NOT_REFLECTED,
      encoding: 'UNKNOWN',
      reflectionFound: false,
      hasUnencodedMetas: false,
      isProperlyEncoded: false,
      unencodedChars: [],
      encodedChars: [],
      transformations: {},
      details: 'Probe marker was not reflected in the HTTP response.'
    };
  }

  // If no injected suffix was provided, only the marker itself was checked
  if (!injectedSuffix || injectedSuffix.length === 0) {
    return {
      status: ENCODING_STATUS.CANARY_ONLY,
      encoding: 'UNKNOWN',
      reflectionFound: true,
      hasUnencodedMetas: false,
      isProperlyEncoded: false,
      unencodedChars: [],
      encodedChars: [],
      transformations: {},
      details: 'Pure marker token reflected without metacharacter probe.'
    };
  }

  // Probe window directly after marker (bounded to the immediate reflection area)
  // Max probe window: 70 characters
  const afterMarker = responseBody.substring(
    markerIdx + markerPrefix.length,
    Math.min(responseBody.length, markerIdx + markerPrefix.length + 70)
  );

  const transformations = {};
  const unencodedChars = [];
  const encodedChars = [];

  // 1. Analyze '<' using the diagnostic probe tag <csxss>
  // To avoid false positives on the application's own HTML tags (like </h1> or </div>),
  // we check whether our unique tag identifier "csxss" is preceded by raw '<' or encoded '&lt;'
  const rawLt = afterMarker.includes('<csxss') || afterMarker.includes('<\'"><csxss');
  const encodedLt = afterMarker.includes('&lt;csxss') || afterMarker.includes('&#60;csxss') || afterMarker.includes('&#x3c;csxss');

  if (rawLt) {
    unencodedChars.push('<');
    transformations['<'] = 'RAW (<)';
  } else if (encodedLt) {
    encodedChars.push('&lt;');
    transformations['<'] = '&lt;';
  } else if (injectedSuffix.includes('<')) {
    transformations['<'] = 'STRIPPED/FILTERED';
  }

  // 2. Analyze '>' using the probe tag <csxss> or delimiter sequence
  const rawGt = afterMarker.includes('csxss>') || afterMarker.includes('"><') || afterMarker.includes('\'><');
  const encodedGt = afterMarker.includes('csxss&gt;') || afterMarker.includes('csxss&#62;') || afterMarker.includes('csxss&#x3e;') ||
    (encodedLt && (afterMarker.includes('&gt;') || afterMarker.includes('&#62;')));

  if (rawGt) {
    unencodedChars.push('>');
    transformations['>'] = 'RAW (>)';
  } else if (encodedGt) {
    encodedChars.push('&gt;');
    transformations['>'] = '&gt;';
  } else if (injectedSuffix.includes('>')) {
    transformations['>'] = 'STRIPPED/FILTERED';
  }

  // 3. Analyze quotes (' and ") in the segment preceding 'csxss'
  // In probe '\'"><csxss>&', quotes are immediately after marker before csxss
  const csxssIdx = afterMarker.indexOf('csxss');
  const quoteSegment = csxssIdx !== -1
    ? afterMarker.substring(0, csxssIdx)
    : afterMarker.substring(0, Math.min(afterMarker.length, 25));

  // Single quote analysis
  if (injectedSuffix.includes("'")) {
    const rawSingle = quoteSegment.includes("'");
    const encodedSingle = quoteSegment.includes('&#39;') || quoteSegment.includes('&#x27;') || quoteSegment.includes('&apos;') ||
      afterMarker.includes('&#39;') || afterMarker.includes('&#x27;') || afterMarker.includes('&apos;');

    if (rawSingle) {
      unencodedChars.push("'");
      transformations["'"] = "RAW (')";
    } else if (encodedSingle) {
      encodedChars.push('&#39;');
      transformations["'"] = '&#39;';
    } else {
      transformations["'"] = 'STRIPPED/FILTERED';
    }
  }

  // Double quote analysis
  if (injectedSuffix.includes('"')) {
    const rawDouble = quoteSegment.includes('"');
    const encodedDouble = quoteSegment.includes('&quot;') || quoteSegment.includes('&#34;') || quoteSegment.includes('&#x22;') ||
      afterMarker.includes('&quot;') || afterMarker.includes('&#34;') || afterMarker.includes('&#x22;');

    if (rawDouble) {
      unencodedChars.push('"');
      transformations['"'] = 'RAW (")';
    } else if (encodedDouble) {
      encodedChars.push('&quot;');
      transformations['"'] = '&quot;';
    } else {
      transformations['"'] = 'STRIPPED/FILTERED';
    }
  }

  // 4. Analyze ampersand '&'
  if (injectedSuffix.includes('&')) {
    // Check if ampersand was encoded as &amp;
    const encodedAmp = afterMarker.includes('&amp;') || afterMarker.includes('&#38;') || afterMarker.includes('&#x26;');
    const rawAmp = hasRawAmpersand(quoteSegment) || (csxssIdx !== -1 && hasRawAmpersand(afterMarker.substring(csxssIdx, csxssIdx + 20)));

    if (rawAmp) {
      unencodedChars.push('&');
      transformations['&'] = 'RAW (&)';
    } else if (encodedAmp) {
      encodedChars.push('&amp;');
      transformations['&'] = '&amp;';
    } else {
      transformations['&'] = 'STRIPPED/FILTERED';
    }
  }

  // Determine overall status
  const criticalMetas = ['<', '>', '"', "'"];
  const unencodedCritical = unencodedChars.filter(c => criticalMetas.includes(c));

  if (unencodedCritical.length === 0 && encodedChars.length > 0) {
    return {
      status: ENCODING_STATUS.SAFE_ENCODED,
      encoding: 'HTML_ENTITIES',
      reflectionFound: true,
      hasUnencodedMetas: false,
      isProperlyEncoded: true,
      unencodedChars: [],
      encodedChars,
      transformations,
      details: `Input is safely neutralized with HTML entity encoding (${encodedChars.join(' ')}).`
    };
  }

  if (unencodedCritical.length > 0 && encodedChars.length === 0) {
    return {
      status: ENCODING_STATUS.UNENCODED,
      encoding: 'NONE',
      reflectionFound: true,
      hasUnencodedMetas: true,
      isProperlyEncoded: false,
      unencodedChars,
      encodedChars: [],
      transformations,
      details: `HTML metacharacters (${unencodedChars.join(' ')}) were returned raw without entity encoding.`
    };
  }

  if (unencodedCritical.length > 0 && encodedChars.length > 0) {
    return {
      status: ENCODING_STATUS.PARTIALLY_ENCODED,
      encoding: 'PARTIAL',
      reflectionFound: true,
      hasUnencodedMetas: true,
      isProperlyEncoded: false,
      unencodedChars,
      encodedChars,
      transformations,
      details: `Partial encoding detected: characters (${unencodedChars.join(' ')}) remain unencoded while (${encodedChars.join(' ')}) were converted.`
    };
  }

  // All critical metas stripped or canary only
  return {
    status: ENCODING_STATUS.SAFE_ENCODED,
    encoding: 'NONE',
    reflectionFound: true,
    hasUnencodedMetas: false,
    isProperlyEncoded: true,
    unencodedChars: [],
    encodedChars: [],
    transformations,
    details: 'Input reflected without unencoded HTML metacharacters.'
  };
}
