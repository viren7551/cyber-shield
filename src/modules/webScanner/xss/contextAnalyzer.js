/**
 * CyberShield Web Security Scanner - DOM & HTML Reflection Context Analyzer
 * Accurately determines the syntactic parser context of reflected user input
 * and evaluates whether injected characters can alter browser parsing semantics.
 */

export const XSS_CONTEXTS = {
  HTML_TEXT: 'HTML_TEXT',
  HTML_ATTRIBUTE: 'HTML_ATTRIBUTE',
  HTML_ATTRIBUTE_VALUE: 'HTML_ATTRIBUTE_VALUE',
  JAVASCRIPT_STRING: 'JAVASCRIPT_STRING',
  JAVASCRIPT_CODE: 'JAVASCRIPT_CODE',
  CSS_CONTEXT: 'CSS_CONTEXT',
  URL_CONTEXT: 'URL_CONTEXT',
  HTML_COMMENT: 'HTML_COMMENT',
  SCRIPT_CONTEXT: 'SCRIPT_CONTEXT',
  STYLE_CONTEXT: 'STYLE_CONTEXT',
  UNKNOWN: 'UNKNOWN'
};

export const FINDING_STATES = {
  NO_REFLECTION: 'NO_REFLECTION',
  REFLECTION_ONLY: 'REFLECTION_ONLY',
  ENCODED_REFLECTION: 'ENCODED_REFLECTION',
  POTENTIAL_XSS: 'POTENTIAL_XSS',
  HIGH_CONFIDENCE_XSS: 'HIGH_CONFIDENCE_XSS',
  CONFIRMED_XSS: 'CONFIRMED_XSS',
  NEEDS_MANUAL_VERIFICATION: 'NEEDS_MANUAL_VERIFICATION'
};

/**
 * Determine line and column number from string index.
 */
function getLineAndCol(text, index) {
  const lines = text.substring(0, index).split('\n');
  const line = lines.length;
  const col = lines[lines.length - 1].length + 1;
  return { line, col };
}

/**
 * Determine the syntactic context of reflected marker in an HTML response.
 * @param {string} html - HTML body response
 * @param {string} marker - Unique probe marker (e.g., XSSSCAN_12345)
 * @returns {object} Context evaluation details
 */
export function analyzeReflectionContext(html, marker) {
  if (!html || typeof html !== 'string' || !marker) {
    return {
      reflected: false,
      context: XSS_CONTEXTS.UNKNOWN,
      occurrences: 0,
      snippet: '',
      contextBefore: '',
      contextAfter: '',
      reflectionLocation: null,
      quoteChar: null,
      details: 'No HTML response or marker provided.'
    };
  }

  const markerIdx = html.indexOf(marker);
  if (markerIdx === -1) {
    return {
      reflected: false,
      context: XSS_CONTEXTS.UNKNOWN,
      occurrences: 0,
      snippet: '',
      contextBefore: '',
      contextAfter: '',
      reflectionLocation: null,
      quoteChar: null,
      details: 'Probe marker was not reflected in the response.'
    };
  }

  // Count total occurrences
  let occurrences = 0;
  let pos = html.indexOf(marker);
  while (pos !== -1) {
    occurrences++;
    pos = html.indexOf(marker, pos + marker.length);
  }

  // Extract snippet and context windows around first match
  const startPos = Math.max(0, markerIdx - 45);
  const endPos = Math.min(html.length, markerIdx + marker.length + 55);
  const snippet = html.substring(startPos, endPos).replace(/[\r\n]+/g, ' ').trim();

  const contextBefore = html.substring(Math.max(0, markerIdx - 40), markerIdx);
  const contextAfter = html.substring(markerIdx + marker.length, Math.min(html.length, markerIdx + marker.length + 40));
  const location = getLineAndCol(html, markerIdx);

  // 1. Check if inside HTML comment: <!-- ... marker ... -->
  const lastCommentOpen = html.lastIndexOf('<!--', markerIdx);
  const lastCommentClose = html.lastIndexOf('-->', markerIdx);
  if (lastCommentOpen !== -1 && lastCommentOpen > lastCommentClose) {
    return {
      reflected: true,
      context: XSS_CONTEXTS.HTML_COMMENT,
      occurrences,
      snippet,
      contextBefore,
      contextAfter,
      reflectionLocation: location,
      quoteChar: null,
      details: 'Reflected inside an HTML comment block (<!-- ... -->)'
    };
  }

  // 2. Check if inside <style> ... </style> block
  const lastStyleOpen = html.toLowerCase().lastIndexOf('<style', markerIdx);
  const lastStyleClose = html.toLowerCase().lastIndexOf('</style>', markerIdx);
  if (lastStyleOpen !== -1 && lastStyleOpen > lastStyleClose) {
    // Check if inside CSS string
    const codeBeforeInStyle = html.substring(lastStyleOpen, markerIdx);
    const doubleQuoteCount = (codeBeforeInStyle.match(/"/g) || []).length;
    const singleQuoteCount = (codeBeforeInStyle.match(/'/g) || []).length;
    const isQuoted = (doubleQuoteCount % 2 === 1) || (singleQuoteCount % 2 === 1);
    return {
      reflected: true,
      context: isQuoted ? XSS_CONTEXTS.CSS_CONTEXT : XSS_CONTEXTS.STYLE_CONTEXT,
      occurrences,
      snippet,
      contextBefore,
      contextAfter,
      reflectionLocation: location,
      quoteChar: doubleQuoteCount % 2 === 1 ? '"' : singleQuoteCount % 2 === 1 ? "'" : null,
      details: isQuoted
        ? 'Reflected inside a quoted CSS string value within a <style> block'
        : 'Reflected inside CSS style rules within a <style> block'
    };
  }

  // 3. Check if inside <script> ... </script> block
  const lastScriptOpen = html.toLowerCase().lastIndexOf('<script', markerIdx);
  const lastScriptClose = html.toLowerCase().lastIndexOf('</script>', markerIdx);
  if (lastScriptOpen !== -1 && lastScriptOpen > lastScriptClose) {
    const codeBeforeInScript = html.substring(lastScriptOpen, markerIdx);
    const doubleQuoteCount = (codeBeforeInScript.match(/"/g) || []).length;
    const singleQuoteCount = (codeBeforeInScript.match(/'/g) || []).length;
    const backtickCount = (codeBeforeInScript.match(/`/g) || []).length;

    const inDouble = doubleQuoteCount % 2 === 1;
    const inSingle = singleQuoteCount % 2 === 1;
    const inBacktick = backtickCount % 2 === 1;
    const isInsideString = inDouble || inSingle || inBacktick;

    const quote = inDouble ? '"' : inSingle ? "'" : inBacktick ? '`' : null;

    return {
      reflected: true,
      context: isInsideString ? XSS_CONTEXTS.JAVASCRIPT_STRING : XSS_CONTEXTS.JAVASCRIPT_CODE,
      occurrences,
      snippet,
      contextBefore,
      contextAfter,
      reflectionLocation: location,
      quoteChar: quote,
      details: isInsideString
        ? `Reflected inside a JavaScript string literal (${quote || 'string'}) within a <script> block`
        : 'Reflected directly as unquoted executable JavaScript syntax in a <script> block'
    };
  }

  // 4. Inspect tag boundaries: look backwards for '<' vs '>'
  const lastTagOpen = html.lastIndexOf('<', markerIdx);
  const lastTagClose = html.lastIndexOf('>', markerIdx);

  // If inside an open tag: <tag attr="marker" ...
  if (lastTagOpen !== -1 && lastTagOpen > lastTagClose) {
    const beforeMarkerInTag = html.substring(lastTagOpen, markerIdx);

    // Check if inside event handler attribute: onclick, onload, onerror, etc.
    const eventHandlerRegex = /\bon[a-z]+\s*=\s*(["']?)([^"'>]*)$/i;
    const eventMatch = eventHandlerRegex.exec(beforeMarkerInTag);
    if (eventMatch) {
      const quote = eventMatch[1] || null;
      return {
        reflected: true,
        context: quote ? XSS_CONTEXTS.JAVASCRIPT_STRING : XSS_CONTEXTS.JAVASCRIPT_CODE,
        occurrences,
        snippet,
        contextBefore,
        contextAfter,
        reflectionLocation: location,
        quoteChar: quote,
        details: 'Reflected inside an inline HTML JavaScript event handler attribute'
      };
    }

    // Check if inside URL attribute: href, src, action, formaction
    const urlAttrRegex = /\b(?:href|src|action|formaction)\s*=\s*(["']?)([^"'>]*)$/i;
    const urlMatch = urlAttrRegex.exec(beforeMarkerInTag);
    if (urlMatch) {
      return {
        reflected: true,
        context: XSS_CONTEXTS.URL_CONTEXT,
        occurrences,
        snippet,
        contextBefore,
        contextAfter,
        reflectionLocation: location,
        quoteChar: urlMatch[1] || null,
        details: 'Reflected inside a navigation/resource URL attribute (href, src, or action)'
      };
    }

    // Check if inside style attribute: style="...marker..."
    const styleAttrRegex = /\bstyle\s*=\s*(["']?)([^"'>]*)$/i;
    const styleMatch = styleAttrRegex.exec(beforeMarkerInTag);
    if (styleMatch) {
      return {
        reflected: true,
        context: XSS_CONTEXTS.STYLE_CONTEXT,
        occurrences,
        snippet,
        contextBefore,
        contextAfter,
        reflectionLocation: location,
        quoteChar: styleMatch[1] || null,
        details: 'Reflected inside an inline HTML style attribute'
      };
    }

    // Check if inside an attribute value: attr="marker" or attr='marker' or attr=marker
    const attrValueRegex = /=\s*(["']?)([^"'>]*)$/;
    const valMatch = attrValueRegex.exec(beforeMarkerInTag);
    if (valMatch) {
      return {
        reflected: true,
        context: XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE,
        occurrences,
        snippet,
        contextBefore,
        contextAfter,
        reflectionLocation: location,
        quoteChar: valMatch[1] || null,
        details: 'Reflected inside an HTML tag attribute value'
      };
    }

    // Otherwise reflected as an attribute name or bare attribute
    return {
      reflected: true,
      context: XSS_CONTEXTS.HTML_ATTRIBUTE,
      occurrences,
      snippet,
      contextBefore,
      contextAfter,
      reflectionLocation: location,
      quoteChar: null,
      details: 'Reflected inside an HTML tag element definition'
    };
  }

  // 5. Default: Standard HTML body text context
  return {
    reflected: true,
    context: XSS_CONTEXTS.HTML_TEXT,
    occurrences,
    snippet,
    contextBefore,
    contextAfter,
    reflectionLocation: location,
    quoteChar: null,
    details: 'Reflected directly as plain text within HTML document markup'
  };
}

/**
 * Evaluates whether observed unencoded characters can alter browser parsing semantics
 * for a specific syntactic context.
 *
 * @param {Array<string>} unencodedChars - List of unencoded characters detected (e.g. ['<', '>'])
 * @param {string} context - One of XSS_CONTEXTS
 * @param {string|null} quoteChar - Surrounding quote character if any ('"', "'", '`')
 * @returns {object} { canAlter: boolean, explanation: string }
 */
export function canAlterParsingContext(unencodedChars = [], context = XSS_CONTEXTS.UNKNOWN, quoteChar = null) {
  const chars = new Set(unencodedChars);

  switch (context) {
    case XSS_CONTEXTS.HTML_TEXT: {
      // In HTML_TEXT, attacker needs '<' to introduce new tag syntax (e.g. <script> or <img onerror=>)
      // Having '<' AND '>' or '<' with tag characters enables constructing a new DOM node.
      if (chars.has('<') && chars.has('>')) {
        return {
          canAlter: true,
          explanation: 'Both tag opening (<) and closing (>) characters were reflected raw, enabling injection of arbitrary HTML elements.'
        };
      }
      if (chars.has('<')) {
        return {
          canAlter: true,
          explanation: 'Tag opening character (<) was reflected raw, permitting construction of new HTML elements.'
        };
      }
      return {
        canAlter: false,
        explanation: 'Input is in HTML text context without unencoded tag opening (<) characters. Browser parses it strictly as text content.'
      };
    }

    case XSS_CONTEXTS.HTML_ATTRIBUTE_VALUE: {
      // If quoted, need the matching quote to escape the attribute value, or '>' to close the tag
      if (quoteChar && chars.has(quoteChar)) {
        return {
          canAlter: true,
          explanation: `Attribute delimiter (${quoteChar}) was reflected raw, enabling breakout from attribute value to inject new attributes or event handlers.`
        };
      }
      if (!quoteChar && (chars.has(' ') || chars.has('>'))) {
        return {
          canAlter: true,
          explanation: 'Unquoted attribute value allows space or tag close (>) to inject additional attributes or close tag.'
        };
      }
      if (chars.has('>') && (chars.has('"') || chars.has("'"))) {
        return {
          canAlter: true,
          explanation: 'Quotes and tag closing (>) reflected raw, enabling breakout from attribute and tag.'
        };
      }
      return {
        canAlter: false,
        explanation: 'Input is constrained within attribute quotes without unescaped quote delimiters.'
      };
    }

    case XSS_CONTEXTS.HTML_ATTRIBUTE: {
      if (chars.has('>') || chars.has('"') || chars.has("'") || chars.has(' ')) {
        return {
          canAlter: true,
          explanation: 'Tag closure (>) or delimiter reflected raw in attribute position, enabling attribute manipulation.'
        };
      }
      return {
        canAlter: false,
        explanation: 'Attribute position without unencoded delimiters.'
      };
    }

    case XSS_CONTEXTS.JAVASCRIPT_STRING: {
      // In JS string, need matching quote without backslash escaping, OR </script> tag breakout
      if (quoteChar && chars.has(quoteChar)) {
        return {
          canAlter: true,
          explanation: `JavaScript string quote delimiter (${quoteChar}) was reflected unescaped, enabling breakout into JavaScript code execution.`
        };
      }
      if (chars.has('<') && chars.has('>')) {
        return {
          canAlter: true,
          explanation: 'Tag delimiters (<, >) reflected raw inside <script>, enabling HTML parser breakout via </script>.'
        };
      }
      return {
        canAlter: false,
        explanation: 'Input is contained within JavaScript string literal without unescaped string quote delimiters.'
      };
    }

    case XSS_CONTEXTS.JAVASCRIPT_CODE:
    case XSS_CONTEXTS.SCRIPT_CONTEXT: {
      // In unquoted JS context, almost any unencoded syntax allows altering execution
      return {
        canAlter: true,
        explanation: 'Input is reflected directly into an executable JavaScript context without string encapsulation.'
      };
    }

    case XSS_CONTEXTS.URL_CONTEXT: {
      if (chars.has('"') || chars.has("'") || chars.has('>')) {
        return {
          canAlter: true,
          explanation: 'Delimiters allow breakout from URL attribute.'
        };
      }
      return {
        canAlter: false,
        explanation: 'URL context without attribute breakout characters.'
      };
    }

    case XSS_CONTEXTS.HTML_COMMENT: {
      if (chars.has('>') && chars.has('-')) {
        return {
          canAlter: true,
          explanation: 'Comment close characters (-->) allow breakout from HTML comment into markup.'
        };
      }
      return {
        canAlter: false,
        explanation: 'Input is safely enclosed within HTML comment block (<!-- ... -->).'
      };
    }

    case XSS_CONTEXTS.STYLE_CONTEXT:
    case XSS_CONTEXTS.CSS_CONTEXT: {
      if (chars.has('<') && chars.has('>')) {
        return {
          canAlter: true,
          explanation: 'Tag delimiters allow breakout from <style> block via </style>.'
        };
      }
      if (quoteChar && chars.has(quoteChar)) {
        return {
          canAlter: true,
          explanation: `CSS string delimiter (${quoteChar}) reflected unescaped.`
        };
      }
      return {
        canAlter: false,
        explanation: 'Input is constrained within CSS context.'
      };
    }

    default:
      return {
        canAlter: false,
        explanation: 'Context is unknown or unverified.'
      };
  }
}
