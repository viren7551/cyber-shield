/**
 * CyberShield Web Security Scanner - Form Security Analyzer
 * Passively extracts HTML forms, evaluates input field types, password handling,
 * and detects CSRF token indicators without submitting forms or performing attacks.
 */

const CSRF_NAME_PATTERNS = [
  /csrf/i, /xsrf/i, /_token/i, /authenticity_token/i, /nonce/i,
  /csrfmiddlewaretoken/i, /protect/i, /security_token/i
];

/**
 * Extract and analyze all <form> elements in HTML body
 * @param {string} html
 * @param {string} pageUrl
 */
export function analyzeForms(html, pageUrl) {
  const forms = [];
  const findings = [];
  if (!html || typeof html !== 'string') return { forms, findings };

  const isHttps = pageUrl.startsWith('https://');

  // Match all <form ...> ... </form> blocks
  const formRegex = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch;
  let formIndex = 0;

  while ((formMatch = formRegex.exec(html)) !== null) {
    formIndex++;
    const formAttrs = formMatch[1];
    const formContent = formMatch[2];

    // Extract action and method
    const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i);
    const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i);

    let rawAction = actionMatch ? actionMatch[1].trim() : pageUrl;
    let absoluteAction = pageUrl;
    try {
      absoluteAction = new URL(rawAction || '', pageUrl).toString();
    } catch {
      absoluteAction = pageUrl;
    }

    const method = methodMatch ? methodMatch[1].trim().toUpperCase() : 'GET';

    // Parse input fields
    const inputs = [];
    const inputRegex = /<input\b([^>]*)>/gi;
    let inputMatch;
    let hasPasswordField = false;
    let hasCsrfToken = false;
    let csrfTokenName = null;

    while ((inputMatch = inputRegex.exec(formContent)) !== null) {
      const fullInputTag = inputMatch[0];
      const attrs = inputMatch[1];
      const typeMatch = attrs.match(/type=["']([^"']*)["']/i);
      const nameMatch = attrs.match(/name=["']([^"']*)["']/i);
      const idMatch = attrs.match(/id=["']([^"']*)["']/i);
      const valueMatch = attrs.match(/value=["']([^"']*)["']/i);
      const placeholderMatch = attrs.match(/placeholder=["']([^"']*)["']/i);

      const type = typeMatch ? typeMatch[1].toLowerCase() : 'text';
      const name = nameMatch ? nameMatch[1] : (idMatch ? idMatch[1] : '');

      if (type === 'password') {
        hasPasswordField = true;
      }

      // Check if this input resembles a CSRF token
      if (name && CSRF_NAME_PATTERNS.some(p => p.test(name))) {
        hasCsrfToken = true;
        csrfTokenName = name;
      }

      inputs.push({
        name: name || `unnamed_input_${inputs.length + 1}`,
        type,
        hasValue: !!valueMatch,
        placeholder: placeholderMatch ? placeholderMatch[1] : '',
        id: idMatch ? idMatch[1] : '',
        formAction: absoluteAction,
        formMethod: method,
        pageUrl,
        htmlSnippet: fullInputTag
      });
    }

    // Parse textarea fields
    const textareaRegex = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>|<textarea\b([^>]*)>/gi;
    let textareaMatch;
    while ((textareaMatch = textareaRegex.exec(formContent)) !== null) {
      const fullTextareaTag = textareaMatch[0];
      const attrs = textareaMatch[1] || textareaMatch[3] || '';
      const nameMatch = attrs.match(/name=["']([^"']*)["']/i);
      const idMatch = attrs.match(/id=["']([^"']*)["']/i);
      const placeholderMatch = attrs.match(/placeholder=["']([^"']*)["']/i);
      const name = nameMatch ? nameMatch[1] : (idMatch ? idMatch[1] : '');
      if (name) {
        inputs.push({
          name,
          type: 'textarea',
          hasValue: false,
          placeholder: placeholderMatch ? placeholderMatch[1] : '',
          id: idMatch ? idMatch[1] : '',
          formAction: absoluteAction,
          formMethod: method,
          pageUrl,
          htmlSnippet: fullTextareaTag
        });
      }
    }

    // Parse select fields
    const selectRegex = /<select\b([^>]*)>[\s\S]*?<\/select>|<select\b([^>]*)>/gi;
    let selectMatch;
    while ((selectMatch = selectRegex.exec(formContent)) !== null) {
      const fullSelectTag = selectMatch[0];
      const attrs = selectMatch[1] || selectMatch[2] || '';
      const nameMatch = attrs.match(/name=["']([^"']*)["']/i);
      const idMatch = attrs.match(/id=["']([^"']*)["']/i);
      const name = nameMatch ? nameMatch[1] : (idMatch ? idMatch[1] : '');
      if (name) {
        inputs.push({
          name,
          type: 'select',
          hasValue: false,
          id: idMatch ? idMatch[1] : '',
          formAction: absoluteAction,
          formMethod: method,
          pageUrl,
          htmlSnippet: fullSelectTag
        });
      }
    }

    // Check textarea and button
    const hasSubmitButton = /<button[^>]*type=["']submit["']|<input[^>]*type=["']submit["']/i.test(formContent) || /<button/i.test(formContent);

    const formData = {
      id: `form_${formIndex}`,
      action: absoluteAction,
      rawAction,
      pageUrl,
      method,
      inputsCount: inputs.length,
      hasPasswordField,
      hasCsrfToken,
      csrfTokenName,
      hasSubmitButton,
      inputs: inputs.slice(0, 20)
    };

    forms.push(formData);

    // Security Checks

    // 1. Password submitted over unencrypted HTTP
    if (hasPasswordField && (!isHttps || absoluteAction.startsWith('http://'))) {
      findings.push({
        ruleId: 'FORM_PASSWORD_OVER_HTTP',
        title: 'Authentication Form Transmits Password In Cleartext (HTTP)',
        severity: 'High',
        confidence: 'High',
        category: 'Authentication Security',
        url: pageUrl,
        description: `A login or password form at "${pageUrl}" specifies action="${absoluteAction}" without HTTPS encryption.`,
        impact: 'User credentials will be transmitted across the network in plaintext, vulnerable to passive wiretapping and packet sniffing.',
        evidence: { formAction: absoluteAction, hasPassword: true, pageProtocol: isHttps ? 'HTTPS' : 'HTTP' },
        recommendation: 'Ensure both the hosting page and the form action URL enforce HTTPS.',
        cwe: 'CWE-319',
        owasp: 'A02:2021 - Cryptographic Failures',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html']
      });
    }

    // 2. State-changing POST form without detectable CSRF protection
    if (method === 'POST' && !hasCsrfToken) {
      findings.push({
        ruleId: 'FORM_POST_MISSING_CSRF_INDICATOR',
        title: 'POST Form Missing Anti-CSRF Token Indicator',
        severity: hasPasswordField ? 'Low' : 'Low',
        confidence: 'Medium',
        category: 'Form Security',
        url: pageUrl,
        description: `A POST form targeting "${absoluteAction}" does not include an observable anti-CSRF hidden token input.`,
        impact: 'If the application does not rely on custom anti-CSRF request headers or SameSite=Strict cookies, users may be susceptible to Cross-Site Request Forgery.',
        evidence: { formAction: absoluteAction, method: 'POST', inputsFound: inputs.map(i => i.name) },
        recommendation: 'Implement synchronizer token pattern (CSRF tokens) or verify Origin/Referer headers on state-changing requests.',
        cwe: 'CWE-352',
        owasp: 'A01:2021 - Broken Access Control',
        references: ['https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html']
      });
    }

    // 3. Form action to external domain
    try {
      const pageHost = new URL(pageUrl).hostname.toLowerCase();
      const actionHost = new URL(absoluteAction).hostname.toLowerCase();
      if (actionHost !== pageHost) {
        findings.push({
          ruleId: 'FORM_ACTION_EXTERNAL_DOMAIN',
          title: 'Form Submits Data to External Domain',
          severity: 'Low',
          confidence: 'High',
          category: 'Form Security',
          url: pageUrl,
          description: `Form on "${pageHost}" sends user inputs to third-party host "${actionHost}".`,
          impact: 'Potential data leakage if the third-party domain is compromised or untrusted.',
          evidence: { pageUrl, actionUrl: absoluteAction },
          recommendation: 'Verify that the external form destination is intended and properly secured.',
          cwe: 'CWE-200',
          owasp: 'A05:2021 - Security Misconfiguration',
          references: ['https://cwe.mitre.org/data/definitions/200.html']
        });
      }
    } catch {}
  }

  // Compile all input fields from forms
  const allInputFields = [];
  for (const f of forms) {
    for (const inp of f.inputs || []) {
      allInputFields.push({
        ...inp,
        source: 'Form Input Field',
        formId: f.id,
        formAction: f.action,
        formMethod: f.method,
        pageUrl
      });
    }
  }

  // Extract Standalone Input Fields (outside of <form> elements)
  const htmlWithoutForms = html.replace(/<form\b[\s\S]*?<\/form>/gi, '');
  const standaloneInputRegex = /<input\b([^>]*)>/gi;
  let saMatch;
  while ((saMatch = standaloneInputRegex.exec(htmlWithoutForms)) !== null) {
    const fullTag = saMatch[0];
    const attrs = saMatch[1];
    const typeMatch = attrs.match(/type=["']([^"']*)["']/i);
    const nameMatch = attrs.match(/name=["']([^"']*)["']/i);
    const idMatch = attrs.match(/id=["']([^"']*)["']/i);
    const placeholderMatch = attrs.match(/placeholder=["']([^"']*)["']/i);

    const type = typeMatch ? typeMatch[1].toLowerCase() : 'text';
    const name = nameMatch ? nameMatch[1] : (idMatch ? idMatch[1] : '');

    // Skip buttons and submit inputs
    if (type === 'submit' || type === 'button' || type === 'image') continue;
    if (!name) continue;

    allInputFields.push({
      name,
      type,
      placeholder: placeholderMatch ? placeholderMatch[1] : '',
      id: idMatch ? idMatch[1] : '',
      formAction: pageUrl,
      formMethod: 'GET',
      pageUrl,
      htmlSnippet: fullTag,
      source: 'Standalone Input Field',
      isStandalone: true
    });
  }

  // Standalone textareas
  const standaloneTextareaRegex = /<textarea\b([^>]*)>([\s\S]*?)<\/textarea>|<textarea\b([^>]*)>/gi;
  while ((saMatch = standaloneTextareaRegex.exec(htmlWithoutForms)) !== null) {
    const fullTag = saMatch[0];
    const attrs = saMatch[1] || saMatch[3] || '';
    const nameMatch = attrs.match(/name=["']([^"']*)["']/i);
    const idMatch = attrs.match(/id=["']([^"']*)["']/i);
    const placeholderMatch = attrs.match(/placeholder=["']([^"']*)["']/i);
    const name = nameMatch ? nameMatch[1] : (idMatch ? idMatch[1] : '');
    if (name) {
      allInputFields.push({
        name,
        type: 'textarea',
        placeholder: placeholderMatch ? placeholderMatch[1] : '',
        id: idMatch ? idMatch[1] : '',
        formAction: pageUrl,
        formMethod: 'GET',
        pageUrl,
        htmlSnippet: fullTag,
        source: 'Standalone Input Field',
        isStandalone: true
      });
    }
  }

  return { forms, findings, inputFields: allInputFields };
}
