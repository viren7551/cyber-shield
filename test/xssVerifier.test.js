import { describe, it, before, after } from 'node:test';
import assert from 'node:assert';
import { createMockLabServer } from '../src/modules/webScanner/testLab/mockVulnerableServer.js';
import { verifyCustomPayloads, getSamplePayloads } from '../src/modules/xssVerifier/xssVerifier.service.js';

describe('XSS Injection Verifier - Dedicated Verification Suite', () => {
  let mockServer;
  const testPort = 9899; // Separate port for verifier test suite
  const testTarget = `http://127.0.0.1:${testPort}`;

  before(async () => {
    mockServer = createMockLabServer();
    await new Promise((resolve) => mockServer.listen(testPort, '127.0.0.1', resolve));
  });

  after(async () => {
    if (mockServer) {
      await new Promise((resolve) => mockServer.close(resolve));
    }
  });

  it('should return predefined safe sample payload presets', () => {
    const samples = getSamplePayloads();
    assert.ok(Array.isArray(samples));
    assert.ok(samples.length >= 3);
    assert.ok(samples.some(s => s.category.includes('Diagnostic Canaries')));
    assert.ok(samples.some(s => s.category.includes('HTML Text Context')));
  });

  it('should fail with descriptive error if targetUrl or payloads are missing', async () => {
    await assert.rejects(
      async () => verifyCustomPayloads({ targetUrl: '', payloads: ['<test>'] }),
      /Target URL is required/i
    );

    await assert.rejects(
      async () => verifyCustomPayloads({ targetUrl: `${testTarget}/search`, payloads: [] }),
      /At least one payload must be provided/i
    );
  });

  it('should detect VULNERABLE status on unencoded reflection endpoint', async () => {
    const payloads = [
      '<csxss_tag>alert(1)</csxss_tag>',
      '"><img src=x onerror=alert(1)>'
    ];

    const result = await verifyCustomPayloads({
      targetUrl: `${testTarget}/search?q=test`,
      parameterName: 'q',
      httpMethod: 'GET',
      payloads,
      options: { rateLimitMs: 0, timeoutMs: 3000 }
    });

    assert.strictEqual(result.summary.testedCount, 2);
    assert.strictEqual(result.summary.vulnerableCount, 2);
    assert.strictEqual(result.summary.vulnerabilityRate, 100);
    assert.strictEqual(result.results[0].status, 'VULNERABLE');
    assert.strictEqual(result.results[0].reflected, true);
    assert.strictEqual(result.results[0].encoding, 'RAW_UNENCODED');
    assert.ok(result.results[0].evidence.snippet.includes('alert(1)'));
    assert.ok(result.results[0].evidence.line >= 1);
  });

  it('should detect SAFE_ENCODED status when server neutralizes delimiters with HTML entities', async () => {
    const payloads = [
      '<b>safe_bold</b>',
      '<script>alert(1)</script>'
    ];

    const result = await verifyCustomPayloads({
      targetUrl: `${testTarget}/safe-search?q=test`,
      parameterName: 'q',
      httpMethod: 'GET',
      payloads,
      options: { rateLimitMs: 0, timeoutMs: 3000 }
    });

    assert.strictEqual(result.summary.testedCount, 2);
    assert.strictEqual(result.summary.safeEncodedCount, 2);
    assert.strictEqual(result.summary.vulnerableCount, 0);
    assert.strictEqual(result.results[0].status, 'SAFE_ENCODED');
    assert.strictEqual(result.results[0].reflected, true);
    assert.strictEqual(result.results[0].encoding, 'HTML_ENTITIES');
  });

  it('should detect NOT_REFLECTED status when parameter is completely ignored by server', async () => {
    const payloads = [
      'canary_payload_12345'
    ];

    const result = await verifyCustomPayloads({
      targetUrl: `${testTarget}/no-reflection?q=test`,
      parameterName: 'q',
      httpMethod: 'GET',
      payloads,
      options: { rateLimitMs: 0, timeoutMs: 3000 }
    });

    assert.strictEqual(result.summary.testedCount, 1);
    assert.strictEqual(result.summary.notReflectedCount, 1);
    assert.strictEqual(result.results[0].status, 'NOT_REFLECTED');
    assert.strictEqual(result.results[0].reflected, false);
  });

  it('should auto-infer parameter from URL query string if not explicitly given', async () => {
    const result = await verifyCustomPayloads({
      targetUrl: `${testTarget}/search?customParam=test`,
      payloads: ['test_probe'],
      options: { rateLimitMs: 0, timeoutMs: 3000 }
    });

    assert.strictEqual(result.parameterName, 'customParam');
  });

  it('should verify more than 200 payloads without truncation when large wordlist is supplied', async () => {
    const largeList = Array.from({ length: 220 }, (_, i) => `probe_${i}`);
    const result = await verifyCustomPayloads({
      targetUrl: `${testTarget}/search?q=test`,
      parameterName: 'q',
      payloads: largeList,
      options: { rateLimitMs: 0, timeoutMs: 3000 }
    });

    assert.strictEqual(result.summary.testedCount, 220);
    assert.strictEqual(result.summary.totalPayloads, 220);
  });
});
