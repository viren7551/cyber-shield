import {
  executePortScan,
  deepSocketProbe,
  sweepSubnetRange,
  PORT_DATABASE,
  PRESET_PROFILES
} from './scanner.engine.js';

/**
 * Controller: Execute Port Scan
 * Handles TCP connect scan against target host or IP with specified profile/ports
 */
export async function executeScanHandler(req, res) {
  try {
    const target = req.body?.target || req.query?.target;
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target host or IP address is required (e.g. 127.0.0.1, localhost, or domain).'
      });
    }

    const preset = req.body?.preset || req.query?.preset || 'top20';
    const customPorts = req.body?.customPorts || req.query?.customPorts || '';
    const timeoutMs = parseInt(req.body?.timeoutMs || req.query?.timeoutMs || '750', 10);
    const concurrency = parseInt(req.body?.concurrency || req.query?.concurrency || '30', 10);
    const grabBanner = req.body?.grabBanner !== false && req.query?.grabBanner !== 'false';

    const scanResult = await executePortScan(target, {
      preset,
      customPorts,
      timeoutMs,
      concurrency,
      grabBanner
    });

    return res.status(200).json({
      success: true,
      scan: scanResult
    });
  } catch (err) {
    console.error('[NetworkScanner Execute Error]:', err.message);
    return res.status(500).json({
      success: false,
      error: err.message || 'An error occurred while executing network scan.'
    });
  }
}

/**
 * Controller: Deep Socket Probe
 * Connects directly to a specific IP and port, writes payload and inspects raw response / hex dump
 */
export async function deepProbeHandler(req, res) {
  try {
    const { host, port, payload, timeoutMs } = req.body;
    if (!host || !port) {
      return res.status(400).json({
        success: false,
        error: 'Both host and port are required for single socket probe.'
      });
    }

    const probeResult = await deepSocketProbe(host, port, payload || '', parseInt(timeoutMs, 10) || 2000);

    return res.status(200).json({
      success: true,
      probe: probeResult
    });
  } catch (err) {
    console.error('[NetworkScanner Deep Probe Error]:', err.message);
    return res.status(500).json({
      success: false,
      error: err.message || 'Failed to complete socket probe.'
    });
  }
}

/**
 * Controller: Subnet Range Sweep
 * Discovers live hosts within an IPv4 /24 subnet range
 */
export async function subnetSweepHandler(req, res) {
  try {
    const subnet = req.body?.subnet || req.query?.subnet || '127.0.0';
    const limit = parseInt(req.body?.limit || req.query?.limit || '20', 10);

    const sweepResult = await sweepSubnetRange(subnet, limit);

    return res.status(200).json({
      success: true,
      sweep: sweepResult
    });
  } catch (err) {
    console.error('[NetworkScanner Subnet Sweep Error]:', err.message);
    return res.status(500).json({
      success: false,
      error: err.message || 'Subnet sweep failed.'
    });
  }
}

/**
 * Controller: Get Port Database & Presets
 * Returns the dictionary of well-known ports and security profiles
 */
export async function getKnowledgeDatabaseHandler(req, res) {
  try {
    const portList = Object.entries(PORT_DATABASE).map(([port, data]) => ({
      port: parseInt(port, 10),
      ...data
    })).sort((a, b) => a.port - b.port);

    return res.status(200).json({
      success: true,
      ports: portList,
      presets: PRESET_PROFILES
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message || 'Failed to fetch port database.'
    });
  }
}
