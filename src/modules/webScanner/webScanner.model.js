import mongoose from 'mongoose';
import { getDBStatus } from '../../config/db.js';

/**
 * CyberShield Web Security Scanner - Database Model & Storage Service
 * Provides MongoDB persistence with automatic fallback to an in-memory resilient repository
 * when MongoDB is unreachable.
 */

// 1. Security Scan Schema
const securityScanSchema = new mongoose.Schema({
  scanId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  userId: {
    type: String,
    default: 'security-analyst',
    index: true
  },
  target: {
    type: String,
    required: true,
    index: true
  },
  scope: {
    type: String,
    default: 'same-origin'
  },
  profile: {
    type: String,
    enum: ['quick', 'standard', 'deep'],
    default: 'standard'
  },
  status: {
    type: String,
    enum: ['pending', 'running', 'completed', 'cancelled', 'failed'],
    default: 'pending',
    index: true
  },
  startedAt: {
    type: Date,
    default: Date.now,
    index: true
  },
  completedAt: {
    type: Date
  },
  duration: {
    type: Number,
    default: 0
  },
  riskScore: {
    type: Number,
    default: 0
  },
  statistics: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  configuration: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  targetInfo: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  error: {
    type: String
  }
}, { timestamps: true });

// 2. Finding Schema
const securityFindingSchema = new mongoose.Schema({
  findingId: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  scanId: {
    type: String,
    required: true,
    index: true
  },
  title: {
    type: String,
    required: true
  },
  category: {
    type: String,
    default: 'Web Security'
  },
  severity: {
    type: String,
    enum: ['Critical', 'High', 'Medium', 'Low', 'Informational'],
    default: 'Medium',
    index: true
  },
  confidence: {
    type: String,
    enum: ['High', 'Medium', 'Low'],
    default: 'High'
  },
  description: {
    type: String,
    default: ''
  },
  impact: {
    type: String,
    default: ''
  },
  url: {
    type: String,
    default: ''
  },
  affectedUrls: {
    type: [String],
    default: []
  },
  evidence: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  },
  recommendation: {
    type: String,
    default: ''
  },
  cwe: {
    type: String,
    default: 'CWE-16'
  },
  owasp: {
    type: String,
    default: 'A05:2021 - Security Misconfiguration'
  },
  references: {
    type: [String],
    default: []
  },
  status: {
    type: String,
    enum: ['open', 'confirmed', 'false_positive', 'accepted_risk', 'resolved'],
    default: 'open',
    index: true
  }
}, { timestamps: true });

// 3. Endpoint Schema
const securityEndpointSchema = new mongoose.Schema({
  scanId: {
    type: String,
    required: true,
    index: true
  },
  url: {
    type: String,
    required: true
  },
  method: {
    type: String,
    default: 'GET'
  },
  statusCode: {
    type: Number,
    default: 200
  },
  contentType: {
    type: String,
    default: ''
  },
  depth: {
    type: Number,
    default: 0
  },
  formsCount: {
    type: Number,
    default: 0
  },
  responseTimeMs: {
    type: Number,
    default: 0
  },
  type: {
    type: String,
    default: 'Page'
  }
}, { timestamps: true });

// Compile models
const MongoScan = mongoose.models.SecurityScan || mongoose.model('SecurityScan', securityScanSchema);
const MongoFinding = mongoose.models.SecurityFinding || mongoose.model('SecurityFinding', securityFindingSchema);
const MongoEndpoint = mongoose.models.SecurityEndpoint || mongoose.model('SecurityEndpoint', securityEndpointSchema);

// In-Memory Fallback Repositories
const fallbackScans = new Map();
const fallbackFindings = new Map(); // scanId -> Array of findings
const fallbackEndpoints = new Map(); // scanId -> Array of endpoints

export const SecurityScanService = {
  /**
   * Create and persist a new scan record
   */
  async createScan(data) {
    const scanId = data.scanId || 'scan_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7);
    const record = {
      ...data,
      scanId,
      id: scanId,
      startedAt: data.startedAt || new Date(),
      status: data.status || 'pending',
      findings: data.findings || [],
      endpoints: data.endpoints || []
    };

    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoScan.create(record);
      } catch (err) {
        console.warn('[WebScanner Mongo] Create failed, using in-memory store:', err.message);
      }
    }

    fallbackScans.set(scanId, record);
    if (data.findings && data.findings.length > 0) {
      this.saveFindings(scanId, data.findings);
    }
    if (data.endpoints && data.endpoints.length > 0) {
      this.saveEndpoints(scanId, data.endpoints);
    }

    return record;
  },

  /**
   * Update scan status and summary results
   */
  async updateScan(scanId, updateData) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoScan.findOneAndUpdate({ scanId }, { $set: updateData });
      } catch (err) {
        console.warn('[WebScanner Mongo] Update failed:', err.message);
      }
    }

    const current = fallbackScans.get(scanId) || {};
    const updated = { ...current, ...updateData, scanId, id: scanId };
    fallbackScans.set(scanId, updated);

    if (updateData.findings && updateData.findings.length > 0) {
      await this.saveFindings(scanId, updateData.findings);
    }
    if (updateData.endpoints && updateData.endpoints.length > 0) {
      await this.saveEndpoints(scanId, updateData.endpoints);
    }

    return updated;
  },

  /**
   * Get scan by ID
   */
  async getScanById(scanId) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        const found = await MongoScan.findOne({ scanId }).lean();
        if (found) {
          found.id = found.scanId;
          return found;
        }
      } catch (err) {
        console.warn('[WebScanner Mongo] Query failed, falling back:', err.message);
      }
    }

    return fallbackScans.get(scanId) || null;
  },

  /**
   * List recent scans
   */
  async listScans(options = {}) {
    const { limit = 50, search = '' } = options;

    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        const query = {};
        if (search) {
          query.$or = [
            { target: { $regex: search, $options: 'i' } },
            { profile: { $regex: search, $options: 'i' } }
          ];
        }
        const scans = await MongoScan.find(query).sort({ startedAt: -1 }).limit(limit).lean();
        return scans.map(s => ({ ...s, id: s.scanId }));
      } catch (err) {
        console.warn('[WebScanner Mongo] List failed, using fallback:', err.message);
      }
    }

    let all = Array.from(fallbackScans.values());
    if (search) {
      const lower = search.toLowerCase();
      all = all.filter(s => s.target?.toLowerCase().includes(lower) || s.profile?.toLowerCase().includes(lower));
    }
    all.sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
    return all.slice(0, limit);
  },

  /**
   * Delete scan and related records
   */
  async deleteScan(scanId) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoScan.deleteOne({ scanId });
        await MongoFinding.deleteMany({ scanId });
        await MongoEndpoint.deleteMany({ scanId });
      } catch (err) {
        console.warn('[WebScanner Mongo] Delete failed:', err.message);
      }
    }

    fallbackScans.delete(scanId);
    fallbackFindings.delete(scanId);
    fallbackEndpoints.delete(scanId);
    return { success: true };
  },

  /**
   * Save findings
   */
  async saveFindings(scanId, findings = []) {
    const formatted = findings.map(f => ({
      findingId: f.id || f.findingId || 'find_' + Math.random().toString(36).substring(2, 9),
      id: f.id || f.findingId || 'find_' + Math.random().toString(36).substring(2, 9),
      scanId,
      title: f.title,
      category: f.category || 'Web Security',
      severity: f.severity || 'Medium',
      confidence: f.confidence || 'High',
      description: f.description || '',
      impact: f.impact || '',
      url: f.url || '',
      affectedUrls: f.affectedUrls || [f.url || ''],
      evidence: f.evidence || {},
      recommendation: f.recommendation || '',
      cwe: f.cwe || 'CWE-16',
      owasp: f.owasp || 'A05:2021 - Security Misconfiguration',
      references: f.references || [],
      status: f.status || 'open',
      createdAt: f.createdAt || new Date()
    }));

    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoFinding.deleteMany({ scanId });
        if (formatted.length > 0) {
          await MongoFinding.insertMany(formatted);
        }
      } catch (err) {
        console.warn('[WebScanner Mongo] Save findings failed:', err.message);
      }
    }

    fallbackFindings.set(scanId, formatted);
    return formatted;
  },

  /**
   * Get findings for a scan
   */
  async getFindingsByScanId(scanId) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        const list = await MongoFinding.find({ scanId }).lean();
        if (list && list.length > 0) {
          return list.map(f => ({ ...f, id: f.findingId }));
        }
      } catch (err) {
        console.warn('[WebScanner Mongo] Get findings failed:', err.message);
      }
    }

    return fallbackFindings.get(scanId) || [];
  },

  /**
   * Update finding status (open, confirmed, false_positive, accepted_risk, resolved)
   */
  async updateFindingStatus(scanId, findingId, status) {
    const validStatuses = ['open', 'confirmed', 'false_positive', 'accepted_risk', 'resolved'];
    if (!validStatuses.includes(status)) {
      throw new Error(`Invalid finding status "${status}". Allowed: ${validStatuses.join(', ')}`);
    }

    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoFinding.updateOne(
          { $or: [{ findingId }, { _id: findingId }], scanId },
          { $set: { status } }
        );
      } catch (err) {
        console.warn('[WebScanner Mongo] Update finding status failed:', err.message);
      }
    }

    const list = fallbackFindings.get(scanId) || [];
    const item = list.find(f => f.findingId === findingId || f.id === findingId);
    if (item) {
      item.status = status;
    }

    return { success: true, findingId, status };
  },

  /**
   * Save endpoints
   */
  async saveEndpoints(scanId, endpoints = []) {
    const formatted = endpoints.map(e => ({
      scanId,
      url: e.url,
      method: e.method || 'GET',
      statusCode: e.statusCode || 200,
      contentType: e.contentType || '',
      depth: e.depth || 0,
      formsCount: e.formsCount || 0,
      responseTimeMs: e.responseTimeMs || 0,
      type: e.type || 'Page'
    }));

    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoEndpoint.deleteMany({ scanId });
        if (formatted.length > 0) {
          await MongoEndpoint.insertMany(formatted);
        }
      } catch (err) {
        console.warn('[WebScanner Mongo] Save endpoints failed:', err.message);
      }
    }

    fallbackEndpoints.set(scanId, formatted);
    return formatted;
  },

  /**
   * Get endpoints for a scan
   */
  async getEndpointsByScanId(scanId) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        const list = await MongoEndpoint.find({ scanId }).lean();
        if (list && list.length > 0) return list;
      } catch (err) {
        console.warn('[WebScanner Mongo] Get endpoints failed:', err.message);
      }
    }

    return fallbackEndpoints.get(scanId) || [];
  }
};
