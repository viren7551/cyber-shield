import mongoose from 'mongoose';
import { getDBStatus } from '../../config/db.js';

const passwordAuditLogSchema = new mongoose.Schema({
  auditType: {
    type: String,
    enum: ['SINGLE', 'BATCH', 'GENERATE'],
    default: 'SINGLE'
  },
  score: {
    type: Number,
    required: true
  },
  grade: {
    type: String,
    required: true
  },
  strength: {
    type: String,
    required: true
  },
  entropyBits: {
    type: Number,
    default: 0
  },
  crackTimeFastGpu: {
    type: String,
    default: 'Instant'
  },
  isBreached: {
    type: Boolean,
    default: false
  },
  breachCount: {
    type: Number,
    default: 0
  },
  length: {
    type: Number,
    default: 0
  },
  summary: {
    type: String,
    default: ''
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const MongoPasswordAuditLog = mongoose.models.PasswordAuditLog || mongoose.model('PasswordAuditLog', passwordAuditLogSchema);

const fallbackAuditLogs = [];

export const PasswordAuditLogService = {
  async createLog(data) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        return await MongoPasswordAuditLog.create(data);
      } catch (err) {
        console.warn('[PasswordAuditLog] Mongo write failed, saving to fallback:', err.message);
      }
    }
    const logEntry = {
      _id: 'pa_local_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
      ...data,
      timestamp: new Date()
    };
    fallbackAuditLogs.unshift(logEntry);
    if (fallbackAuditLogs.length > 100) fallbackAuditLogs.pop();
    return logEntry;
  },

  async getRecentLogs(limit = 30) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        return await MongoPasswordAuditLog.find().sort({ timestamp: -1 }).limit(limit).lean();
      } catch (err) {
        console.warn('[PasswordAuditLog] Mongo read failed, falling back:', err.message);
      }
    }
    return fallbackAuditLogs.slice(0, limit);
  },

  async clearLogs() {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoPasswordAuditLog.deleteMany({});
      } catch (err) {
        console.warn('[PasswordAuditLog] Mongo delete failed:', err.message);
      }
    }
    fallbackAuditLogs.length = 0;
    return { success: true };
  }
};
