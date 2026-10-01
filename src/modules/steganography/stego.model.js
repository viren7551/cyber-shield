import mongoose from 'mongoose';
import { getDBStatus } from '../../config/db.js';

const stegoLogSchema = new mongoose.Schema({
  action: {
    type: String,
    enum: ['ENCODE', 'DECODE', 'ANALYZE'],
    required: true
  },
  fileName: {
    type: String,
    default: 'unknown_image.png'
  },
  fileSize: {
    type: Number,
    default: 0
  },
  payloadSize: {
    type: Number,
    default: 0
  },
  imageDimensions: {
    width: Number,
    height: Number
  },
  isEncrypted: {
    type: Boolean,
    default: false
  },
  status: {
    type: String,
    enum: ['SUCCESS', 'FAILED'],
    default: 'SUCCESS'
  },
  details: {
    type: String,
    default: ''
  },
  timestamp: {
    type: Date,
    default: Date.now
  }
});

const MongoStegoLog = mongoose.models.StegoLog || mongoose.model('StegoLog', stegoLogSchema);

const fallbackLogs = [];

export const StegoLogService = {
  async createLog(data) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        return await MongoStegoLog.create(data);
      } catch (err) {
        console.warn('[StegoLog] Mongo write failed, saving to fallback:', err.message);
      }
    }
    const logEntry = {
      _id: 'local_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
      ...data,
      timestamp: new Date()
    };
    fallbackLogs.unshift(logEntry);
    if (fallbackLogs.length > 100) fallbackLogs.pop();
    return logEntry;
  },

  async getRecentLogs(limit = 25) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        return await MongoStegoLog.find().sort({ timestamp: -1 }).limit(limit).lean();
      } catch (err) {
        console.warn('[StegoLog] Mongo read failed, falling back:', err.message);
      }
    }
    return fallbackLogs.slice(0, limit);
  },

  async clearLogs() {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoStegoLog.deleteMany({});
      } catch (err) {
        console.warn('[StegoLog] Mongo delete failed:', err.message);
      }
    }
    fallbackLogs.length = 0;
    return { success: true };
  }
};
