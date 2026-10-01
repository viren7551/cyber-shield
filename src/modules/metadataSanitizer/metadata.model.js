import mongoose from 'mongoose';
import { getDBStatus } from '../../config/db.js';

const metadataLogSchema = new mongoose.Schema({
  action: {
    type: String,
    enum: ['INSPECT', 'SANITIZE'],
    required: true
  },
  fileName: {
    type: String,
    default: 'image.jpg'
  },
  fileSize: {
    type: Number,
    default: 0
  },
  format: {
    type: String,
    default: 'JPEG'
  },
  tagsFound: {
    type: Number,
    default: 0
  },
  hasGps: {
    type: Boolean,
    default: false
  },
  bytesSaved: {
    type: Number,
    default: 0
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

const MongoMetadataLog = mongoose.models.MetadataLog || mongoose.model('MetadataLog', metadataLogSchema);

const fallbackLogs = [];

export const MetadataLogService = {
  async createLog(data) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        return await MongoMetadataLog.create(data);
      } catch (err) {
        console.warn('[MetadataLog] Mongo write failed, using fallback:', err.message);
      }
    }
    const logEntry = {
      _id: 'meta_' + Date.now() + '_' + Math.random().toString(36).substring(2, 7),
      ...data,
      timestamp: new Date()
    };
    fallbackLogs.unshift(logEntry);
    if (fallbackLogs.length > 100) fallbackLogs.pop();
    return logEntry;
  },

  async getRecentLogs(limit = 30) {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        return await MongoMetadataLog.find().sort({ timestamp: -1 }).limit(limit).lean();
      } catch (err) {
        console.warn('[MetadataLog] Mongo read failed, using fallback:', err.message);
      }
    }
    return fallbackLogs.slice(0, limit);
  },

  async clearLogs() {
    const dbStatus = getDBStatus();
    if (dbStatus.connected) {
      try {
        await MongoMetadataLog.deleteMany({});
      } catch (err) {
        console.warn('[MetadataLog] Mongo delete failed:', err.message);
      }
    }
    fallbackLogs.length = 0;
    return { success: true };
  }
};
