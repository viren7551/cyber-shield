import mongoose from 'mongoose';

let isConnected = false;
let connectionAttempt = 0;
let lastError = null;

export const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/cybershield';
  connectionAttempt++;

  try {
    const conn = await mongoose.connect(mongoUri, {
      serverSelectionTimeoutMS: 5000,
      connectTimeoutMS: 5000,
    });
    isConnected = true;
    lastError = null;
    console.log(`[CyberShield DB] MongoDB Connected to cluster: ${conn.connection.host}, Database: ${conn.connection.name}`);
  } catch (error) {
    isConnected = false;
    lastError = error.message;
    console.warn(`[CyberShield DB] MongoDB Atlas attempt #${connectionAttempt} failed (${error.message}). Using In-Memory Resilient Store.`);
  }
};

// Retry connection in background if offline (every 10s)
const retryInterval = setInterval(() => {
  if (!isConnected) {
    connectDB();
  }
}, 10000);
if (retryInterval.unref) retryInterval.unref();

export const getDBStatus = () => ({
  connected: isConnected,
  database: isConnected ? mongoose.connection.name : 'In-Memory Resilient Cache',
  host: isConnected ? mongoose.connection.host : (process.env.MONGODB_URI ? 'MongoDB Atlas (Connecting/Retrying...)' : 'Local Sandbox'),
  error: lastError
});
