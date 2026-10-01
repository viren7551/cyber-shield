import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB, getDBStatus } from './src/config/db.js';
import apiModules from './src/modules/index.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5001;

// Global process error handlers to prevent silent stops
process.on('uncaughtException', (err) => {
  console.error('[CyberShield Uncaught Exception]:', err.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('[CyberShield Unhandled Rejection]:', reason);
});

// Middleware
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '60mb' }));
app.use(express.urlencoded({ extended: true, limit: '60mb' }));

// Mount Modular API Registry
app.use('/api', apiModules);

// Health check endpoint
app.get('/api/health', (req, res) => {
  const dbStatus = getDBStatus();
  res.status(200).json({
    status: 'ONLINE',
    project: 'CyberShield',
    port: PORT,
    activeModules: ['steganography', 'password-audit', 'metadata-sanitizer', 'osint', 'network-scanner', 'log-analyzer', 'url-analyzer'],
    database: dbStatus,
    timestamp: new Date()
  });
});

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('[Server Error]:', err.message);
  res.status(err.status || 500).json({
    success: false,
    error: err.message || 'Internal Server Error'
  });
});

import { execSync } from 'child_process';

/**
 * Automatically detects and terminates any stale or zombie process holding the port.
 */
function freePort(port) {
  try {
    if (process.platform === 'win32') {
      const output = execSync(`cmd /c "netstat -ano | findstr :${port}"`, {
        encoding: 'utf8',
        stdio: ['pipe', 'pipe', 'ignore']
      });
      const lines = output.split('\n');
      for (const line of lines) {
        if (line.includes('LISTENING')) {
          const parts = line.trim().split(/\s+/);
          const pid = parts[parts.length - 1];
          if (pid && pid !== '0' && pid !== String(process.pid)) {
            console.log(`[CyberShield Auto-Recovery] Freeing port ${port} by terminating old process (PID: ${pid})...`);
            execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' });
          }
        }
      }
    } else {
      execSync(`lsof -ti :${port} | xargs kill -9`, { stdio: 'ignore' });
    }
  } catch {
    // Port wasn't occupied or already released
  }
}

// Resilient server launcher with automatic port conflict recovery
function startServer(port, retries = 2) {
  const server = app.listen(port, () => {
    console.log(`[CyberShield API] Server running on http://localhost:${port}`);
    connectDB();
  });

  server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
      if (retries > 0) {
        console.warn(`[CyberShield Auto-Recovery] Port ${port} is in use. Auto-clearing stale process...`);
        freePort(port);
        setTimeout(() => {
          console.log(`[CyberShield Auto-Recovery] Retrying server startup on http://localhost:${port}...`);
          startServer(port, retries - 1);
        }, 1200);
      } else {
        console.error(`\n[CyberShield Error] Port ${port} is still in use after auto-recovery.`);
        console.error(`Please stop conflicting processes or choose another port in .env.\n`);
        process.exit(1);
      }
    } else {
      console.error('[CyberShield Server Error]:', err);
      process.exit(1);
    }
  });

  return server;
}

startServer(PORT);

export default app;

