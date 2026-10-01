import express from 'express';
import multer from 'multer';
import {
  extractMetadataHandler,
  sanitizeImageHandler,
  sampleImageHandler,
  getMetadataLogs,
  clearMetadataLogs
} from './metadata.controller.js';

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 40 * 1024 * 1024 }, // 40MB
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Please upload an image file (JPEG, PNG, WebP, TIFF).'));
    }
  }
});

router.get('/sample', sampleImageHandler);
router.post('/extract', upload.single('image'), extractMetadataHandler);
router.post('/sanitize', upload.single('image'), sanitizeImageHandler);
router.get('/logs', getMetadataLogs);
router.delete('/logs', clearMetadataLogs);

export default router;
