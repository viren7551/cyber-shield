import express from 'express';
import multer from 'multer';
import {
  encodeImage,
  decodeImage,
  analyzeImageHandler,
  getLogs,
  clearLogs
} from './stego.controller.js';

const router = express.Router();

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only valid image files (PNG, JPEG, WebP, BMP) are allowed.'));
    }
  }
});

router.post('/encode', upload.single('carrierImage'), encodeImage);
router.post('/decode', upload.single('stegoImage'), decodeImage);
router.post('/analyze', upload.single('image'), analyzeImageHandler);
router.get('/logs', getLogs);
router.delete('/logs', clearLogs);

export default router;
