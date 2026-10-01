import express from 'express';
import {
  domainIntelHandler,
  subdomainsHandler,
  whoisHandler,
  ipIntelHandler,
  dnsMapHandler,
  usernameSearchHandler,
  emailIntelHandler,
  techDetectionHandler,
  dorkBuilderHandler,
  newsMonitorHandler
} from './osint.controller.js';

const router = express.Router();

router.get('/domain', domainIntelHandler);
router.get('/subdomains', subdomainsHandler);
router.get('/whois', whoisHandler);
router.get('/ip', ipIntelHandler);
router.get('/dns-map', dnsMapHandler);
router.get('/username', usernameSearchHandler);
router.get('/email', emailIntelHandler);
router.get('/tech', techDetectionHandler);
router.get('/dorks', dorkBuilderHandler);
router.get('/news', newsMonitorHandler);

export default router;
