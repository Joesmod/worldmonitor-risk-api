const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

// --- API Key Store (file-based for MVP) ---
const KEYS_FILE = path.join(__dirname, 'data', 'api-keys.json');

function loadKeys() {
  try { return JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8')); }
  catch { return {}; }
}

function saveKeys(keys) {
  fs.mkdirSync(path.dirname(KEYS_FILE), { recursive: true });
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2));
}

// Tiers: free=10/day, starter=1000/day, pro=10000/day, enterprise=unlimited
const TIER_LIMITS = { free: 10, starter: 1000, pro: 10000, enterprise: 999999 };

// --- Auth Middleware ---
function authenticate(req, res, next) {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'Missing X-API-Key header' });
  
  const keys = loadKeys();
  const keyData = keys[apiKey];
  if (!keyData) return res.status(403).json({ error: 'Invalid API key' });
  
  req.keyData = keyData;
  req.apiKey = apiKey;
  next();
}

// --- Per-key Rate Limiting ---
const keyUsage = {}; // { apiKey: { date: 'YYYY-MM-DD', count: N } }

function rateLimitByKey(req, res, next) {
  const key = req.apiKey;
  const tier = req.keyData.tier || 'free';
  const limit = TIER_LIMITS[tier] || 10;
  const today = new Date().toISOString().slice(0, 10);
  
  if (!keyUsage[key] || keyUsage[key].date !== today) {
    keyUsage[key] = { date: today, count: 0 };
  }
  
  keyUsage[key].count++;
  
  res.set('X-RateLimit-Limit', String(limit));
  res.set('X-RateLimit-Remaining', String(Math.max(0, limit - keyUsage[key].count)));
  
  if (keyUsage[key].count > limit) {
    return res.status(429).json({ error: 'Rate limit exceeded', limit, tier });
  }
  next();
}

// --- World Monitor Data Fetcher ---
const WORLDMONITOR_BASE = 'https://worldmonitor.app';
const fetch = (...args) => import('node-fetch').then(m => m.default(...args));

let riskCache = { data: null, ts: 0 };
let postureCache = { data: null, ts: 0 };
const CACHE_TTL = 5 * 60 * 1000; // 5 min

async function fetchRiskScores() {
  if (riskCache.data && Date.now() - riskCache.ts < CACHE_TTL) return riskCache.data;
  
  try {
    // Hit World Monitor's real endpoints (Vercel Edge Functions)
    const urls = [
      `${WORLDMONITOR_BASE}/api/risk-scores`,
      `${WORLDMONITOR_BASE}/api/theater-posture`,
    ];
    
    for (const url of urls) {
      try {
        const resp = await fetch(url, { timeout: 10000 });
        if (resp.ok) {
          const data = await resp.json();
          riskCache = { data, ts: Date.now() };
          return data;
        }
      } catch {}
    }
    
    // Fallback: serve from local seed data
    const seed = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'risk-scores-seed.json'), 'utf8'));
    return seed;
  } catch (e) {
    console.error('Failed to fetch risk scores:', e.message);
    const seed = JSON.parse(fs.readFileSync(path.join(__dirname, 'data', 'risk-scores-seed.json'), 'utf8'));
    return seed;
  }
}

// --- Routes ---

// Health
app.get('/health', (req, res) => res.json({ status: 'ok', version: '1.0.0' }));

// Generate API key (public for MVP — would be behind signup in prod)
app.post('/v1/keys', (req, res) => {
  const { email, tier = 'free' } = req.body;
  if (!email) return res.status(400).json({ error: 'Email required' });
  
  const key = `grisk_${uuidv4().replace(/-/g, '')}`;
  const keys = loadKeys();
  keys[key] = { email, tier, created: new Date().toISOString() };
  saveKeys(keys);
  
  res.json({ apiKey: key, tier, limits: { daily: TIER_LIMITS[tier] } });
});

// GET /v1/risk-scores — all countries
app.get('/v1/risk-scores', authenticate, rateLimitByKey, async (req, res) => {
  try {
    const data = await fetchRiskScores();
    const scores = Array.isArray(data) ? data : data.countries || data.scores || [];
    res.json({
      count: scores.length,
      last_updated: riskCache.ts ? new Date(riskCache.ts).toISOString() : new Date().toISOString(),
      countries: scores.map(c => ({
        country: c.country || c.name,
        iso: c.iso || c.code || c.iso3,
        cii_score: c.cii_score ?? c.score ?? c.instability ?? null,
        trend: c.trend || 'stable',
        last_updated: c.last_updated || new Date().toISOString()
      }))
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch risk scores' });
  }
});

// GET /v1/risk-scores/:country — single country
app.get('/v1/risk-scores/:country', authenticate, rateLimitByKey, async (req, res) => {
  try {
    const data = await fetchRiskScores();
    const scores = Array.isArray(data) ? data : data.countries || data.scores || [];
    const country = req.params.country.toUpperCase();
    
    const match = scores.find(c => 
      (c.iso || c.code || '').toUpperCase() === country ||
      (c.country || c.name || '').toUpperCase() === country
    );
    
    if (!match) return res.status(404).json({ error: 'Country not found' });
    
    res.json({
      country: match.country || match.name,
      iso: match.iso || match.code,
      cii_score: match.cii_score ?? match.score ?? null,
      sub_scores: match.sub_scores || {
        political: match.political ?? null,
        economic: match.economic ?? null,
        security: match.security ?? null,
        social: match.social ?? null
      },
      trend: match.trend || 'stable',
      trend_30d: match.trend_30d ?? null,
      trend_90d: match.trend_90d ?? null,
      contributing_factors: match.factors || [],
      last_updated: match.last_updated || new Date().toISOString()
    });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch country data' });
  }
});

// GET /v1/risk-scores/compare?countries=US,CN,RU
app.get('/v1/risk-scores/compare', authenticate, rateLimitByKey, async (req, res) => {
  try {
    const countries = (req.query.countries || '').split(',').map(c => c.trim().toUpperCase()).filter(Boolean);
    if (!countries.length) return res.status(400).json({ error: 'Provide ?countries=US,CN,RU' });
    
    const data = await fetchRiskScores();
    const scores = Array.isArray(data) ? data : data.countries || data.scores || [];
    
    const results = countries.map(code => {
      const match = scores.find(c =>
        (c.iso || c.code || '').toUpperCase() === code ||
        (c.country || c.name || '').toUpperCase() === code
      );
      return match ? {
        country: match.country || match.name,
        iso: match.iso || match.code,
        cii_score: match.cii_score ?? match.score ?? null,
        trend: match.trend || 'stable'
      } : { iso: code, error: 'not found' };
    });
    
    res.json({ compared: results });
  } catch (e) {
    res.status(500).json({ error: 'Failed to compare' });
  }
});

// GET /v1/alerts — countries with CII spikes in last 24h
app.get('/v1/alerts', authenticate, rateLimitByKey, async (req, res) => {
  try {
    const data = await fetchRiskScores();
    const scores = Array.isArray(data) ? data : data.countries || data.scores || [];
    
    // Filter for countries with rising/critical trends
    const alerts = scores.filter(c => 
      c.trend === 'rising' || c.trend === 'critical' || 
      (c.cii_score ?? c.score ?? 0) > 70
    ).map(c => ({
      country: c.country || c.name,
      iso: c.iso || c.code,
      cii_score: c.cii_score ?? c.score ?? null,
      trend: c.trend || 'rising',
      alert_type: (c.cii_score ?? c.score ?? 0) > 80 ? 'critical' : 'elevated'
    }));
    
    res.json({ count: alerts.length, alerts });
  } catch (e) {
    res.status(500).json({ error: 'Failed to fetch alerts' });
  }
});

// --- Landing page ---
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use('/public', express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Risk API running on :${PORT}`));
