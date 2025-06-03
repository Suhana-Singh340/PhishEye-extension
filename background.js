// PhishEye Core Detection Engine - Optimized v3.1
const CONFIG = {
  // System Configuration
  MAX_CONCURRENT_CHECKS: 100,
  REQUEST_TIMEOUT: 5000,
  BLACKLIST: {
    // Update frequency (minutes)
    UPDATE_INTERVAL: 30,
    // Sources (multiple for redundancy)
    SOURCES: [
      'https://phishtank.org/feed.php',
      'https://openphish.com/feed.txt',
      'https://urlhaus.abuse.ch/downloads/text_instant/'
    ],
  },

  CACHE_TTL: {
    LEGIT_DOMAINS: 24 * 60 * 60 * 1000, // 24 hours
    REPUTATION: 6 * 60 * 60 * 1000,     // 6 hours
    DOMAIN_AGE: 12 * 60 * 60 * 1000     // 12 hours
  },

  DEBUG_MODE: false, // Added debug mode flag

  // Detection Parameters - Fine-tuned
  THRESHOLD_RATIO: 0.35,  // Lowered to improve recall
  MIN_DOMAIN_AGE_DAYS: 45, // Increased minimum age
  FUZZY_MATCH_THRESHOLD: 0.80, // Adjusted for better precision
  LEVENSHTEIN_THRESHOLD: 3,    // More tolerant
  DOMAIN_REPUTATION_THRESHOLD: 65, // Lowered threshold

  // Heuristic Weights - Optimized
  HEURISTIC_WEIGHTS: {
    brand: 3.5,    // Increased weight for brand impersonation
    ip: 3.0,       // More weight for IP addresses
    tld: 2.5,      // Increased TLD importance
    entropy: 2.0,  // Reduced entropy weight
    symbols: 1.8,
    numbers: 1.0,
    hyphens: 0.7,
    path: 0.8,
    protocol: 1.2,
    subdomain: 0.7,
    idn: 2.5,      // Increased IDN weight
    hiddenRedirect: 1.7,
    loginForm: 0.9,
    domainAge: 1.4,
    suspiciousPath: 1.1,
    serviceKeywords: 1.8,
    deliveryKeywords: 1.5
  },

  // Enhanced Brand Protection
  BRANDS: [
    'paypal', 'google', 'amazon', 'microsoft', 
    'facebook', 'apple', 'netflix', 'ebay',
    'bankofamerica', 'wellsfargo', 'chase', 'linkedin'
  ],
  
  BRAND_PATTERNS: {
    paypal: /p[Ã¤a4@]y[pt]a[l1i]/i,
    google: /g[o0Ã¶]{2}g[l1|][e3]/i,
    amazon: /a[mn4@][a4@]z[o0Ã¶]n/i,
    microsoft: /m[1i][cÃ§]r[o0Ã¶]s[o0Ã¶]f[t7]/i,
    facebook: /f[a4@]c[e3]e?b[o0Ã¶]?[o0Ã¶]k/i,
    apple: /a[qp]p[l1][e3]/i,
    netflix: /n[e3]tfl[1i]x/i,
    bankofamerica: /b[a4@]nk[o0Ã¶]f?a[m4@]e?r[1i]c[a4@]/i,
    visa: /^(myaccount\.)?visa\.com$/i,
    amex: /^(www\.)?americanexpress\.com$/i,
    disney: /^(www\.)?disneyplus\.com$/i,
    confluence: /^confluence\.atlassian\.com$/i
  },

  // Expanded Suspicious TLDs
  SUSPICIOUS_TLDS: [
    '.tk', '.gq', '.ml', '.cf', '.ga', '.xyz',
    '.top', '.cc', '.club', '.info', '.biz',
    '.online', '.site', '.ru', '.cn', '.pw',
    '.pro', '.work', '.tech', '.space'
  ],
  
  // Enhanced Whitelist
  WHITELIST: [
    /^(?:[a-z]+\.)?(paypal|google|amazon|microsoft)\.(com|org|net|edu)$/i,
    /^(?:[a-z]+\.)?(facebook|apple|netflix|ebay|linkedin)\.(com|net|org)$/i,
    /^[a-z0-9-]+\.(gov|edu|mil|bank|financial|security)(\.[a-z]{2})?$/i,
    /^(?:[a-z]+\.)?(chase|wellsfargo|bankofamerica)\.com$/i,
    /^(login|account)\.live\.com$/i,
    /^myaccount\.visa\.com$/i,
    /^help\.instagram\.com$/i,
    /^driver\.grubhub\.com$/i,
    /^confluence\.atlassian\.com$/i,
    /^(www\.)?disneyplus\.com$/i
  ],

  // API Keys (Replace with your actual keys)
  SAFE_BROWSING_KEY: "AIzaSyAsn4ESEWxTFvLbCLI86_CCDsCaFb7Cs80",
  WHOIS_API_KEY: "at_ZKkbp1741Bv6M1qN70cS1ZKpJdUq3",
  REPUTATION_API_KEY: "01971bd2-41e3-7729-b025-a21009715be3"
};

// State Management with Enhanced Tracking
const state = {
  stats: {
    totalScans: 0,
    threatsBlocked: 0,
    falsePositives: 0,
    lastDetection: null,
    detectionLog: [],
    accuracyMetrics: {
      truePositives: 0,
      trueNegatives: 0,
      falsePositives: 0,
      falseNegatives: 0,
      precision: 0,
      recall: 0,
      f1Score: 0
    }
  },
  performance: {
    totalDetectionTime: 0,
    averageDetectionTime: 0,
    lastDetectionTime: 0,
    scanCount: 0,
    detectionTimes: [],
    resourceUsage: {
      memory: 0,
      cpu: 0
    }
  },
  cache: {
    legitDomains: {
      data: null,
      lastUpdated: 0
    },
    domainReputation: new Map(),
    domainAge: new Map(),
    safeBrowsing: new Map()
  },
  blacklist: {
    domains: new Set(),
    urlPatterns: [],
    lastUpdated: 0
  }
};

// Blacklist loader
// Blacklist loader with better error handling
async function updateBlacklist() {
  try {
    const now = Date.now();
    
    // Check if update is needed
    if (now - state.blacklist.lastUpdated < CONFIG.BLACKLIST.UPDATE_INTERVAL * 60 * 1000) {
      return;
    }

    const newDomains = new Set();
    const newPatterns = [];
    
    // Enhanced fetch with timeout
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    // Fetch from all sources in parallel
    const responses = await Promise.allSettled(
      CONFIG.BLACKLIST.SOURCES.map(url => 
        fetch(url, { signal: controller.signal })
      )
    );

    clearTimeout(timeout);

    // Process responses
    for (const response of responses) {
      if (response.status === 'fulfilled' && response.value.ok) {
        try {
          const text = await response.value.text();
          processBlacklistData(text, newDomains, newPatterns);
        } catch (e) {
          console.warn('[PhishEye] Failed to process blacklist source:', e);
        }
      }
    }

    // Only update if we got data
    if (newDomains.size > 0 || newPatterns.length > 0) {
      state.blacklist = {
        domains: newDomains,
        urlPatterns: newPatterns,
        lastUpdated: now
      };
      console.log(`[PhishEye] Blacklist updated with ${newDomains.size} domains`);
    }
  } catch (error) {
    console.error('[PhishEye] Blacklist update failed:', error);
    // Don't clear existing blacklist if update fails
  }
}

// Helper function to process blacklist data
function processBlacklistData(text, domainsSet, patternsArray) {
  const lines = text.split('\n');
  for (const line of lines) {
    if (!line.startsWith('http')) continue;
    
    try {
      const url = new URL(line.trim());
      domainsSet.add(url.hostname);
      
      if (url.pathname !== '/') {
        patternsArray.push(
          new RegExp(`^${escapeRegex(url.hostname)}${escapeRegex(url.pathname)}`, 'i')
        );
      }
    } catch (e) {
      // Skip malformed URLs
    }
  }
}

// Helper to escape regex special characters
function escapeRegex(string) {
  return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}


// Queue System for URL Processing
const detectionQueue = {
  queue: new Set(),
  isProcessing: false,
  MAX_QUEUE_SIZE: 15,

  add(url) {
    if (this.queue.size < this.MAX_QUEUE_SIZE) {
      this.queue.add(url);
      if (!this.isProcessing) {
        this.process();
      }
    } else {
      console.warn('[PhishEye] Queue limit reached');
    }
  },

  async process() {
    this.isProcessing = true;
    while (this.queue.size > 0) {
      const url = this.queue.values().next().value;
      this.queue.delete(url);
      await processURL(url);
    }
    this.isProcessing = false;
  }
};

// Initialization with Error Handling
chrome.runtime.onInstalled.addListener(initializeExtension);

async function initializeExtension() {
  try {
    // Initialize state with default values first
    state.blacklist = {
      domains: new Set(),
      urlPatterns: [],
      lastUpdated: 0
    };

    // Load cached data if available
    const cachedData = await chrome.storage.local.get([
      'phisheyeStats',
      'phisheyePerformance',
      'phisheyeCache',
      'phisheyeBlacklist'
    ]);

    // Restore stats
    if (cachedData.phisheyeStats) {
      state.stats = {
        ...state.stats, // Keep defaults for missing properties
        ...cachedData.phisheyeStats
      };
    }

    // Restore performance data
    if (cachedData.phisheyePerformance) {
      state.performance = {
        ...state.performance,
        ...cachedData.phisheyePerformance
      };
    }

    // Restore cache
    if (cachedData.phisheyeCache) {
      state.cache = {
        ...state.cache,
        legitDomains: cachedData.phisheyeCache.legitDomains || state.cache.legitDomains,
        domainReputation: cachedData.phisheyeCache.domainReputation ? 
          new Map(cachedData.phisheyeCache.domainReputation) : state.cache.domainReputation,
        domainAge: cachedData.phisheyeCache.domainAge ?
          new Map(cachedData.phisheyeCache.domainAge) : state.cache.domainAge
      };
    }

    // Restore blacklist
    if (cachedData.phisheyeBlacklist) {
      state.blacklist = {
        domains: new Set(cachedData.phisheyeBlacklist.domains || []),
        urlPatterns: cachedData.phisheyeBlacklist.urlPatterns || [],
        lastUpdated: cachedData.phisheyeBlacklist.lastUpdated || 0
      };
    }

    console.log('[PhishEye] Extension initialized successfully');
    
    // Initial blacklist update
    try {
      await updateBlacklist();
    } catch (error) {
      console.error('[PhishEye] Initial blacklist update failed:', error);
      // Continue with cached blacklist if available
    }

    // Schedule regular updates with error handling
    setInterval(async () => {
      try {
        await updateBlacklist();
      } catch (error) {
        console.error('[PhishEye] Scheduled blacklist update failed:', error);
      }
    }, CONFIG.BLACKLIST.UPDATE_INTERVAL * 60 * 1000);

  } catch (error) {
    console.error('[PhishEye] Initialization failed:', error);
    // Try to recover with default values
    state.blacklist = {
      domains: new Set(),
      urlPatterns: [],
      lastUpdated: 0
    };
  }
}


// Main Detection Flow - Updated to ensure tabId is properly passed
chrome.webNavigation.onCompleted.addListener(handleNavigation, { 
  url: [{ schemes: ['http', 'https'] }] 
});

// In handleNavigation function:
async function handleNavigation(details) {
  if (details.frameId !== 0) return;
  
  try {
    const tab = await chrome.tabs.get(details.tabId);
    if (!tab?.url?.startsWith('http')) return;

    // Store both URL and tab ID as an object
    detectionQueue.add({
      url: tab.url,
      tabId: details.tabId,
      timestamp: Date.now() 
    });
    
    state.stats.totalScans++;
    updateState();
  } catch (error) {
    console.error('[PhishEye] Navigation error:', error);
  }
}

// Core Detection Functions - Modified to handle queued objects
async function processURL(urlInfo, tabId = null) {
  // Early blacklist check
  if (isBlacklisted(urlInfo.url)) {
    return { isPhishy: true, reason: 'blacklisted' };
  }
  const url = typeof urlInfo === 'string' ? urlInfo : urlInfo.url;
  const actualTabId = tabId || (typeof urlInfo === 'object' ? urlInfo.tabId : null);
  
  const startTime = performance.now();
  const result = {
    url,
    isPhishy: false,
    heuristics: null,
    details: {},
    detectionTime: 0,
    safeBrowsingResult: null
  };

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;

    // Early exit for whitelisted domains
    if (isWhitelisted(hostname)) {
      result.detectionTime = performance.now() - startTime;
      trackPerformance(result);
      updateAccuracyMetrics(false, false); // True negative
      return result;
    }

    // Parallel execution of all checks including Safe Browsing
    const [legitDomains, domainAge, heuristics, fuzzyMatch, reputation, safeBrowsing] = await Promise.all([
      loadLegitDomains(),
      checkDomainAge(hostname),
      analyzeURL(urlObj),
      checkFuzzyMatch(hostname),
      checkDomainReputation(hostname),
      checkGoogleSafeBrowsing(url, actualTabId) // Now returns actual result
    ]);

    result.heuristics = heuristics;
    result.details = { domainAge, reputation, fuzzyMatch };
    result.safeBrowsingResult = safeBrowsing;
    
    // Incorporate Safe Browsing result into final decision
    result.isPhishy = await makeFinalDecision(
      heuristics, 
      fuzzyMatch, 
      reputation, 
      domainAge,
      safeBrowsing // Pass to decision maker
    );

    if (result.isPhishy) {
      handlePhishingDetection(url, heuristics, actualTabId, 
        safeBrowsing?.isPhishy ? 'Google Safe Browsing' : null);
      updateAccuracyMetrics(true, true);
    } else {
      updateAccuracyMetrics(false, true);
    }

  } catch (error) {
    console.error(`[PhishEye] Error processing ${url}:`, error);
    result.error = error.message;
  } finally {
    result.detectionTime = performance.now() - startTime;
    trackPerformance(result);
    return result;
  }
}

// Enhanced URL Analysis
async function analyzeURL(urlObj) {
  const hostname = urlObj.hostname;
  const isNewDomain = await checkDomainAge(hostname);
  return checkHeuristics(urlObj, isNewDomain);
}

function checkHeuristics(url, isNewDomain = false) {
  const domain = url.hostname;
  const pathFeatures = analyzePath(url.pathname);
  const domainFeatures = analyzeDomain(domain, isNewDomain);

  const features = {
    ...pathFeatures,
    ...domainFeatures,
    protocol: url.protocol === 'http:' ? 1 : 0,
    hiddenRedirect: /\/https?:\/\//i.test(url.href) ? 1 : 0,
    domainAge: isNewDomain ? 1 : 0
  };

  const score = calculateHeuristicScore(features);
  return { features, score };
}

function analyzeDomain(domain, isNewDomain) {
  return {
    brand: checkBrandImpersonation(domain) ? 1 : 0,
    ip: isIPAddress(domain) ? 1 : 0,
    tld: hasSuspiciousTLD(domain) ? 1 : 0,
    entropy: calculateAdjustedEntropy(domain, isNewDomain),
    symbols: hasSuspiciousSymbols(domain) ? 1 : 0,
    numbers: countNumbers(domain) > (isNewDomain ? 1 : 2) ? 1 : 0,
    hyphens: countHyphens(domain) > (isNewDomain ? 1 : 2) ? 1 : 0,
    subdomain: domain.split('.').length > (isNewDomain ? 3 : 4) ? 1 : 0,
    idn: isIDNDomain(domain) ? 1 : 0,
    suspiciousSubdomain: hasSuspiciousSubdomain(domain) ? 1 : 0,
    impersonationKeywords: hasImpersonationKeywords(domain) ? 1 : 0,
    serviceKeywords: hasServiceKeywords(domain) ? 1 : 0,
    deliveryKeywords: hasDeliveryKeywords(domain) ? 1 : 0
  };
}

// Robust blacklist checking
function isBlacklisted(url) {
  if (!url) return false;
  
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const fullPath = `${hostname}${urlObj.pathname}`;

    // Check domains
    if (state.blacklist.domains.has(hostname)) {
      return true;
    }

    // Check path patterns
    for (const pattern of state.blacklist.urlPatterns) {
      if (pattern.test(fullPath)) {
        return true;
      }
    }
  } catch (e) {
    console.warn('[PhishEye] URL parsing error:', e);
  }
  
  return false;
}

function hasSuspiciousSubdomain(domain) {
  return /(login|secure|auth|verify|account|update|support)\./i.test(domain);
}

function hasImpersonationKeywords(domain) {
  return /(security|update|verification|confirmation|authenticate)/i.test(domain);
}

function hasServiceKeywords(domain) {
  return /(support|verify|update|renewal|billing|tracking|delivery|shipment)/i.test(domain);
}

function hasDeliveryKeywords(domain) {
  return /(delivery|shipment|tracking|courier|driver|express)/i.test(domain);
}

function analyzePath(path) {
  const lowerPath = path.toLowerCase();
  return {
    pathDepth: path.split('/').length > 5 ? 1 : 0,
    fakeLogin: hasLoginKeywords(lowerPath) ? 1 : 0,
    duplicateWords: hasDuplicateWords(lowerPath) ? 1 : 0,
    longRandomPath: isLongRandomPath(path) ? 1 : 0,
    sensitiveKeywords: hasSensitiveKeywords(lowerPath) ? 0.5 : 0
  };
}

// Enhanced Brand Protection
function checkBrandImpersonation(domain) {
  if (isWhitelisted(domain)) return false;

  const domainParts = domain.split('.');
  const mainPart = domainParts.length > 1 ? domainParts[domainParts.length - 2] : domainParts[0];

  // Check against brand patterns first
  for (const [brand, pattern] of Object.entries(CONFIG.BRAND_PATTERNS)) {
    if (pattern.test(mainPart)) {
      if (!isOfficialDomain(domain, brand)) {
        return true;
      }
    }
  }

  // Check for common phishing patterns
  const phishingPatterns = [
    /-login-/i,
    /-secure-/i,
    /-verify-/i,
    /-account-/i,
    /-update-/i,
    /-confirm-/i
  ];

  if (phishingPatterns.some(p => p.test(domain))) {
    return true;
  }

  return false;
}

// Domain Analysis Utilities
function isIPAddress(domain) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(domain);
}

function hasSuspiciousTLD(domain) {
  return CONFIG.SUSPICIOUS_TLDS.some(tld => domain.endsWith(tld));
}

function hasSuspiciousSymbols(str) {
  return /[@%#\$&]/.test(str);
}

function countNumbers(str) {
  return (str.match(/\d/g) || []).length;
}

function countHyphens(str) {
  return (str.match(/-/g) || []).length;
}

function isIDNDomain(domain) {
  return /xn--/.test(domain) || 
         /[^\x00-\x7F]/.test(domain) || // Non-ASCII chars
         /[Ð°-ÑÐ-Ð¯]/.test(domain); // Cyrillic chars
}

function hasLoginKeywords(path) {
  return /(log[oi]n|sign|auth|verify)/i.test(path);
}

function hasDuplicateWords(path) {
  return (path.match(/(\b\w+\b).*?\1/g) || []).length > 0;
}

function isLongRandomPath(path) {
  return path.length > 35 && /[a-z0-9]{10,}/i.test(path);
}

function hasSensitiveKeywords(path) {
  return /(account|security|update|verify|confirm|bank|payment)/i.test(path);
}

function fallbackDomainAgeCheck(domain) {
  const mainPart = domain.split('.')[0];
  return (
    mainPart.length > 15 ||
    (domain.split('.').length > 2 && mainPart.length > 8) ||
    /(20[2-3][0-9]|24|25)/.test(domain) // Contains recent years
  );
}

function analyzeSubdomains(domain) {
  const parts = domain.split('.');
  if (parts.length < 3) return 0;
  
  const subdomains = parts.slice(0, -2);
  return subdomains.some(sd => 
    sd.length > 15 || 
    /[^a-z0-9-]/.test(sd) ||
    /([0-9][a-z]|[a-z][0-9])/.test(sd)
  ) ? 1 : 0;
}

// Adjusted Entropy Calculation
function calculateAdjustedEntropy(str, isNewDomain) {
  const entropy = calculateEntropy(str);
  const threshold = isNewDomain ? 3.0 : 3.5;
  return entropy > threshold ? Math.min(entropy / 5, 1) : 0;
}

function calculateHeuristicScore(features) {
  let score = 0;
  for (const [feature, value] of Object.entries(features)) {
    if (CONFIG.HEURISTIC_WEIGHTS[feature]) {
      score += value * CONFIG.HEURISTIC_WEIGHTS[feature];
    }
  }
  return score;
}

// Fuzzy Matching with Enhanced Similarity Checks
async function checkFuzzyMatch(domain) {
  const legitDomains = await loadLegitDomains();
  let maxScore = 0;

  const domainParts = domain.split('.');
  const mainDomain = domainParts.length > 1 ? domainParts[domainParts.length - 2] : domainParts[0];

  for (const legit of legitDomains) {
    const legitParts = legit.split('.');
    const legitMain = legitParts.length > 1 ? legitParts[legitParts.length - 2] : legitParts[0];

    const jw = jaroWinklerSimilarity(mainDomain, legitMain);
    const lev = levenshteinDistance(mainDomain, legitMain);
    const hybrid = 0.6 * jw + 0.4 * (1 - lev / Math.max(mainDomain.length, legitMain.length));

    if (hybrid > maxScore) maxScore = hybrid;
  }

  return maxScore;  // score from 0 to 1
}


function isSimilarDomain(a, b) {
  const similarity = jaroWinklerSimilarity(a, b);
  const distance = levenshteinDistance(a, b);
  const lengthDiff = Math.abs(a.length - b.length);

  return similarity > CONFIG.FUZZY_MATCH_THRESHOLD || 
        (distance <= CONFIG.LEVENSHTEIN_THRESHOLD && lengthDiff <= 3);
}

// Domain Reputation System with Fallback
async function checkDomainReputation(domain) {
  try {
    // Check cache first
    if (state.cache.domainReputation.has(domain)) {
      const cached = state.cache.domainReputation.get(domain);
      if (Date.now() - cached.timestamp < CONFIG.CACHE_TTL.REPUTATION) {
        return cached.score > CONFIG.DOMAIN_REPUTATION_THRESHOLD;
      }
    }

    // If no API key, use fallback
    if (!CONFIG.REPUTATION_API_KEY || CONFIG.REPUTATION_API_KEY === "your_reputation_api_key_here") {
      return fallbackReputationCheck(domain);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    const response = await fetch(`https://api.urlvoid.com/api/phisheye/${domain}?apiKey=${CONFIG.REPUTATION_API_KEY}`, {
      signal: controller.signal
    }).catch(() => null);
    
    clearTimeout(timeout);
    
    if (!response || !response.ok) {
      return fallbackReputationCheck(domain);
    }

    const data = await response.json();
    const score = data.threatScore || 0;

    // Update cache
    state.cache.domainReputation.set(domain, {
      score,
      timestamp: Date.now()
    });

    return score > CONFIG.DOMAIN_REPUTATION_THRESHOLD;
  } catch (error) {
    console.warn('[PhishEye] Reputation check failed, using fallback:', error.message);
    return fallbackReputationCheck(domain);
  }
}

function fallbackReputationCheck(domain) {
  let score = 0;
  
  // Suspicious TLD
  if (hasSuspiciousTLD(domain)) {
    score += 0.4;
  }
  
  // Multiple subdomains
  if (domain.split('.').length > 3) {
    score += 0.3;
  }
  
  // Brand in subdomain
  if (checkBrandImpersonation(domain)) {
    score += 0.3;
  }

  return score > 0.7;
}

// Domain Age Verification with Fallback
async function checkDomainAge(domain) {
  try {
    // Check cache first
    if (state.cache.domainAge.has(domain)) {
      const cached = state.cache.domainAge.get(domain);
      if (Date.now() - cached.timestamp < CONFIG.CACHE_TTL.DOMAIN_AGE) {
        return cached.isNew;
      }
    }

    // If no API key, use fallback
    if (!CONFIG.WHOIS_API_KEY || CONFIG.WHOIS_API_KEY === "your_whois_api_key_here") {
      return fallbackDomainAgeCheck(domain);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), CONFIG.REQUEST_TIMEOUT);

    const response = await fetch(`https://api.whois.com/v1/${domain}?apiKey=${CONFIG.WHOIS_API_KEY}`, {
      signal: controller.signal
    }).catch(() => null);
    
    clearTimeout(timeout);
    
    if (!response || !response.ok) {
      return fallbackDomainAgeCheck(domain);
    }

    const data = await response.json();
    const creationDate = new Date(data.creationDate || Date.now());
    const ageInDays = (Date.now() - creationDate) / (1000 * 60 * 60 * 24);
    const isNew = ageInDays < CONFIG.MIN_DOMAIN_AGE_DAYS;

    // Update cache
    state.cache.domainAge.set(domain, {
      isNew,
      timestamp: Date.now()
    });

    return isNew;
  } catch (error) {
    console.warn('[PhishEye] Domain age check failed, using fallback:', error.message);
    return fallbackDomainAgeCheck(domain);
  }
}

function fallbackDomainAgeCheck(domain) {
  const mainPart = domain.split('.')[0];
  const hasNumbers = /\d/.test(mainPart);
  const isLong = mainPart.length > 18;
  const hasMultipleHyphens = (mainPart.match(/-/g) || []).length > 1;
  
  return hasNumbers || isLong || hasMultipleHyphens || 
         /(login|secure|verify|account)/i.test(domain);
}

async function makeFinalDecision(heuristics, fuzzyMatch, reputation, isNewDomain, safeBrowsing = null) {
  // If GSB says it's phishing, we trust that immediately
  if (safeBrowsing?.isPhishy) {
    console.debug('[PhishEye] Safe Browsing confirmed phishing');
    return true;
  }
  const domain = heuristics.features.domain || extractDomainFromFeatures(heuristics.features);
  const maxScore = calculateMaxHeuristicScore();
  const heuristicConfidence = heuristics.score / maxScore;
  
  const weights = {
    heuristics: 0.65,
    fuzzy: 0.22,
    reputation: 0.08,
    domainAge: 0.08,
    threatBoosters: 0.25
  };

  let combinedScore = (
    (heuristicConfidence * weights.heuristics * 100) +
    (fuzzyMatch * weights.fuzzy * 100) +
    (reputation ? weights.reputation * 100 : 0)
  );

  // Fuzzy score band logic: boost suspicion on lower similarity, lower score on high similarity
  if (fuzzyMatch < 0.82) {
    combinedScore += 15;
  } else if (fuzzyMatch < 0.85) {
    combinedScore += 10;
  } else if (fuzzyMatch < 0.93) {
    combinedScore += 5;
  } else {
    combinedScore -= 10; // very similar â†’ probably safe
  }

  if (isNewDomain) {
    combinedScore += weights.domainAge * 100;
    
    if (heuristics.features.brand) {
      combinedScore += 12;
    }
    if (heuristics.features.tld) {
      combinedScore += 10;
    }
  }

  const threatBoosters = {
    idn: heuristics.features.idn ? 20 : 0,
    mixedScript: isMixedScript(domain) ? 25 : 0,
    longSubdomain: hasLongSuspiciousSubdomain(domain) ? 15 : 0,
    recentYear: hasRecentYear(domain) ? 12 : 0,
    sensitiveKeywords: hasSensitiveKeywords(domain) ? 18 : 0
  };

  const boosterScore = Object.values(threatBoosters).reduce((sum, value) => sum + value, 0);
combinedScore += Math.min(boosterScore, 60) * weights.threatBoosters;

  
  combinedScore += Object.values(threatBoosters).reduce((sum, value) => sum + value, 0) * weights.threatBoosters;

  let dynamicThreshold = Math.max(
    CONFIG.THRESHOLD_RATIO * 100 + 1,
    25
  );

  const extremeCases = {
    brandWithIp: heuristics.features.brand && heuristics.features.ip,
    brandWithRedirect: heuristics.features.brand && heuristics.features.hiddenRedirect,
    brandWithIdn: heuristics.features.brand && heuristics.features.idn,
    newWithSensitiveKeywords: isNewDomain && threatBoosters.sensitiveKeywords > 0
  };

  if (Object.values(extremeCases).some(Boolean)) {
    dynamicThreshold -= 15;
    combinedScore += 10;
  }

  const isPhishy = combinedScore > dynamicThreshold;
  
  if (isPhishy || CONFIG.DEBUG_MODE) {
    console.debug(`[PhishEye] Detection Decision - Score: ${combinedScore.toFixed(1)}/${dynamicThreshold.toFixed(1)}`, {
      verdict: isPhishy ? 'PHISHING' : 'SAFE',
      weights,
      features: heuristics.features,
      boosters: threatBoosters,
      extremeCases,
      scoreBreakdown: {
        baseHeuristics: (heuristicConfidence * weights.heuristics * 100).toFixed(1),
        fuzzyMatch: (fuzzyMatch * weights.fuzzy * 100).toFixed(1),
        reputation: (reputation ? weights.reputation * 100 : 0).toFixed(1),
        domainAge: (isNewDomain ? weights.domainAge * 100 : 0).toFixed(1),
        threatBoosters: (Object.values(threatBoosters).reduce((sum, value) => sum + value, 0) * weights.threatBoosters).toFixed(1)
      }
    });
  }

  return isPhishy;
}

function handleWarningAction(request, tabId) {
  switch (request.action) {
    case "proceed":
      // User chose to proceed anyway
      chrome.tabs.update(tabId, { url: request.url });
      break;
      
    case "goBack":
      // User chose to go back to safety
      chrome.tabs.goBack(tabId);
      break;
      
    case "reportFalsePositive":
      handleFalsePositiveReport(request.url);
      break;
  }
}

// Helper functions
function isMixedScript(domain) {
  return /[a-z]/i.test(domain) && /[^\x00-\x7F]/.test(domain);
}

function hasLongSuspiciousSubdomain(domain) {
  const parts = domain.split('.');
  return parts.length > 2 && parts[0].length > 15;
}

function hasRecentYear(domain) {
  return /(202[2-9]|2030)/.test(domain);
}

function hasSensitiveKeywords(domain) {
  return /(login|verify|secure|update|account|support|payment|bank)/i.test(domain);
}

function extractDomainFromFeatures(features) {
  return features.hostname || '';
}

function calculateMaxHeuristicScore() {
  return Object.values(CONFIG.HEURISTIC_WEIGHTS).reduce((a, b) => a + b, 0);
}

// Safe Browsing Integration
async function checkGoogleSafeBrowsing(url, tabId) {
  try {
    // Return cached result if available
    if (state.cache.safeBrowsing?.has(url)) {
      const cached = state.cache.safeBrowsing.get(url);
      if (Date.now() - cached.timestamp < CONFIG.CACHE_TTL.REPUTATION) {
        return cached.result;
      }
    }

    const payload = {
      client: {
        clientId: "phisheye",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };

    const response = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.SAFE_BROWSING_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      }
    );

    if (!response.ok) throw new Error(`GSB API error: ${response.status}`);

    const data = await response.json();
    const isThreat = data.matches?.length > 0;
    
    // Cache the result
    if (!state.cache.safeBrowsing) state.cache.safeBrowsing = new Map();
    state.cache.safeBrowsing.set(url, {
      result: { isPhishy: isThreat, details: data.matches },
      timestamp: Date.now()
    });

    return { isPhishy: isThreat, details: data.matches };
  } catch (error) {
    console.warn('[PhishEye] Safe Browsing check failed:', error.message);
    return { isPhishy: false, error: error.message };
  }
}

// Phishing Handling - Updated to ensure proper warning page display
async function handlePhishingDetection(url, heuristics, tabId, reason = null) {
  if (!tabId) {
    console.error('[PhishEye] No tabId provided for phishing detection');
    return;
  }

  state.stats.threatsBlocked++;
  
  if (!reason) {
    reason = `Heuristic match (score: ${heuristics?.score?.toFixed(2) || 'N/A'})`;
  }

  logDetection({
    url,
    type: 'heuristic',
    reason,
    details: heuristics?.features || {},
    isFalsePositive: false
  });

  try {
    // 1. First try to update the tab
    await chrome.tabs.update(tabId, {
      url: chrome.runtime.getURL(`warning/warning.html?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}&tabId=${tabId}`)
    });

    // 2. Send notification
    chrome.notifications.create({
    type: 'basic',
    iconUrl: chrome.runtime.getURL('icons/icon128.png'),
    title: 'Phishing Detected!',
    message: `Blocked suspicious page: ${new URL(url).hostname}`
  }, () => {
    if (chrome.runtime.lastError) {
      console.warn('[PhishEye] Failed to show notification:', chrome.runtime.lastError.message);
    }
  });

    // 3. Update icon
    chrome.action.setIcon({
    tabId,
    path: {
      "16": "icons/icon16-alert.png",
      "32": "icons/icon32-alert.png",
      "48": "icons/icon48-alert.png"
    }
   }, () => {
    if (chrome.runtime.lastError) {
      console.warn('[PhishEye] Failed to set icon:', chrome.runtime.lastError.message);
    }
  });

    // 4. Send message to content script if available
    try {
      await chrome.tabs.sendMessage(tabId, {
        action: "showPhishingWarning",
        url,
        reason
      });
    } catch (contentScriptError) {
      console.debug('[PhishEye] Content script not available, proceeding without it');
    }

  } catch (error) {
    console.error('[PhishEye] Failed to show warning:', error);
    
    // Fallback: Try to create a new tab if updating fails
    try {
      await chrome.tabs.create({
        url: chrome.runtime.getURL(`warning/warning.html?url=${encodeURIComponent(url)}&reason=${encodeURIComponent(reason)}`)
      });
    } catch (fallbackError) {
      console.error('[PhishEye] Fallback warning page also failed:', fallbackError);
    }
  }
}

// Whitelisting System
function isWhitelisted(domain) {
  const exactWhitelist = [
    'www.paypal.com',
    'accounts.google.com',
    'login.microsoftonline.com',
    'facebook.com',
    'appleid.apple.com',
    'amazon.com',
    'netflix.com',
    'ebay.com',
    'bankofamerica.com',
    'wellsfargo.com',
    'chase.com'
  ];
  
  return exactWhitelist.includes(domain) || 
         CONFIG.WHITELIST.some(regex => regex.test(domain));
}

function isOfficialDomain(domain, brand) {
  const officialPatterns = {
    paypal: /^(www\.)?paypal\.(com|org|net)$/i,
    google: /^(www\.)?google\.(com|org|net)$/i,
    amazon: /^(www\.)?amazon\.(com|org|net)$/i,
    microsoft: /^(www\.)?microsoft\.(com|org|net)$/i,
    facebook: /^(www\.)?facebook\.(com|org|net)$/i,
    apple: /^(www\.)?apple\.(com|org|net)$/i,
    netflix: /^(www\.)?netflix\.(com|org|net)$/i,
    ebay: /^(www\.)?ebay\.(com|org|net)$/i,
    bankofamerica: /^(www\.)?bankofamerica\.com$/i,
    wellsfargo: /^(www\.)?wellsfargo\.com$/i,
    chase: /^(www\.)?chase\.com$/i
  };

  return officialPatterns[brand]?.test(domain) || false;
}

// Data Loading with Caching
async function loadLegitDomains() {
  if (state.cache.legitDomains.data?.length > 5000) {
    state.cache.legitDomains.data = state.cache.legitDomains.data.slice(0, 5000);
  }
  try {
    if (state.cache.legitDomains.data && 
        Date.now() - state.cache.legitDomains.lastUpdated < CONFIG.CACHE_TTL.LEGIT_DOMAINS) {
      return state.cache.legitDomains.data;
    }

    const response = await fetch(chrome.runtime.getURL('data/top_sites.json'));
    const data = await response.json();
    
    state.cache.legitDomains.data = data.map(url => {
      try {
        return new URL(url.startsWith('http') ? url : `https://${url}`).hostname
          .replace(/^www\./, '')
          .toLowerCase();
      } catch {
        return null;
      }
    }).filter(domain => domain && domain.split('.').length >= 2);

    state.cache.legitDomains.lastUpdated = Date.now();
    return state.cache.legitDomains.data;
  } catch (error) {
    console.error("[PhishEye] Failed to load legit domains:", error);
    return [];
  }
}

// Performance Monitoring
function trackPerformance(result) {
  state.performance.scanCount++;
  state.performance.lastDetectionTime = result.detectionTime;
  state.performance.totalDetectionTime += result.detectionTime;
  state.performance.averageDetectionTime = 
    state.performance.totalDetectionTime / state.performance.scanCount;
  
  if (state.performance.detectionTimes.length > 100) {
    state.performance.detectionTimes.shift();
  }
  state.performance.detectionTimes.push(result.detectionTime);

  if (!state.performance.resourceUsage) {
    state.performance.resourceUsage = { memory: 0, cpu: 0 };
  }
  
  state.performance.resourceUsage.memory = 0;
  try {
    if (performance?.memory?.usedJSHeapSize) {
      state.performance.resourceUsage.memory = 
        performance.memory.usedJSHeapSize / (1024 * 1024);
    }
  } catch (e) {
    console.debug('[PhishEye] Memory measurement unavailable');
  }
  
  updateState();
}

function updateAccuracyMetrics(isPhishy, isDetection) {
  state.stats.accuracyMetrics = state.stats.accuracyMetrics || {
    truePositives: 0,
    trueNegatives: 0,
    falsePositives: 0,
    falseNegatives: 0,
    precision: 0,
    recall: 0,
    f1Score: 0
  };

  const metrics = state.stats.accuracyMetrics;
  
  if (isDetection) {
    if (isPhishy) {
      metrics.truePositives = (metrics.truePositives || 0) + 1;
    } else {
      metrics.falseNegatives = (metrics.falseNegatives || 0) + 1;
    }
  } else {
    if (isPhishy) {
      metrics.falsePositives = (metrics.falsePositives || 0) + 1;
    } else {
      metrics.trueNegatives = (metrics.trueNegatives || 0) + 1;
    }
  }

  const tp = metrics.truePositives || 0;
  const fp = metrics.falsePositives || 0;
  const fn = metrics.falseNegatives || 0;

  metrics.precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  metrics.recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  
  metrics.f1Score = metrics.precision + metrics.recall > 0 
    ? 2 * (metrics.precision * metrics.recall) / (metrics.precision + metrics.recall) 
    : 0;

  updateState();
}

// Update state persistence to include blacklist
function updateState() {
  chrome.storage.local.set({
    phisheyeStats: state.stats,
    phisheyePerformance: state.performance,
    phisheyeCache: {
      legitDomains: state.cache.legitDomains,
      domainReputation: Array.from(state.cache.domainReputation.entries()),
      domainAge: Array.from(state.cache.domainAge.entries())
    },
    phisheyeBlacklist: {
      domains: Array.from(state.blacklist.domains),
      urlPatterns: state.blacklist.urlPatterns,
      lastUpdated: state.blacklist.lastUpdated
    }
  });
}

function logDetection(detection) {
  detection.timestamp = new Date().toISOString();
  state.stats.detectionLog.unshift(detection);
  state.stats.lastDetection = detection;
  
  if (state.stats.detectionLog.length > 100) {
    state.stats.detectionLog.pop();
  }
  
  updateState();
}

// UI Functions
function showWarningPage(tabId, reason) {
  chrome.tabs.update(tabId, {
    url: chrome.runtime.getURL(`warning/warning.html?reason=${encodeURIComponent(reason)}&tabId=${tabId}`)
  });
  
  chrome.action.setBadgeText({ 
    text: String(state.stats.threatsBlocked), 
    tabId 
  });
  
  chrome.action.setBadgeBackgroundColor({ 
    color: '#F44336' 
  });
}

// Similarity Algorithms (Optimized)
function jaroWinklerSimilarity(s1, s2) {
  if (s1 === s2) return 1.0;

  const m = Math.min(s1.length, s2.length);
  const matchDistance = Math.max(Math.floor(Math.max(s1.length, s2.length) / 2) - 1, 0);

  let matches = 0;
  const s1Matches = new Array(s1.length).fill(false);
  const s2Matches = new Array(s2.length).fill(false);

  for (let i = 0; i < s1.length; i++) {
    const start = Math.max(0, i - matchDistance);
    const end = Math.min(s2.length, i + matchDistance + 1);
    
    for (let j = start; j < end; j++) {
      if (!s2Matches[j] && s1[i] === s2[j]) {
        s1Matches[i] = s2Matches[j] = true;
        matches++;
        break;
      }
    }
  }

  if (matches === 0) return 0.0;

  let transpositions = 0;
  let k = 0;
  for (let i = 0; i < s1.length; i++) {
    if (s1Matches[i]) {
      while (!s2Matches[k]) k++;
      if (s1[i] !== s2[k]) transpositions++;
      k++;
    }
  }

  const jaro = (
    (matches / s1.length) + 
    (matches / s2.length) + 
    ((matches - transpositions / 2) / matches)
  ) / 3.0;

  const prefixLength = Math.min(4, [...s1].filter((c, i) => c === s2[i]).length);
  return jaro + (prefixLength * 0.1 * (1 - jaro));
}

function levenshteinDistance(a, b) {
  if (a === b) return 0;
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  if (a.length > b.length) [a, b] = [b, a];

  const lenDiff = b.length - a.length;
  if (lenDiff >= CONFIG.LEVENSHTEIN_THRESHOLD) {
    return lenDiff;
  }

  const matrix = [];
  for (let i = 0; i <= a.length; i++) {
    matrix[i] = [i];
  }
  for (let j = 0; j <= b.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i][j] = Math.min(
        matrix[i - 1][j] + 1,
        matrix[i][j - 1] + 1,
        matrix[i - 1][j - 1] + cost
      );
    }
  }

  return matrix[a.length][b.length];
}

// Entropy Calculation
function calculateEntropy(str) {
  const len = str.length;
  const freq = {};
  
  for (const char of str.toLowerCase()) {
    freq[char] = (freq[char] || 0) + 1;
  }
  
  return Object.values(freq).reduce((sum, count) => {
    const p = count / len;
    return sum - (p * Math.log2(p));
  }, 0);
}

// Message Handling
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.action) {
    case "phishWarningAction":
      handleWarningAction(request, sender.tab?.id);
      break;
      
    case "getCurrentTab":
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        sendResponse(tabs[0]);
      });
      return true;

    case "getStats":
      sendResponse({
        stats: state.stats,
        performance: state.performance
      });
      break;
      
    case "getDetectionLog":
      sendResponse(state.stats.detectionLog);
      break;
      
    case "getConfig":
      sendResponse(CONFIG);
      break;
      
    case "reportFalsePositive":
      handleFalsePositiveReport(request.url);
      sendResponse({ success: true });
      break;
      
    case "checkUrl":
      (async () => {
        try {
          const result = await processURL(request.url);
          sendResponse(result);
        } catch (error) {
          sendResponse({ 
            url: request.url,
            error: error.message
          });
        }
      })();
      return true;
      
    case "checkBatch":
      (async () => {
        if (!request.urls || request.urls.length > CONFIG.MAX_CONCURRENT_CHECKS) {
          return sendResponse({
            error: `Maximum ${CONFIG.MAX_CONCURRENT_CHECKS} URLs allowed`
          });
        }

        const results = await Promise.allSettled(
          request.urls.map(url => processURL(url))
        );

        sendResponse({
          processed: results.length,
          results: results.map(r => r.status === 'fulfilled' ? r.value : {
            url: r.reason.url,
            error: r.reason.message
          }),
          performance: {
            averageTime: state.performance.averageDetectionTime,
            lastBatchTime: state.performance.lastDetectionTime
          }
        });
      })();
      return true;
      
    default:
      sendResponse({ error: 'Unknown action' });
  }
});

function handleFalsePositiveReport(url) {
  const detection = state.stats.detectionLog.find(d => d.url === url);
  if (detection) {
    detection.isFalsePositive = true;
    state.stats.falsePositives++;
    
    state.stats.accuracyMetrics.falsePositives++;
    state.stats.accuracyMetrics.truePositives--;
    
    updateState();
  }
}

// Batch Processing
async function batchProcessURLs(urls) {
  const results = [];
  const batches = chunkArray(urls, CONFIG.MAX_CONCURRENT_CHECKS);

  for (const batch of batches) {
    const batchResults = await Promise.allSettled(
      batch.map(url => processURL(url))
    );
    results.push(...batchResults);
  }

  return results;
}

function chunkArray(arr, size) {
  return Array.from(
    { length: Math.ceil(arr.length / size) },
    (_, i) => arr.slice(i * size, i * size + size)
  );
}