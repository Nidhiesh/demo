/**
 * CYBER SHIELD - BACKGROUND SERVICE WORKER
 * Runs automatically in background
 * Communicates with Flask API for scam detection
 */
import { logThreat } from './firebase-config.js';

// This is the "Receiver" that stays active in the background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'CHECK_SCAM') {
    console.log("Received alert from WhatsApp, sending to Firebase...");

    // Call the function we built in firebase-config.js
    logThreat(sender.tab.url || "WhatsApp Web", "Suspicious Message Detected")
      .then(() => {
        sendResponse({ status: "Success", logged: true });
      })
      .catch((error) => {
        console.error("Firebase log failed:", error);
        sendResponse({ status: "Error", message: error.message });
      });

    return true; // CRITICAL: Keeps the connection alive for the async Firebase call
  }
});

// Listen for redirects or phishing sites blocked by your rules
chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const blockedUrl = info.request.url;
    console.log("CyberShield Blocked:", blockedUrl);
    
    // This sends the data to your Firebase Firestore
    logThreat(blockedUrl, "Malicious Redirect/Phishing");
});

const API_ENDPOINT = 'http://localhost:5000/detect';
let detectionEnabled = true;
let backendStatus = 'offline';

function isBankRelated(message) {
    const lower = message.toLowerCase();
    const bankTerms = [
        'sbi', 'hdfc', 'icici', 'axis', 'boi', 'bank', 'bank account',
        'bank alert', 'credit card', 'debit card', 'netbanking', 'online banking',
        'upi', 'ifsc', 'atm', 'account locked', 'account suspended',
        'banking security', 'transaction alert', 'loan', 'card details'
    ];
    return bankTerms.some(term => lower.includes(term));
}

// Load settings on startup
chrome.storage.sync.get(['detectionEnabled'], (data) => {
    if (data.detectionEnabled !== undefined) {
        detectionEnabled = data.detectionEnabled;
    }
    checkBackendHealth();
    updateBadge(); // Update badge on startup
});

// Listen for storage changes
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'sync' && changes.detectionEnabled) {
        detectionEnabled = changes.detectionEnabled.newValue;
        updateBadge();
    }
});

// Update the badge on the extension icon
function updateBadge() {
    if (detectionEnabled) {
        // Green badge for active
        chrome.action.setBadgeText({ text: '✓' });
        chrome.action.setBadgeBackgroundColor({ color: '#00c851' });
    } else {
        // Red badge for inactive
        chrome.action.setBadgeText({ text: '✗' });
        chrome.action.setBadgeBackgroundColor({ color: '#ff6b6b' });
    }
}

// Check if backend is online (runs continuously)
function checkBackendHealth() {
    fetch('http://localhost:5000/health')
        .then(response => {
            if (response.ok) {
                backendStatus = 'online';
                console.log('✓ Backend is online and ready');
            } else {
                backendStatus = 'offline';
            }
        })
        .catch(error => {
            backendStatus = 'offline';
            console.log('⚠ Backend offline - using fallback detection');
        });
    
    // Check every 30 seconds
    setTimeout(checkBackendHealth, 30000);
}

// Main message listener from content.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    
    if (request.type === 'CHECK_SCAM') {
        handleScamCheck(request, sender, sendResponse);
        return true; // Keep connection alive for async response
    }
    
    if (request.type === 'URL_SCAM_DETECTED') {
        handleUrlScamDetected(request, sender, sendResponse);
        return true;
    }
    
    if (request.type === 'GET_STATUS') {
        sendResponse({
            detectionEnabled: detectionEnabled,
            backendStatus: backendStatus
        });
    }
});

// Handle URL scam detection
function handleUrlScamDetected(request, sender, sendResponse) {
    console.log(`[Background] URL Scam detected on ${request.platform}:`, request.threats);
    
    // Send alert to content script
    chrome.tabs.sendMessage(sender.tab.id, {
        type: 'SHOW_WARNING',
        status: 'scam',
        confidence: 0.95,
        threats: request.threats,
        checkId: `URL_${Date.now()}`,
        isUrlScam: true,
        messagePreview: request.messageText
    }, (response) => {
        if (chrome.runtime.lastError) {
            console.log('Content script not ready yet');
        }
    });
    
    sendResponse({ received: true });
}

// Handle scam detection - sends to Flask API
async function handleScamCheck(request, sender, sendResponse) {
    try {
        // Check if detection is enabled
        if (!detectionEnabled) {
            sendResponse({
                type: 'DETECTION_DISABLED',
                status: 'safe'
            });
            return;
        }
        
        const message = request.text;
        if (!message || message.trim().length < 3) {
            sendResponse({
                type: 'MESSAGE_TOO_SHORT',
                status: 'safe'
            });
            return;
        }
        
        console.log(`[Background] Checking message: "${message.substring(0, 50)}..."`);
        
        // If backend is offline, use fallback
        if (backendStatus === 'offline') {
            console.log('[Background] Using fallback detection');
            const result = fallbackDetection(message);
            sendResponse(result);
            return;
        }
        
        // Send to Flask API for ML-based detection
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ message: message })
        });
        
        if (!response.ok) {
            throw new Error(`API error: ${response.status}`);
        }
        
        const result = await response.json();
        
        console.log(`[Background] Detection result:`, result);
        
        // Backend /detect returns: { risk_level, confidence, threats, matches_training_patterns }
        const riskLevel  = result.risk_level  || 'safe';
        const confidence = result.confidence  || 0;
        const threats    = result.threats     || [];
        const matchesTraining = result.matches_training_patterns === true;
        
        const shouldAlert = matchesTraining && riskLevel !== 'safe';
        
        // Send alert to content script if scam detected AND matches training data
        if (shouldAlert) {
            chrome.tabs.sendMessage(sender.tab.id, {
                type: 'SHOW_WARNING',
                status: riskLevel,
                confidence: confidence,
                threats: threats,
                checkId: result.check_id,
                matchesTrainingData: matchesTraining
            }, (response) => {
                if (chrome.runtime.lastError) {
                    console.log('Content script not ready yet');
                }
            });
        }
        
        // Send response back
        sendResponse({
            type: riskLevel === 'safe' ? 'MESSAGE_SAFE' : 'SCAM_DETECTED',
            status: riskLevel,
            confidence: confidence,
            threats: threats,
            matchesTrainingData: matchesTraining
        });
        
    } catch (error) {
        console.error('[Background] Error:', error);
        const fallbackResult = fallbackDetection(request.text);
        sendResponse(fallbackResult);
    }
}

// Fallback keyword detection (when backend is offline) - STRICT mode + Multilingual
function fallbackDetection(message) {
    if (!isBankRelated(message)) {
        return {
            type: 'MESSAGE_SAFE',
            status: 'safe',
            confidence: 0,
            threats: [],
            matchesTrainingData: false
        };
    }

    // Training data patterns from backend — English + Multilingual
    const trainingPatterns = {
        // ===== ENGLISH (High-confidence) =====
        criticalOTP: ['verify your otp', 'enter your otp', 'confirm your otp', 'one time password', 'enter otp'],
        criticalVerify: ['verify account', 'confirm identity', 'verify now', 'confirm account'],
        criticalPayment: ['update payment', 'verify credit card', 'billing information', 'payment method', 'bank account', 'cvv'],
        criticalPrize: ['congratulations won', 'claim prize', 'lottery', 'grand prize', 'free money'],
        criticalUrgent: ['account will be suspended', 'account compromised', 'account locked', 'action required immediately', 'unusual login detected'],
        criticalLink: ['bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', 'short.link', 'ow.ly/secure'],
        criticalBank: ['your bank', 'bank alert', 'suspected fraud', 'unusual activity'],
        criticalImitation: ['this is your bank', 'amazon security', 'google alert', 'facebook confirm', 'whatsapp security'],
        criticalDownload: ['download security update', 'install app', 'download cleaner', 'critical update', 'system scan'],
        criticalLegal: ['arrested warrant', 'narcotic drugs', 'cbi notice', 'cyber crime notice', 'customs clearance', 'parcel held', 'digital arrest', 'money laundering case'],
        criticalCollectRequest: ['collect request', 'sending you advance payment', 'accept the collect request', 'approve the payment request', 'refund of rs', 'cashback is pending'],
        criticalQR: ['scan this qr', 'scan the qr code', 'scan to receive', 'qr code to receive'],
        criticalRemoteAccess: ['anydesk', 'teamviewer', 'quicksupport', 'screen share', 'screen-sharing', 'remote access'],
        criticalSimSwap: ['sim card will be deactivated', 'sim swap', 'sim will be deactivated', 'port your number'],
        criticalLoanApp: ['loan app', 'processing fee', 'loan approved', 'emi overdue', 'release funds'],

        // ===== HINDI Romanized (Hinglish) =====
        hindiOTP: ['otp share karo', 'otp bhejo', 'apna otp do', 'otp share karen', 'otp batao'],
        hindiAccount: ['khata band ho jayega', 'aapka account suspend', 'account band karenge'],
        hindiPrize: ['aapne jeeta', 'inam jeeta', 'lottery jeeti', 'bada inam', 'cash prize mila'],
        hindiKYC: ['kyc update karo', 'aadhaar verify karo', 'pan card verify', 'kyc nahi hua'],
        hindiUrgent: ['turant karwai karo', 'abhi click karo', 'jaldi karo', 'tatkal sampark'],
        hindiLegal: ['police pak', 'cbi notice aya', 'arrest hoga', 'drugs pakray gaye', 'case darj'],

        // ===== HINDI Devanagari =====
        hindiDevOTP: ['ओटीपी शेयर करें', 'ओटीपी भेजें', 'अपना ओटीपी दें'],
        hindiDevPrize: ['आपने जीता', 'इनाम जीता', 'लॉटरी जीती', 'मुफ्त रिचार्ज'],
        hindiDevAccount: ['खाता बंद हो जाएगा', 'आपका खाता निलंबित'],

        // ===== TAMIL Romanized =====
        tamilOTP: ['otp pari', 'otp share pannunga', 'otp kudu'],
        tamilAccount: ['ungal account niruththapadum', 'account block aagidum'],
        tamilPrize: ['ilava parichu', 'vetri petriirkal', 'panam vandhuchu'],
        tamilLegal: ['ungal phone arrest aagum', 'police varum', 'cyber crime case'],

        // ===== TELUGU Romanized =====
        teluguOTP: ['otp pampandi', 'otp share cheyandi'],
        teluguAccount: ['mee khata nilipivestuundi', 'account close avutundi'],
        teluguPrize: ['uchita bahumati', 'meeru gelicharu', 'money vastundi'],

        // ===== BENGALI Romanized =====
        bengaliOTP: ['otp share korun', 'otp pathiye din'],
        bengaliAccount: ['apnar account bondho hobe', 'account block korbe'],
        bengaliPrize: ['binamullye puroshkar', 'apni jitechhen'],

        // ===== GUJARATI Romanized =====
        gujaratiOTP: ['otp share karo', 'tamaro otp apo'],
        gujaratiPrize: ['mafat inam', 'tame jitya'],

        // ===== MARATHI Romanized =====
        marathiOTP: ['otp share kara', 'tumcha otp sanga'],
        marathiPrize: ['mofat bakshis', 'tumhi jinklat'],

        // ===== ARABIC =====
        arabicOTP: ['شارك رمز otp', 'أرسل الرمز', 'otp شارك'],
        arabicAccount: ['حسابك سيُغلق', 'تم تعليق حسابك'],
        arabicPrize: ['جائزة مجانية', 'لقد فزت', 'يانصيب'],

        // ===== SPANISH =====
        spanishOTP: ['comparte tu otp', 'envia el codigo'],
        spanishPrize: ['has ganado', 'premio gratis', 'loteria'],

        // ===== FRENCH =====
        frenchOTP: ['partagez votre otp'],
        frenchPrize: ['vous avez gagne', 'prix gratuit', 'loterie']
    };
    
    let matchCount = 0;
    const matchedPatterns = [];
    const msgLower = message.toLowerCase();
    
    // Count how many training patterns match
    for (const [patternType, patterns] of Object.entries(trainingPatterns)) {
        for (const pattern of patterns) {
            if (msgLower.includes(pattern)) {
                matchCount++;
                matchedPatterns.push(patternType.replace('critical', ''));
                break; // Count each pattern type only once
            }
        }
    }
    
    // Only flag if multiple training patterns match (at least 2)
    // This ensures we only alert on messages similar to training data
    if (matchCount >= 2) {
        return {
            type: 'SCAM_DETECTED',
            status: 'scam',
            confidence: Math.min(0.7 + (matchCount * 0.1), 1.0),
            threats: matchedPatterns.slice(0, 3),
            matchesTrainingData: true
        };
    }
    
    // Single minor pattern match - flag as suspicious only if very specific
    if (matchCount === 1) {
        // Only certain types warrant suspicious flag alone
        const soloSuspiciousPatterns = ['OTP', 'Verify', 'Payment', 'Link', 'Bank', 'Imitation'];
        if (soloSuspiciousPatterns.some(p => matchedPatterns.some(m => m.includes(p)))) {
            return {
                type: 'SCAM_DETECTED',
                status: 'suspicious',
                confidence: 0.5,
                threats: matchedPatterns,
                matchesTrainingData: true
            };
        }
    }
    
    // Safe - no training patterns match or insufficient matches
    return {
        type: 'MESSAGE_SAFE',
        status: 'safe',
        confidence: 0.0,
        threats: [],
        matchesTrainingData: false
    };
}

