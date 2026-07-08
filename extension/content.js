/**
 * CYBER SHIELD - CONTENT SCRIPT
 * Automatically runs on websites
 * Monitors and detects scams in real-time
 */

let detectionEnabled = true;

// ============ MESSAGE DEDUPLICATION ============
// Tracks messages already scanned so the same message isn't re-checked
// every time WhatsApp's DOM updates (read receipts, timestamps, scroll, etc.)
let checkedMessageHashes = new Set();

function getMessageHash(text) {
    return text.trim().substring(0, 100); // simple text-based fingerprint
}

// Load detection status
chrome.storage.sync.get(['detectionEnabled'], (data) => {
    if (data.detectionEnabled !== undefined) {
        detectionEnabled = data.detectionEnabled;
    }
});

// Listen for settings changes
chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'sync' && changes.detectionEnabled) {
        detectionEnabled = changes.detectionEnabled.newValue;
    }
});

// Listen for alert messages from background
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'SHOW_WARNING') {
        showWarning(request);
        sendResponse({ received: true });
    }
});

// ============ AUTOMATIC MESSAGE MONITORING ============

// Wait for DOM to be ready before starting
console.log('🛡️ Cyber Shield Content Script loaded - waiting for DOM');

// Check if DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeMonitoring);
} else {
    // DOM is already ready
    setTimeout(initializeMonitoring, 500);
}

function initializeMonitoring() {
    console.log('🛡️ Initializing message monitoring');
    
    // Wait for body element to exist
    if (!document.body) {
        console.log('⏳ Body not ready yet, waiting...');
        setTimeout(initializeMonitoring, 500);
        return;
    }
    
    // Monitor WhatsApp Web
    monitorWhatsApp();
    
    // Monitor Gmail
    monitorGmail();
}

// ============ URL SCAM DETECTION ============

// Malicious URL patterns and shortened URL services commonly used in scams
const suspiciousUrlPatterns = {
    shortened: [
        'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly', 
        'short.link', 'short.cm', 'buff.ly', 'clck.ru',
        'is.gd', 'qr.net', 'spr.ly',
        't.me', 'tg.me', 'telegra.ph', 'telegram.dog',
        'trycloudflare.com', 'trycloudflare', '.trycloudflare.com'
    ],
    phishing: [
        'paypal-verify', 'amazon-secure', 'google-verify',
        'apple-id-verify', 'confirm-account', 'verify-identity',
        'update-payment', 'secure-login', 'account-confirm',
        'bank-security', 'verify-now', 'action-required'
    ],
    suspicious: [
        'click-here', 'claim-reward', 'get-free', 
        'verify-account', 'confirm-now', 'urgent-action',
        'limited-time', 'act-now', 'download-now'
    ],
    // Scam keywords found IN the domain name itself (e.g. free-recharge-jio.xyz)
    scamDomainKeywords: [
        'free-recharge', 'freerecharge', 'claim-prize', 'claimprice',
        'win-prize', 'winprize', 'lucky-draw', 'luckydraw',
        'cash-reward', 'cashreward', 'get-reward', 'getreward',
        'free-gift', 'freegift', 'earn-money', 'earnmoney',
        'aadhaar-verify', 'aadhaarverify', 'aadhaar-update',
        'kyc-update', 'kycupdate', 'otp-verify', 'otpverify',
        'bank-update', 'bankupdate', 'account-verify'
    ]
};

const BANK_CONTEXT_KEYWORDS = [
    'sbi', 'hdfc', 'icici', 'axis', 'boi', 'bank', 'bank account',
    'bank alert', 'credit card', 'debit card', 'netbanking', 'online banking',
    'upi', 'ifsc', 'atm', 'account locked', 'account suspended',
    'banking security', 'statement update', 'transaction alert', 'loan',
    'card details', 'account number'
];

const BANK_URL_CONTEXT_KEYWORDS = [
    'bank', 'hdfc', 'icici', 'sbi', 'axis', 'boi', 'netbanking',
    'upi', 'ifsc', 'creditcard', 'debitcard', 'banking', 'secure-login',
    'account-verify', 'bank-alert', 'bank-update', 'payment-gateway'
];

function isBankRelated(text) {
    const lower = text.toLowerCase();
    return BANK_CONTEXT_KEYWORDS.some(keyword => lower.includes(keyword));
}

function analyzeUrlsInMessage(messageText, element, platform) {
    // Extract URLs from message text
    const urlRegex = /(https?:\/\/[^\s]+|www\.[^\s]+|[a-zA-Z0-9.-]+\.(com|net|org|co|io|click|download|space|tk|ml|ga|cf|top|bid|win|date|faith|review|site|space|pw|info|biz)[\/\S]*)/gi;
    const urls = messageText.match(urlRegex) || [];
    
    // Also extract URLs from href attributes in element
    const linkElements = element.querySelectorAll('a[href]');
    linkElements.forEach(link => {
        const href = link.getAttribute('href');
        if (href) urls.push(href);
    });
    
    if (urls.length === 0) return false;
    
    // Check each URL for suspicious patterns
    let hasScamUrl = false;
    const detectedUrlThreats = [];
    
    urls.forEach(url => {
        const urlLower = url.toLowerCase();
        
        // Check shortened URL services
        for (const service of suspiciousUrlPatterns.shortened) {
            if (urlLower.includes(service)) {
                hasScamUrl = true;
                detectedUrlThreats.push(`Shortened URL: ${service}`);
                break;
            }
        }
        
        // Check for phishing patterns in URL
        for (const pattern of suspiciousUrlPatterns.phishing) {
            if (urlLower.includes(pattern)) {
                hasScamUrl = true;
                detectedUrlThreats.push(`Phishing URL pattern: ${pattern}`);
                break;
            }
        }

        // ⭐ NEW: Check for scam keywords embedded in domain name
        for (const keyword of suspiciousUrlPatterns.scamDomainKeywords) {
            if (urlLower.includes(keyword)) {
                hasScamUrl = true;
                detectedUrlThreats.push(`Scam domain keyword: ${keyword}`);
                break;
            }
        }
        
        // Check for suspicious subdomains/patterns
        if (/\b(verify|confirm|update|action|urgent|claim|secure|login|account)\b/i.test(url)) {
            if (/[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/.test(url) || 
                url.includes('-') && (url.split('/')[2] || '').includes('-verify')) {
                hasScamUrl = true;
                detectedUrlThreats.push('IP-based or suspicious domain URL');
            }
        }
    });
    
    const bankRelated = isBankRelated(messageText) || urls.some(url => BANK_URL_CONTEXT_KEYWORDS.some(k => url.toLowerCase().includes(k)));
    if (hasScamUrl && !bankRelated) {
        return false;
    }

    if (hasScamUrl) {
        console.log(`🔗 [${platform}] SCAM URL DETECTED:`, detectedUrlThreats);
        
        // Highlight the message with suspicious URL
        element.style.backgroundColor = 'rgba(255, 67, 67, 0.15)';
        element.style.borderLeft = '5px solid #FF4444';
        element.style.paddingLeft = '10px';
        element.setAttribute('data-url-warning', 'true');
        
        // Add URL threat badge
        addUrlBadge(element, detectedUrlThreats);
        
        // Show premium popup directly (no background.js roundtrip)
        showWarning({
            status: 'scam',
            confidence: 0.95,
            threats: detectedUrlThreats.slice(0, 3),
            messagePreview: messageText.substring(0, 80),
            isUrlScam: true
        });
        
        return true;
    }
    
    return false;
}

function addUrlBadge(element, threats) {
    if (element.querySelector('.url-threat-badge')) return;
    
    const badge = document.createElement('div');
    badge.className = 'url-threat-badge';
    badge.style.cssText = `
        position: absolute;
        top: 5px;
        right: 5px;
        background: #ff4444;
        color: white;
        padding: 5px 10px;
        border-radius: 4px;
        border: 2px solid #cc0000;
        font-size: 11px;
        font-weight: bold;
        z-index: 1000;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    `;
    badge.textContent = '🔗 SCAM URL';
    element.style.position = 'relative';
    element.appendChild(badge);
}

// ============ WHATSAPP WEB MONITORING ============

function monitorWhatsApp() {
    // Safety check: ensure document.body exists
    if (!document.body) {
        console.log('⚠ WhatsApp: document.body not ready');
        return;
    }
    
    try {
        // Monitor for message bubbles with multiple selector strategies
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) { // Element node
                        // Find new messages using multiple strategies for different WhatsApp Web versions
                        const messages = node.querySelectorAll(
                            '[data-testid="msg-container"], '
                            + '[data-testid="message"], '
                            + '[role="article"][data-testid], '
                            + '.message, '
                            + '[class*="message"]:not([class*="message-input"])'
                        );
                        messages.forEach(msg => {
                            analyzeMessage(msg, 'whatsapp');
                        });
                        
                        // Also check direct message elements — fix: wrap both conditions
                        if (node.classList && (node.classList.contains('message-in') || node.classList.contains('message-out'))) {
                            analyzeMessage(node, 'whatsapp');
                        }
                    }
                });
            });
        });

        // Start watching for new messages
        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        // Initial backward scan of existing messages (newest → oldest)
        setTimeout(() => scanChatHistory('whatsapp'), 150);
        
        // Detect when user opens a DIFFERENT chat — rescan history each time
        let lastChatTitle = '';
        setInterval(() => {
            // WhatsApp sets the chat title in the header when a chat is open
            const titleEl = document.querySelector('header [data-testid="conversation-header"] span[dir], header [title]');
            const currentTitle = titleEl ? (titleEl.textContent || titleEl.getAttribute('title') || '') : '';
            if (currentTitle && currentTitle !== lastChatTitle) {
                lastChatTitle = currentTitle;
                console.log(`💬 Chat switched to "${currentTitle}" — clearing cache and scanning...`);
                // ⭐ Clear hash cache so chat messages get re-scanned fresh
                checkedMessageHashes.clear();
                // Delay to let WhatsApp render all messages in new chat
                setTimeout(() => scanChatHistory('whatsapp'), 300);
            }
        }, 500); // 500ms poll = fast detection of chat switch
        
        // Periodically pick up newly arrived messages (new messages have no hash yet)
        setInterval(() => {
            const allMessages = document.querySelectorAll('[data-testid="msg-container"]');
            allMessages.forEach(msg => analyzeMessage(msg, 'whatsapp'));
        }, 1500);
        
        console.log('✓ WhatsApp Web monitoring started');
        
        // Show premium activated badge in top right corner
        injectActivatedBadge('whatsapp');
    } catch (error) {
        console.error('❌ WhatsApp monitoring error:', error);
    }
}

// ============ PREMIUM PRIORITY SCAN ENGINE ============
// Phase 1: Instant keyword check on ALL messages (synchronous, zero delay)
// Phase 2: ML check on last ~2hrs of messages (recent 40) in fast batches
// Phase 3: ML check on older messages in slower batches
function scanChatHistory(platform) {
    const selectors = platform === 'whatsapp'
        ? '[data-testid="msg-container"], [role="article"][data-testid], .message.message-in, .message.message-out'
        : '[role="main"] [role="article"]';

    const messages = Array.from(document.querySelectorAll(selectors));
    if (messages.length === 0) {
        console.log(`\ud83d\udd0d [${platform}] No messages in DOM yet — will retry`);
        return;
    }

    // Newest first
    const newest = messages.slice().reverse();
    console.log(`\u26a1 [${platform}] Priority scan: ${newest.length} messages (newest \u2192 oldest)`);

    // ---- PHASE 1: INSTANT keyword check on everything (no network, zero delay) ----
    // Show popup for the FIRST scam found (don't spam)
    let popupShownThisScan = false;
    newest.forEach(msg => {
        // Skip if already shown a badge for this message content (prevents re-badging on same DOM node)
        if (msg.hasAttribute('data-scam-warning')) return;

        const text = extractText(msg, platform);
        if (!text || text.trim().length <= 3) return;
        const instant = instantKeywordCheck(text);
        if (instant !== 'safe') {
            msg.style.backgroundColor = instant === 'scam' ? 'rgba(255,67,67,0.15)' : 'rgba(255,193,7,0.15)';
            msg.style.borderLeft = `5px solid ${instant === 'scam' ? '#FF4444' : '#FF9800'}`;
            msg.style.paddingLeft = '10px';
            msg.setAttribute('data-scam-warning', 'true');
            addBadge(msg, instant);
            console.log(`⚡ INSTANT [${platform}]: ${instant.toUpperCase()} — "${text.substring(0,50)}"`);
            
            // ⭐ Show premium popup for the first scam/suspicious found
            if (!popupShownThisScan) {
                popupShownThisScan = true;
                showWarning({
                    status: instant,
                    confidence: instant === 'scam' ? 0.85 : 0.55,
                    threats: extractInstantThreats(text),
                    messagePreview: text.substring(0, 80),
                    isUrlScam: false
                });
            }
        }
    });

    // ---- PHASE 2: ML scan on RECENT messages (last ~40 = approx 2 hrs) in fast batches ----
    const recent  = newest.slice(0, 40);   // newest 40 messages
    const older   = newest.slice(40);       // everything else

    sendBatchToML(recent, platform, 50);    // 50ms between batches (fast)

    // ---- PHASE 3: ML scan on OLDER messages in slower batches (don't block UI) ----
    // Delay Phase 3 start until Phase 2 is well underway
    setTimeout(() => sendBatchToML(older, platform, 200), recent.length * 55);
}

// Send messages to ML in batches of 5, with `gapMs` between each batch
function sendBatchToML(messages, platform, gapMs) {
    const BATCH = 5;
    let i = 0;
    function processNext() {
        const slice = messages.slice(i, i + BATCH);
        if (slice.length === 0) return;
        slice.forEach(msg => analyzeMessage(msg, platform));
        i += BATCH;
        if (i < messages.length) setTimeout(processNext, gapMs);
    }
    processNext();
}

// ============ GMAIL MONITORING ============

function monitorGmail() {
    // Safety check: ensure document.body exists
    if (!document.body) {
        console.log('⚠ Gmail: document.body not ready');
        return;
    }
    
    try {
        const observer = new MutationObserver((mutations) => {
            mutations.forEach((mutation) => {
                mutation.addedNodes.forEach((node) => {
                    if (node.nodeType === 1) {
                        // Find new emails
                        const emails = node.querySelectorAll('[role="main"] [role="article"], [data-message-id]');
                        emails.forEach(email => {
                            analyzeMessage(email, 'gmail');
                        });
                    }
                });
            });
        });

        observer.observe(document.body, {
            childList: true,
            subtree: true
        });

        // Check existing emails (backward from newest)
        setTimeout(() => scanChatHistory('gmail'), 2000);
        
        console.log('✓ Gmail monitoring started');
        
        // Show premium activated badge in top right corner
        injectActivatedBadge('gmail');
    } catch (error) {
        console.error('❌ Gmail monitoring error:', error);
    }
}

// ============ MESSAGE ANALYSIS ============

// ============ INSTANT KEYWORD PRE-SCANNER ============
// Runs synchronously before ML — gives immediate visual feedback
// ⭐ MULTILINGUAL SCAM DATABASE — 15+ languages
const INSTANT_TRIGGERS = {
    scam: [
        // ===== ENGLISH =====
        'verify your otp', 'send otp', 'share otp', 'enter otp', 'one time password',
        'send your otp', 'forward otp', 'otp immediately', 'otp now',
        'verify account', 'confirm identity', 'account suspended', 'account locked',
        'account will be suspended', 'account compromised', 'unusual login', 'unusual activity',
        'bank account', 'cvv', 'credit card details', 'your bank', 'bank alert',
        'bank account number', 'update payment', 'billing information',
        'bit.ly', 'tinyurl', 'goo.gl', 'free-recharge', 'freerecharge',
        'aadhaar-verify', 'aadhaar-update', 'kyc-update', 'claim prize',
        'free-recharge-jio', 'recharge-jio', 'http://free',
        'whatsapp security', 'amazon security', 'google alert',
        'facebook confirm',
        'congratulations won', 'claim prize', 'lottery', 'grand prize', 'lucky draw',
        'you have won', 'cash reward', 'free gift',
        'install app', 'download security update', 'download app', '.apk',
        'your account will be blocked', 'reset your password immediately',
        'click link below', 'your kyc is pending', 'aadhaar link',
        'pan card verify', 'income tax refund', 'emi overdue', 'loan approved',
        'insurance expired', 'policy lapsed', 'customs clearance', 'parcel held',
        'arrested warrant', 'narcotic drugs', 'cbi notice', 'cyber crime notice',

        // ===== HINDI (Devanagari script) =====
        'ओटीपी शेयर करें', 'ओटीपी भेजें', 'अपना ओटीपी दें', 'खाता बंद हो जाएगा',
        'आपका खाता निलंबित', 'तुरंत कार्रवाई करें', 'बैंक खाता', 'क्रेडिट कार्ड',
        'आपने जीता', 'इनाम जीता', 'लॉटरी जीती', 'मुफ्त रिचार्ज', 'कैश बैक',
        'केवाईसी अपडेट', 'आधार वेरीफाई', 'पैन कार्ड', 'आयकर रिफंड',
        'तत्काल सत्यापन', 'लिंक पर क्लिक करें', 'ऐप डाउनलोड करें',
        'आपका खाता हैक', 'संदिग्ध गतिविधि', 'बैंक अलर्ट', 'फ्री गिफ्ट',
        'बड़ा इनाम', 'ईएमआई बकाया', 'लोन मंजूर', 'बीमा समाप्त',

        // ===== HINDI (Romanized / Hinglish) =====
        'otp share karo', 'otp bhejo', 'apna otp do', 'khata band ho jayega',
        'aapka account suspend', 'turant karwai karo', 'bank khata', 'credit card',
        'aapne jeeta', 'inam jeeta', 'lottery jeeti', 'free recharge', 'cash back',
        'kyc update karo', 'aadhaar verify karo', 'pan card', 'aaykar refund',
        'tatkal satyapan', 'link par click karo', 'app download karo',
        'aapka khata hack', 'sandigdh gatividhi', 'bank alert', 'free gift pai',
        'bada inam', 'emi bakaya', 'loan manjur', 'bima samapt',
        'apna password share karo', 'paytm kyc', 'google pay scam',
        'police pak', 'cbi notice aya', 'arrest hoga', 'drugs pakray gaye',

        // ===== TAMIL (Tamil script) =====
        'ஓடிபி பகிர்', 'உங்கள் கணக்கு நிறுத்தப்படும்', 'இலவச பரிசு',
        'வெற்றி பெற்றீர்கள்', 'லாட்டரி', 'கேஒய்சி புதுப்பி', 'ஆதார் சரிபார்',
        'வங்கி கணக்கு', 'கிரெடிட் கார்டு விவரம்', 'உடனடி நடவடிக்கை',
        'இணைப்பை கிளிக்', 'ஆப் பதிவிறக்கம்', 'பணம் வந்தது', 'சந்தேகமான செயல்',

        // ===== TAMIL (Romanized) =====
        'otp pari', 'ungal account niruththapadum', 'ilava parichu',
        'vetri petriirkal', 'lottery', 'kyc puduppi', 'aadhaar sarippaar',
        'vangi kanakku', 'credit card vivaram', 'udanadi nadavatikkai',
        'inaippai click', 'app pathivirakkam', 'panam vandhuthu', 'sandegamaana seyal',
        'ungal phone arrest aagum', 'police varum', 'cyber crime case',

        // ===== TELUGU (Telugu script) =====
        'ఓటీపీ పంపండి', 'మీ ఖాతా నిలిపివేయబడుతుంది', 'ఉచిత బహుమతి',
        'మీరు గెలిచారు', 'లాటరీ', 'కేవైసీ నవీకరించండి', 'ఆధార్ ధృవీకరించండి',
        'బ్యాంక్ ఖాతా', 'క్రెడిట్ కార్డ్', 'తక్షణ చర్య',
        'లింక్ క్లిక్ చేయండి', 'యాప్ డౌన్లోడ్',

        // ===== TELUGU (Romanized) =====
        'otp pampandi', 'mee khata nilipivestuundi', 'uchita bahumati',
        'meeru gelicharu', 'lottery', 'kyc naveekarinchandi', 'aadhaar dhruveekarinchandi',
        'bank khata', 'credit card', 'takshaņa charyaga',
        'link click cheyandi', 'app download cheyandi',

        // ===== BENGALI (Bengali script) =====
        'ওটিপি শেয়ার করুন', 'আপনার অ্যাকাউন্ট বন্ধ হবে', 'বিনামূল্যে পুরস্কার',
        'আপনি জিতেছেন', 'লটারি', 'কেওয়াইসি আপডেট', 'আধার যাচাই',
        'ব্যাংক অ্যাকাউন্ট', 'ক্রেডিট কার্ড', 'এখনই ক্লিক করুন',

        // ===== BENGALI (Romanized) =====
        'otp share korun', 'apnar account bondho hobe', 'binamullye puroshkar',
        'apni jitechhen', 'lottery', 'kyc update korun', 'aadhaar jachai',
        'bank account', 'credit card', 'ekhoni click korun',

        // ===== MARATHI (Devanagari script) =====
        'ओटीपी शेअर करा', 'तुमचे खाते निलंबित होईल', 'मोफत बक्षीस',
        'तुम्ही जिंकलात', 'लॉटरी', 'केवायसी अपडेट', 'आधार पडताळणी',
        'बँक खाते', 'क्रेडिट कार्ड', 'ताबडतोब क्लिक करा',

        // ===== MARATHI (Romanized) =====
        'otp share kara', 'tumche khate nilambit hoil', 'mofat bakshis',
        'tumhi jinklat', 'lottery', 'kyc update kara', 'aadhaar padtalni',
        'bank khate', 'credit card', 'tabadtob click kara',

        // ===== GUJARATI (Gujarati script) =====
        'ઓટીપી શેર કરો', 'તમારું ખાતું બ્લૉક થઈ જશે', 'મફત ઇનામ',
        'તમે જીત્યા', 'લોટરી', 'કેવાયસી અપડેટ', 'આધાર ચકાસો',
        'બેંક ખાતું', 'ક્રેડિટ કાર્ડ',

        // ===== GUJARATI (Romanized) =====
        'otp share karo', 'tamaru khatu block thai jashe', 'mafat inam',
        'tame jitya', 'lottery', 'kyc update karo', 'aadhaar chakaso',
        'bank khatu', 'credit card',

        // ===== KANNADA (Kannada script) =====
        'ಓಟಿಪಿ ಹಂಚಿಕೊಳ್ಳಿ', 'ನಿಮ್ಮ ಖಾತೆ ಬ್ಲಾಕ್', 'ಉಚಿತ ಬಹುಮಾನ',
        'ನೀವು ಗೆದ್ದಿದ್ದೀರಿ', 'ಲಾಟರಿ', 'ಕೆವೈಸಿ ನವೀಕರಿಸಿ',

        // ===== KANNADA (Romanized) =====
        'otp hanchikollali', 'nimma khate block', 'uchita bahumana',
        'neevu geddiddeeri', 'lottery', 'kyc naveekari',

        // ===== MALAYALAM (Malayalam script) =====
        'ഒടിപി പങ്കിടുക', 'നിങ്ങളുടെ അക്കൗണ്ട് ബ്ലോക്ക്', 'സൗജന്യ സമ്മാനം',
        'നിങ്ങൾ ജയിച്ചു', 'ലോട്ടറി', 'കെവൈസി അപ്ഡേറ്റ്',

        // ===== MALAYALAM (Romanized) =====
        'otp pangidam', 'ningalude account block', 'soujanya sammanam',
        'ningal jayichu', 'lottery', 'kyc update cheyyuka',

        // ===== PUNJABI (Gurmukhi script) =====
        'ਓਟੀਪੀ ਸਾਂਝਾ ਕਰੋ', 'ਤੁਹਾਡਾ ਖਾਤਾ ਬੰਦ', 'ਮੁਫ਼ਤ ਇਨਾਮ',
        'ਤੁਸੀਂ ਜਿੱਤੇ', 'ਲਾਟਰੀ',

        // ===== PUNJABI (Romanized) =====
        'otp sanjha karo', 'tuhada khata band', 'muft inam',
        'tusi jitte', 'lottery',

        // ===== URDU (Romanized — commonly used in India/Pakistan) =====
        'otp share karen', 'apka account band ho jayega', 'muft inam',
        'aapne jeeta', 'lottery', 'kyc tajdeed karen', 'aadhaar tasteeq',
        'bank account', 'credit card', 'abhi click karen',
        'police arrest karegi', 'drugs pakri gai', 'case darj',

        // ===== ARABIC =====
        'شارك رمز otp', 'حسابك سيُغلق', 'جائزة مجانية', 'لقد فزت',
        'يانصيب', 'انقر على الرابط', 'تنزيل التطبيق', 'تحقق من الهوية',
        'تحديث بيانات البنك', 'نشاط مشبوه',

        // ===== SPANISH =====
        'comparte tu otp', 'tu cuenta sera suspendida', 'premio gratis',
        'has ganado', 'loteria', 'haz clic aqui', 'descarga la app',
        'verificacion de cuenta', 'actividad sospechosa',

        // ===== FRENCH =====
        'partagez votre otp', 'votre compte sera suspendu', 'prix gratuit',
        'vous avez gagne', 'loterie', 'cliquez ici', 'telecharger application',
        'verification de compte', 'activite suspecte',

        // ===== CHINESE (Simplified — common online scam phrases) =====
        '分享您的验证码', '您的账户将被封禁', '免费奖品', '您赢了',
        '点击链接', '下载应用', '账户验证', '可疑活动',

        // ===== RUSSIAN =====
        'поделитесь кодом otp', 'ваш аккаунт будет заблокирован',
        'бесплатный приз', 'вы выиграли', 'нажмите на ссылку',
        'скачать приложение', 'подозрительная активность'
    ],
    suspicious: [
        // ===== ENGLISH =====
        'click here', 'urgent', 'immediately', 'limited time', 'act now',
        'verify', 'update payment', 'billing', 'confirm', 'suspicious',
        'recharge', 'claim', 'reward', 'prize', 'free offer',
        'you are selected', 'exclusive offer', 'don\'t share this',
        'do not tell anyone', 'keep this secret', 'this is confidential',
        'government notice', 'tax department', 'court notice',
        'help me transfer', 'investment opportunity', 'double your money',
        'bitcoin wallet', 'crypto investment', 'guaranteed returns',

        // ===== HINDI (Romanized) =====
        'jaldi karo', 'abhi click karo', 'sirf aaj ke liye', 'seedha sambandh karo',
        'kisi ko mat batao', 'yeh secret hai', 'free paisa', 'jaldi se',
        'sarkari notice', 'tax vibhag', 'court notice', 'guarantee return',
        'paise double', 'bitcoin', 'crypto',

        // ===== HINDI (Devanagari) =====
        'जल्दी करो', 'अभी क्लिक करो', 'किसी को मत बताओ', 'यह गुप्त है',
        'मुफ्त पैसा', 'सरकारी नोटिस', 'पैसे दोगुना', 'गारंटी रिटर्न',

        // ===== TAMIL (Romanized) =====
        'sigram seyya vendum', 'yarukkum solladhey', 'idhuvai rakasiamaa vaikkavum',
        'free panam', 'sarkaar notice', 'udan seyya vendum',

        // ===== TELUGU (Romanized) =====
        'veganga cheyandi', 'evvarikee cheppakandi', 'idhi rahasyam',
        'free money', 'government notice', 'guarantee return',

        // ===== ARABIC =====
        'اتصل بنا الآن', 'عرض محدود', 'لا تخبر أحداً', 'مجاني',
        'اضغط هنا', 'عاجل',

        // ===== SPANISH =====
        'llame ahora', 'oferta limitada', 'no le digas a nadie',
        'gratis', 'haga clic', 'urgente',

        // ===== FRENCH =====
        'appelez maintenant', 'offre limitee', 'ne dites a personne',
        'gratuit', 'cliquez', 'urgent',

        // ===== RUSSIAN =====
        'позвони сейчас', 'ограниченное предложение', 'не говори никому',
        'бесплатно', 'нажмите', 'срочно'
    ]
};

function instantKeywordCheck(text) {
    const lower = text.toLowerCase();
    if (!isBankRelated(text)) return 'safe';
    if (INSTANT_TRIGGERS.scam.some(k => lower.includes(k))) return 'scam';
    if (INSTANT_TRIGGERS.suspicious.some(k => lower.includes(k))) return 'suspicious';
    return 'safe';
}

function analyzeMessage(element, platform) {
    if (!element || !detectionEnabled) return;

    // Extract message text based on platform
    let messageText = extractText(element, platform);
    
    if (messageText && messageText.trim().length > 3) {
        // ⭐ DEDUP CHECK — skip if this exact message was already scanned
        const msgHash = getMessageHash(messageText);
        if (checkedMessageHashes.has(msgHash)) {
            return; // already checked this message, do nothing
        }
        checkedMessageHashes.add(msgHash);

        // Safety: cap the cache so it never grows unbounded in long sessions
        if (checkedMessageHashes.size > 5000) {
            checkedMessageHashes.clear();
        }

        console.log(`[${platform}] Found message: "${messageText.substring(0, 50)}..."`);
        
        // ⚡ INSTANT PRE-CHECK — runs synchronously with zero network delay
        const instantResult = instantKeywordCheck(messageText);
        let instantFired = false; // track if popup was already shown
        if (instantResult !== 'safe') {
            console.log(`⚡ [${platform}] INSTANT DETECTION: ${instantResult}`);
            element.style.backgroundColor = instantResult === 'scam' ? 'rgba(255, 67, 67, 0.15)' : 'rgba(255, 193, 7, 0.15)';
            element.style.borderLeft = `5px solid ${instantResult === 'scam' ? '#FF4444' : '#FF9800'}`;
            element.style.paddingLeft = '10px';
            element.setAttribute('data-scam-warning', 'true');
            addBadge(element, instantResult);
            instantFired = true;
            
            // ✅ Show popup immediately from instant check
            showWarning({
                status: instantResult,
                confidence: instantResult === 'scam' ? 0.85 : 0.55,
                threats: extractInstantThreats(messageText),
                messagePreview: messageText.substring(0, 80),
                isUrlScam: false
            });
        }
        
        // Check for scam URLs (works independently — has its own showWarning call)
        const hasScamUrl = analyzeUrlsInMessage(messageText, element, platform);
        
        // Also send to ML for higher-accuracy check (runs in background)
        chrome.runtime.sendMessage({
            type: 'CHECK_SCAM',
            text: messageText,
            platform: platform
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.log('Background not ready');
                return;
            }

            if (response && response.type === 'SCAM_DETECTED') {
                console.log(`⚠️ [${platform}] ML SCAM DETECTED:`, response);
                
                // Upgrade highlight
                element.style.backgroundColor = 'rgba(255, 67, 67, 0.15)';
                element.style.borderLeft = '5px solid #FF4444';
                element.style.paddingLeft = '10px';
                element.setAttribute('data-scam-warning', 'true');
                
                // Add/upgrade badge
                const existingBadge = element.querySelector('.cyber-shield-badge');
                if (existingBadge) existingBadge.remove();
                addBadge(element, response.status);
                
                // Only show ML popup if instant check didn't already fire one
                // (avoids double popup on same message)
                if (!instantFired) {
                    showWarning({
                        status: response.status,
                        confidence: response.confidence,
                        threats: response.threats || [],
                        messagePreview: messageText.substring(0, 80),
                        isUrlScam: false
                    });
                }
            }
        });
    }
}

// Extract which specific keywords triggered the instant scan
function extractInstantThreats(text) {
    const lower = text.toLowerCase();
    const found = [];
    const categories = {
        'OTP Request':      ['send otp', 'share otp', 'enter otp', 'otp immediately', 'otp now', 'forward otp', 'one time password'],
        'Account Attack':   ['account suspended', 'account locked', 'account compromised', 'unusual login', 'unusual activity'],
        'Financial Scam':   ['bank account', 'cvv', 'credit card', 'billing information', 'update payment'],
        'Prize Scam':       ['congratulations won', 'claim prize', 'lottery', 'grand prize', 'lucky draw', 'cash reward', 'you have won'],
        'Phishing URL':     ['bit.ly', 'tinyurl', 'goo.gl', 'free-recharge', 'aadhaar-verify', 'kyc-update', 'http://free'],
        'Impersonation':    ['whatsapp security', 'amazon security', 'google alert', 'facebook confirm'],
        'Malware':          ['install app', 'download security', 'download app', '.apk']
    };
    for (const [label, keywords] of Object.entries(categories)) {
        if (keywords.some(k => lower.includes(k))) found.push(label);
    }
    return found.length ? found : ['Suspicious keyword pattern detected'];
}

// Extract text from message element
function extractText(element, platform) {
    let text = '';

    if (platform === 'whatsapp') {
        // Try WhatsApp selectors (multiple strategies for different versions)
        const selectors = [
            '[class*="selectable-text"]',
            '[data-testid="msg-text"]',
            'span[dir="auto"][style*="word-wrap"]',
            '.selectable-text',
            '[role="img"][alt]',  // For images with alt text
            '.copyable-text'
        ];
        for (let selector of selectors) {
            const el = element.querySelector(selector);
            if (el) {
                text = el.innerText || el.textContent || el.alt || el.getAttribute('aria-label');
                if (text && text.trim().length > 2) break;
            }
        }
        // Fallback: extract all text from the message container
        if (!text) {
            text = element.innerText;
        }
        
        // Also check for URLs that might be in href attributes
        const links = element.querySelectorAll('a[href]');
        if (links.length > 0 && text.length < 10) {
            text = Array.from(links).map(l => l.href).join(' ') + ' ' + (text || '');
        }
    }
    else if (platform === 'gmail') {
        // Try Gmail selectors
        const selectors = ['[role="main"] [data-tooltip]', '.iT [dir="auto"]'];
        for (let selector of selectors) {
            const el = element.querySelector(selector);
            if (el) {
                text = el.innerText || el.textContent;
                if (text && text.trim().length > 3) break;
            }
        }
        if (!text) text = element.innerText;
    }


    // Clean up text
    text = text.trim().replace(/\n+/g, ' ').substring(0, 500);
    return text;
}

// Add warning badge to suspicious message
function addBadge(element, status) {
    if (element.querySelector('.cyber-shield-badge')) return;

    const badge = document.createElement('div');
    badge.className = 'cyber-shield-badge';
    const bgColor = status === 'scam' ? '#ff4444' : '#ff9800';
    const borderColor = status === 'scam' ? '#cc0000' : '#ff6600';
    const label = status === 'scam' ? '⚠️ SCAM' : '⚠️ SUSPICIOUS';
    
    badge.style.cssText = `
        position: absolute;
        top: 5px;
        right: 5px;
        background: ${bgColor};
        color: white;
        padding: 5px 10px;
        border-radius: 4px;
        border: 2px solid ${borderColor};
        font-size: 11px;
        font-weight: bold;
        z-index: 1000;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    `;
    badge.textContent = label;
    element.style.position = 'relative';
    element.appendChild(badge);
}

// ============ WARNING POPUP ALERT ============

// Track if a warning is currently showing (only one at a time, stays until dismissed or refresh)
let warningActive = false;

function showWarning(data) {
    // If a warning is already showing, don't replace it — let user read and dismiss first
    // (except: if the new one is a scam and the old one is just suspicious, upgrade it)
    const existing = document.getElementById('cyberShieldAlert');
    const newIsScam = data.status === 'scam' || data.isUrlScam === true;
    if (existing && warningActive) {
        const existingIsScam = existing.getAttribute('data-threat-level') === 'scam';
        if (existingIsScam || !newIsScam) return; // Keep existing unless upgrading to scam
        existing.remove();
    }

    warningActive = true;

    const isUrlScam   = data.isUrlScam === true;
    const isScam      = data.status === 'scam' || isUrlScam;
    const riskScore   = Math.round((data.confidence || 0) * 100);
    const threats     = data.threats || [];
    const msgPreview  = (data.messagePreview || '').substring(0, 80);

    const accentColor  = isScam ? '#ff4444' : '#ffb300';
    const accentGlow   = isScam ? 'rgba(255,68,68,0.4)' : 'rgba(255,179,0,0.4)';
    const accentDim    = isScam ? 'rgba(255,68,68,0.10)' : 'rgba(255,179,0,0.10)';
    const accentMid    = isScam ? 'rgba(255,68,68,0.22)' : 'rgba(255,179,0,0.22)';
    const badgeLabel   = isUrlScam ? 'MALICIOUS URL' : (isScam ? 'SCAM DETECTED' : 'SUSPICIOUS MESSAGE');
    const badgeIcon    = isUrlScam ? '🔗' : (isScam ? '🚨' : '⚠️');
    const typeLabel    = isUrlScam ? 'Malicious URL' : (isScam ? 'Scam' : 'Suspicious');

    const guidance = isUrlScam ? [
        { icon: '🚫', text: 'Do <strong>NOT</strong> click any link in this message' },
        { icon: '🗑️', text: 'Delete the message and <strong>block the sender</strong>' },
        { icon: '🚨', text: 'Report this chat to <strong>WhatsApp / platform support</strong>' }
    ] : isScam ? [
        { icon: '🔒', text: '<strong>Never share OTPs, passwords or bank details</strong> with anyone' },
        { icon: '📵', text: 'Cut contact — <strong>block and report</strong> the sender immediately' },
        { icon: '🏦', text: 'If you shared anything sensitive, <strong>contact your bank now</strong>' }
    ] : [
        { icon: '👀', text: 'Verify the sender\'s identity <strong>through a known channel</strong> first' },
        { icon: '⏸️', text: 'Do <strong>not act urgently</strong> — scammers rely on panic and time pressure' },
        { icon: '🔍', text: 'Search the exact message text online to check for <strong>known scam patterns</strong>' }
    ];

    const threatRows = threats.length
        ? threats.map(t => `
            <div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:1px solid rgba(255,255,255,0.05);">
                <span style="color:${accentColor};font-size:11px;flex-shrink:0;">▶</span>
                <span style="color:#ccd6f6;font-size:12px;">${t}</span>
            </div>`).join('')
        : `<div style="color:#8892b0;font-size:12px;padding:4px 0;">Pattern-based keyword match</div>`;

    const previewHtml = msgPreview
        ? `<div style="margin:10px 0;padding:8px 12px;background:rgba(255,255,255,0.04);border-left:3px solid ${accentColor};border-radius:4px;font-size:12px;color:#8892b0;font-family:'Consolas',monospace;word-break:break-word;line-height:1.5;">"${msgPreview}${msgPreview.length >= 80 ? '…' : ''}"</div>`
        : '';

    const guidanceHtml = guidance.map(g =>
        `<div style="display:flex;align-items:flex-start;gap:10px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
            <span style="font-size:15px;flex-shrink:0;margin-top:1px;">${g.icon}</span>
            <span style="font-size:12px;color:#ccd6f6;line-height:1.5;">${g.text}</span>
        </div>`
    ).join('');

    const popup = document.createElement('div');
    popup.id = 'cyberShieldAlert';
    popup.setAttribute('data-threat-level', isScam ? 'scam' : 'suspicious');

    // Always replace keyframe styles so dynamic values (riskScore, colors) are fresh
    const styleId = 'cs-popup-keyframes';
    const existingStyle = document.getElementById(styleId);
    if (existingStyle) existingStyle.remove();
    {
        const s = document.createElement('style');
        s.id = styleId;
        s.textContent = `
            @keyframes cs-popup-enter {
                0%   { transform: translateX(420px) scale(0.92); opacity: 0; }
                60%  { transform: translateX(-8px) scale(1.01); opacity: 1; }
                80%  { transform: translateX(4px) scale(0.99); }
                100% { transform: translateX(0) scale(1); opacity: 1; }
            }
            @keyframes cs-riskbar {
                from { width: 0%; }
                to   { width: ${riskScore}%; }
            }
            @keyframes cs-border-pulse {
                0%, 100% { box-shadow: 0 20px 60px rgba(0,0,0,0.7), 0 0 20px ${accentGlow}; }
                50%       { box-shadow: 0 20px 60px rgba(0,0,0,0.7), 0 0 55px ${accentGlow}; }
            }
            @keyframes cs-scan-beam {
                0%   { top: 0%; opacity: 0.7; }
                100% { top: 110%; opacity: 0; }
            }
            @keyframes cs-icon-pulse {
                0%, 100% { transform: scale(1); box-shadow: 0 0 10px ${accentGlow}; }
                50%       { transform: scale(1.12); box-shadow: 0 0 22px ${accentGlow}; }
            }
            @keyframes cs-top-bar-scan {
                0%   { background-position: -400px 0; }
                100% { background-position: 400px 0; }
            }
            #cyberShieldAlert {
                position: fixed;
                bottom: 22px;
                right: 22px;
                width: 370px;
                z-index: 2147483647;
                font-family: 'Segoe UI', 'Consolas', system-ui, sans-serif;
                animation: cs-popup-enter 0.5s cubic-bezier(0.22,1,0.36,1) forwards,
                           cs-border-pulse 3s ease-in-out 0.6s infinite;
                background: linear-gradient(160deg, rgba(6,14,30,0.98) 0%, rgba(9,18,40,0.98) 100%);
                backdrop-filter: blur(22px);
                -webkit-backdrop-filter: blur(22px);
                border: 1.5px solid ${accentColor};
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.7), 0 0 30px ${accentGlow};
                overflow: hidden;
            }
            #cyberShieldAlert:hover {
                animation-play-state: paused;
            }
            #cs-close-alert:hover { background: rgba(255,255,255,0.12) !important; color: #fff !important; }
            #cs-dismiss-alert:hover {
                background: ${accentColor} !important;
                color: #000 !important;
                transform: translateY(-1px);
                box-shadow: 0 4px 20px ${accentGlow};
            }
        `;
        document.head.appendChild(s);
    }

    popup.innerHTML = `
        <!-- Animated top bar -->
        <div style="
            height: 4px;
            background: linear-gradient(90deg, ${accentColor}, #7b2ff7, #00b8ff, ${accentColor});
            background-size: 200% 100%;
            animation: cs-top-bar-scan 2.5s linear infinite;
            position: relative;
        "></div>

        <!-- Scan beam overlay -->
        <div style="
            position:absolute; left:0; right:0; height:40px;
            background:linear-gradient(to bottom, transparent, ${accentColor}18, transparent);
            animation: cs-scan-beam 2.5s ease-in-out 0.5s 3;
            pointer-events:none; z-index:1;
        "></div>

        <div style="padding:18px 18px 16px; position:relative; z-index:2;">

            <!-- Header row -->
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:16px;">
                <div style="display:flex;align-items:center;gap:12px;">
                    <!-- Animated icon -->
                    <div style="
                        width:42px;height:42px;border-radius:10px;
                        background:${accentDim};border:1.5px solid ${accentColor};
                        display:flex;align-items:center;justify-content:center;font-size:22px;
                        animation: cs-icon-pulse 2.5s ease-in-out infinite;
                        flex-shrink:0;
                    ">${badgeIcon}</div>
                    <div>
                        <div style="font-size:14px;font-weight:900;color:${accentColor};letter-spacing:1px;text-transform:uppercase;">${badgeLabel}</div>
                        <div style="font-size:10px;color:#5a6a8a;letter-spacing:1.5px;text-transform:uppercase;margin-top:2px;">
                            <span style="color:#00ff88;">●</span>&nbsp;CyberShield AI &middot; ${typeLabel} Alert
                        </div>
                    </div>
                </div>
                <!-- Close button -->
                <button id="cs-close-alert" style="
                    background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);
                    color:#6a7a9a;width:30px;height:30px;border-radius:8px;
                    cursor:pointer;font-size:18px;line-height:1;
                    display:flex;align-items:center;justify-content:center;
                    transition:all 0.2s;flex-shrink:0;
                ">&times;</button>
            </div>

            <!-- Risk Score Bar -->
            <div style="margin-bottom:14px;">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <span style="font-size:10px;color:#5a6a8a;letter-spacing:1.5px;text-transform:uppercase;">AI Risk Score</span>
                    <span style="font-size:13px;font-weight:800;color:${accentColor};">${riskScore}<span style="font-size:9px;color:#5a6a8a;">/100</span></span>
                </div>
                <div style="height:7px;background:rgba(255,255,255,0.06);border-radius:99px;overflow:hidden;position:relative;">
                    <div style="
                        height:100%;width:${riskScore}%;
                        background:linear-gradient(90deg,${isScam ? '#ff7700,#ff4444,#ff0055' : '#ffd200,#ffb300,#ff8c00'});
                        border-radius:99px;
                        box-shadow:0 0 10px ${accentColor};
                        animation:cs-riskbar 1.1s cubic-bezier(0.22,1,0.36,1) forwards;
                    "></div>
                </div>
            </div>

            <!-- Message preview -->
            ${previewHtml}

            <!-- Detected threats -->
            <div style="background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);border-radius:10px;padding:10px 12px;margin-bottom:12px;">
                <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:#5a6a8a;margin-bottom:6px;">🔎 Detected Signals</div>
                ${threatRows}
            </div>

            <!-- Guidance -->
            <div style="background:${accentDim};border:1px solid ${accentColor}44;border-radius:10px;padding:10px 12px;margin-bottom:16px;">
                <div style="font-size:10px;letter-spacing:1.5px;text-transform:uppercase;color:${accentColor};margin-bottom:4px;font-weight:700;">⚡ What To Do Now</div>
                ${guidanceHtml}
            </div>

            <!-- Footer CTAs -->
            <div style="display:flex;gap:8px;margin-bottom:0;">
                <button id="cs-dismiss-alert" style="
                    flex:1;padding:11px 8px;
                    background:linear-gradient(135deg,${accentMid},${accentDim});
                    border:1.5px solid ${accentColor};border-radius:10px;
                    color:${accentColor};font-weight:800;font-size:12px;
                    cursor:pointer;letter-spacing:0.6px;text-transform:uppercase;
                    transition:all 0.25s;
                ">🛡️ Got it</button>
                <button id="cs-helpline-btn" style="
                    flex:1;padding:11px 8px;
                    background:linear-gradient(135deg,rgba(220,38,38,0.25),rgba(220,38,38,0.10));
                    border:1.5px solid #dc2626;border-radius:10px;
                    color:#ff6b6b;font-weight:800;font-size:12px;
                    cursor:pointer;letter-spacing:0.4px;text-transform:uppercase;
                    transition:all 0.25s;
                ">🚨 Report Crime</button>
            </div>

            <!-- "stays until dismissed" hint -->
            <div style="text-align:center;margin-top:8px;font-size:10px;color:#3a4a6a;letter-spacing:0.5px;">
                This alert stays until you dismiss it or refresh the page
            </div>
        </div>
    `;

    document.body.appendChild(popup);

    const close = () => {
        warningActive = false;
        popup.style.transition = 'opacity 0.35s ease, transform 0.35s ease';
        popup.style.opacity = '0';
        popup.style.transform = 'translateX(420px) scale(0.9)';
        setTimeout(() => popup.remove(), 380);
    };

    // Bind close buttons
    const closeBtn = popup.querySelector('#cs-close-alert');
    const dismissBtn = popup.querySelector('#cs-dismiss-alert');
    const helplineBtn = popup.querySelector('#cs-helpline-btn');
    if (closeBtn) closeBtn.addEventListener('click', close);
    if (dismissBtn) dismissBtn.addEventListener('click', close);
    if (helplineBtn) helplineBtn.addEventListener('click', () => {
        close();
        setTimeout(() => showHelplineModal(), 380);
    });

    // ✅ NO auto-close — warning stays until user manually dismisses or page refreshes
}

// ============ CYBER SECURITY HELPLINE MODAL ============

function showHelplineModal() {
    // Remove existing if any
    const existing = document.getElementById('cs-helpline-modal');
    if (existing) existing.remove();

    // Inject styles once
    if (!document.getElementById('cs-helpline-styles')) {
        const s = document.createElement('style');
        s.id = 'cs-helpline-styles';
        s.textContent = `
            @keyframes cs-modal-enter {
                0%   { opacity:0; transform:scale(0.85) translateY(30px); }
                60%  { transform:scale(1.02) translateY(-4px); }
                100% { opacity:1; transform:scale(1) translateY(0); }
            }
            @keyframes cs-helpline-pulse {
                0%,100% { box-shadow: 0 0 0 0 rgba(220,38,38,0.7); }
                50%      { box-shadow: 0 0 0 10px rgba(220,38,38,0); }
            }
            @keyframes cs-number-glow {
                0%,100% { text-shadow: 0 0 20px rgba(249,115,22,0.5); }
                50%      { text-shadow: 0 0 40px rgba(249,115,22,0.9), 0 0 60px rgba(249,115,22,0.4); }
            }
            @keyframes cs-step-slide {
                from { opacity:0; transform:translateX(-20px); }
                to   { opacity:1; transform:translateX(0); }
            }
            @keyframes cs-top-scan {
                0%   { background-position: -400px 0; }
                100% { background-position: 400px 0; }
            }
            #cs-helpline-modal {
                position: fixed;
                inset: 0;
                z-index: 2147483647;
                display: flex;
                align-items: center;
                justify-content: center;
                background: rgba(0,0,0,0.75);
                backdrop-filter: blur(8px);
                -webkit-backdrop-filter: blur(8px);
                font-family: 'Segoe UI', system-ui, sans-serif;
                padding: 16px;
                box-sizing: border-box;
            }
            #cs-helpline-card {
                background: linear-gradient(160deg, rgba(6,14,30,0.99) 0%, rgba(12,22,48,0.99) 100%);
                border: 1.5px solid rgba(220,38,38,0.6);
                border-radius: 20px;
                width: 100%;
                max-width: 480px;
                max-height: 90vh;
                overflow-y: auto;
                overflow-x: hidden;
                box-shadow: 0 30px 80px rgba(0,0,0,0.8), 0 0 40px rgba(220,38,38,0.2);
                animation: cs-modal-enter 0.5s cubic-bezier(0.34,1.56,0.64,1) forwards;
                scrollbar-width: thin;
                scrollbar-color: rgba(220,38,38,0.4) transparent;
            }
            #cs-helpline-card::-webkit-scrollbar { width:4px; }
            #cs-helpline-card::-webkit-scrollbar-thumb { background:rgba(220,38,38,0.4);border-radius:99px; }
            .cs-step-item {
                animation: cs-step-slide 0.4s ease forwards;
                opacity: 0;
            }
            .cs-step-item:nth-child(1)  { animation-delay: 0.1s; }
            .cs-step-item:nth-child(2)  { animation-delay: 0.18s; }
            .cs-step-item:nth-child(3)  { animation-delay: 0.26s; }
            .cs-step-item:nth-child(4)  { animation-delay: 0.34s; }
            .cs-step-item:nth-child(5)  { animation-delay: 0.42s; }
            .cs-step-item:nth-child(6)  { animation-delay: 0.50s; }
            .cs-step-item:nth-child(7)  { animation-delay: 0.58s; }
            #cs-helpline-close:hover { background:rgba(255,255,255,0.12) !important; color:#fff !important; }
            .cs-portal-btn:hover {
                background: rgba(59,130,246,0.30) !important;
                border-color: #60a5fa !important;
                transform: translateY(-1px);
                box-shadow: 0 4px 20px rgba(59,130,246,0.3);
            }
            .cs-call-btn:hover {
                background: rgba(220,38,38,0.40) !important;
                transform: translateY(-2px);
                box-shadow: 0 6px 24px rgba(220,38,38,0.4);
            }
        `;
        document.head.appendChild(s);
    }

    const steps = [
        { num:'1', icon:'🖥️', title:'Go to Cyber Crime Portal', desc:'Open <strong>cybercrime.gov.in</strong> in your browser — India\'s official national cyber crime reporting portal.' },
        { num:'2', icon:'📋', title:'Click "Report Other Cyber Crimes"', desc:'Select this option on the homepage for scams, fraud messages, phishing links, and financial cyber crimes.' },
        { num:'3', icon:'👤', title:'Register / Login', desc:'Create a free account with your mobile number and email. Your details remain <strong>strictly confidential</strong>.' },
        { num:'4', icon:'📝', title:'Fill the Complaint Form', desc:'Select crime category (e.g. "Online Financial Fraud" or "Social Media Fraud"). Provide all details.' },
        { num:'5', icon:'📎', title:'Attach Evidence', desc:'Upload screenshots of the scam message, URLs, transaction IDs, and any receipts. More evidence = faster action.' },
        { num:'6', icon:'✅', title:'Submit & Note Complaint ID', desc:'After submission, <strong>save your Complaint Acknowledgement Number</strong>. Use it to track status anytime.' },
        { num:'7', icon:'📞', title:'Follow Up by Calling 1930', desc:'Call the <strong>National Cyber Crime Helpline 1930</strong> (24/7) and quote your complaint ID for faster action.' }
    ];

    const stepsHtml = steps.map(s => `
        <div class="cs-step-item" style="
            display:flex;align-items:flex-start;gap:14px;
            padding:12px 14px;margin-bottom:8px;
            background:rgba(255,255,255,0.03);
            border:1px solid rgba(255,255,255,0.06);
            border-radius:12px;
        ">
            <div style="
                min-width:34px;height:34px;border-radius:10px;
                background:rgba(220,38,38,0.15);border:1.5px solid rgba(220,38,38,0.4);
                display:flex;align-items:center;justify-content:center;
                font-size:13px;font-weight:900;color:#f97316;flex-shrink:0;
            ">${s.num}</div>
            <div style="flex:1;">
                <div style="display:flex;align-items:center;gap:7px;margin-bottom:4px;">
                    <span style="font-size:15px;">${s.icon}</span>
                    <span style="font-size:13px;font-weight:700;color:#e2e8f0;">${s.title}</span>
                </div>
                <div style="font-size:12px;color:#94a3b8;line-height:1.6;">${s.desc}</div>
            </div>
        </div>
    `).join('');

    const overlay = document.createElement('div');
    overlay.id = 'cs-helpline-modal';
    overlay.innerHTML = `
        <div id="cs-helpline-card">

            <!-- Animated top bar -->
            <div style="
                height:4px;
                background:linear-gradient(90deg,#dc2626,#f97316,#fbbf24,#dc2626);
                background-size:200% 100%;
                animation:cs-top-scan 2.5s linear infinite;
            "></div>

            <div style="padding:22px 22px 20px;">

                <!-- Header -->
                <div style="display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:20px;">
                    <div style="display:flex;align-items:center;gap:14px;">
                        <div style="
                            width:52px;height:52px;border-radius:14px;
                            background:rgba(220,38,38,0.15);border:2px solid rgba(220,38,38,0.5);
                            display:flex;align-items:center;justify-content:center;font-size:26px;
                            animation:cs-helpline-pulse 2s ease-in-out infinite;
                        ">🚨</div>
                        <div>
                            <div style="font-size:16px;font-weight:900;color:#ff6b6b;letter-spacing:0.5px;text-transform:uppercase;">Cyber Crime Helpline</div>
                            <div style="font-size:11px;color:#64748b;letter-spacing:1px;text-transform:uppercase;margin-top:2px;">
                                <span style="color:#22c55e;">●</span>&nbsp;National Cyber Crime Reporting Portal
                            </div>
                        </div>
                    </div>
                    <button id="cs-helpline-close" style="
                        background:rgba(255,255,255,0.06);border:1px solid rgba(255,255,255,0.12);
                        color:#64748b;width:32px;height:32px;border-radius:9px;
                        cursor:pointer;font-size:20px;line-height:1;
                        display:flex;align-items:center;justify-content:center;
                        transition:all 0.2s;flex-shrink:0;
                    ">&times;</button>
                </div>

                <!-- Emergency Helpline Number -->
                <div style="
                    background:linear-gradient(135deg,rgba(220,38,38,0.2),rgba(239,68,68,0.08));
                    border:2px solid rgba(220,38,38,0.5);
                    border-radius:14px;padding:18px 20px;margin-bottom:16px;
                    text-align:center;
                ">
                    <div style="font-size:11px;letter-spacing:2px;text-transform:uppercase;color:#94a3b8;margin-bottom:8px;">
                        🇮🇳 NATIONAL CYBER CRIME HELPLINE
                    </div>
                    <div style="
                        font-size:52px;font-weight:900;color:#f97316;
                        letter-spacing:4px;line-height:1;
                        animation:cs-number-glow 2.5s ease-in-out infinite;
                        font-family:'Consolas','Courier New',monospace;
                    ">1930</div>
                    <div style="font-size:12px;color:#94a3b8;margin-top:8px;">Available 24 × 7 · Free to call · All networks</div>
                    <a href="tel:1930" style="
                        display:inline-block;margin-top:12px;
                        background:linear-gradient(135deg,#dc2626,#b91c1c);
                        color:#fff;padding:10px 28px;border-radius:10px;
                        font-weight:800;font-size:14px;text-decoration:none;
                        letter-spacing:0.5px;
                        transition:all 0.25s;
                    " class="cs-call-btn">📞 Call 1930 Now</a>
                </div>

                <!-- Portal link -->
                <div style="
                    background:rgba(59,130,246,0.08);border:1.5px solid rgba(59,130,246,0.3);
                    border-radius:12px;padding:14px 16px;margin-bottom:20px;
                    display:flex;align-items:center;justify-content:space-between;gap:12px;
                ">
                    <div>
                        <div style="font-size:13px;font-weight:700;color:#93c5fd;margin-bottom:3px;">🌐 Official Online Portal</div>
                        <div style="font-size:12px;color:#64748b;">File detailed complaint with screenshots & evidence</div>
                    </div>
                    <a href="https://cybercrime.gov.in" target="_blank" style="
                        background:rgba(59,130,246,0.15);border:1.5px solid rgba(59,130,246,0.4);
                        color:#60a5fa;padding:9px 16px;border-radius:9px;
                        font-weight:700;font-size:12px;text-decoration:none;
                        white-space:nowrap;flex-shrink:0;
                        transition:all 0.25s;
                    " class="cs-portal-btn">Report Online →</a>
                </div>

                <!-- What to do IMMEDIATELY -->
                <div style="
                    background:rgba(234,179,8,0.06);border:1px solid rgba(234,179,8,0.25);
                    border-radius:12px;padding:12px 14px;margin-bottom:20px;
                ">
                    <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#fbbf24;margin-bottom:10px;font-weight:700;">⚡ Do This IMMEDIATELY</div>
                    <div style="display:flex;flex-direction:column;gap:6px;">
                        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#cbd5e1;">
                            <span>🔒</span> <span><strong>Do NOT share OTPs, passwords, or CVV</strong> with anyone</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#cbd5e1;">
                            <span>🏦</span> <span>If money was transferred, <strong>call your bank NOW</strong> to freeze the transaction</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#cbd5e1;">
                            <span>📱</span> <span><strong>Block the sender</strong> and screenshot all evidence before deleting</span>
                        </div>
                        <div style="display:flex;align-items:center;gap:10px;font-size:12px;color:#cbd5e1;">
                            <span>⏱️</span> <span>Report within <strong>24 hours</strong> — faster reports = higher recovery chances</span>
                        </div>
                    </div>
                </div>

                <!-- Step-by-step guide -->
                <div style="margin-bottom:16px;">
                    <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#64748b;margin-bottom:12px;font-weight:700;">📋 How to File a Complaint — Step by Step</div>
                    ${stepsHtml}
                </div>

                <!-- Additional contacts -->
                <div style="
                    background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.07);
                    border-radius:12px;padding:12px 14px;margin-bottom:16px;
                ">
                    <div style="font-size:11px;letter-spacing:1.5px;text-transform:uppercase;color:#64748b;margin-bottom:10px;font-weight:700;">📞 Other Emergency Contacts</div>
                    <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;">
                        <div style="background:rgba(255,255,255,0.04);border-radius:9px;padding:10px 12px;">
                            <div style="font-size:10px;color:#64748b;margin-bottom:2px;">Police Control Room</div>
                            <div style="font-size:18px;font-weight:800;color:#e2e8f0;font-family:monospace;">100</div>
                        </div>
                        <div style="background:rgba(255,255,255,0.04);border-radius:9px;padding:10px 12px;">
                            <div style="font-size:10px;color:#64748b;margin-bottom:2px;">RBI Fraud Helpline</div>
                            <div style="font-size:18px;font-weight:800;color:#e2e8f0;font-family:monospace;">14440</div>
                        </div>
                        <div style="background:rgba(255,255,255,0.04);border-radius:9px;padding:10px 12px;">
                            <div style="font-size:10px;color:#64748b;margin-bottom:2px;">TRAI DNC Registry</div>
                            <div style="font-size:18px;font-weight:800;color:#e2e8f0;font-family:monospace;">1909</div>
                        </div>
                        <div style="background:rgba(255,255,255,0.04);border-radius:9px;padding:10px 12px;">
                            <div style="font-size:10px;color:#64748b;margin-bottom:2px;">Sanchar Saathi</div>
                            <div style="font-size:12px;font-weight:700;color:#60a5fa;">sancharsaathi.gov.in</div>
                        </div>
                    </div>
                </div>

                <!-- Close button -->
                <button id="cs-helpline-close-bottom" style="
                    width:100%;padding:13px;
                    background:linear-gradient(135deg,rgba(220,38,38,0.2),rgba(220,38,38,0.08));
                    border:1.5px solid rgba(220,38,38,0.5);border-radius:11px;
                    color:#ff6b6b;font-weight:800;font-size:13px;letter-spacing:0.8px;
                    text-transform:uppercase;cursor:pointer;transition:all 0.25s;
                ">✅ I Understand — Close Guide</button>

            </div>
        </div>
    `;

    document.body.appendChild(overlay);

    const closeModal = () => {
        overlay.style.transition = 'opacity 0.3s ease';
        overlay.style.opacity = '0';
        setTimeout(() => overlay.remove(), 320);
    };

    // Close on backdrop click
    overlay.addEventListener('click', (e) => { if (e.target === overlay) closeModal(); });
    const topClose = overlay.querySelector('#cs-helpline-close');
    const bottomClose = overlay.querySelector('#cs-helpline-close-bottom');
    if (topClose)    topClose.addEventListener('click', closeModal);
    if (bottomClose) bottomClose.addEventListener('click', closeModal);
}


console.log('✓ Cyber Shield ready and monitoring');

// ============ URL REDIRECT INTERCEPTION (NEW FEATURE) ============
// Intercepts clicks on scam URLs in WhatsApp Web & Gmail
// Shows a "Proceed / Go Back" confirmation modal before any redirect

(function initUrlRedirectGuard() {

    // Helper: check if a given href matches any scam pattern
    function isScamUrl(href) {
        if (!href) return false;
        const url = href.toLowerCase();

        // Skip anchor-only, mailto, javascript, and same-origin hash links
        if (
            url.startsWith('#') ||
            url.startsWith('mailto:') ||
            url.startsWith('javascript:') ||
            url.startsWith('tel:')
        ) return false;

        // Reuse the existing suspiciousUrlPatterns object already defined above
        for (const service of suspiciousUrlPatterns.shortened) {
            if (url.includes(service)) return true;
        }
        for (const pattern of suspiciousUrlPatterns.phishing) {
            if (url.includes(pattern)) return true;
        }
        for (const pattern of suspiciousUrlPatterns.suspicious) {
            if (url.includes(pattern)) return true;
        }
        for (const keyword of suspiciousUrlPatterns.scamDomainKeywords) {
            if (url.includes(keyword)) return true;
        }
        // IP-based URLs are always suspicious
        if (/https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(href)) return true;

        return false;
    }

    // Inject modal styles once
    function injectGuardStyles() {
        if (document.getElementById('cs-guard-styles')) return;
        const style = document.createElement('style');
        style.id = 'cs-guard-styles';
        style.textContent = `
            #cs-redirect-overlay {
                position: fixed;
                inset: 0;
                background: rgba(0,0,0,0.72);
                backdrop-filter: blur(6px);
                -webkit-backdrop-filter: blur(6px);
                z-index: 2147483647;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: cs-guard-fadein 0.2s ease;
            }
            @keyframes cs-guard-fadein {
                from { opacity: 0; }
                to   { opacity: 1; }
            }
            #cs-redirect-modal {
                background: linear-gradient(145deg, #0d1b2a 0%, #1a2740 100%);
                border: 1.5px solid rgba(255,80,80,0.45);
                border-radius: 18px;
                padding: 32px 28px 26px;
                width: 420px;
                max-width: calc(100vw - 32px);
                box-shadow: 0 24px 64px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,255,255,0.04);
                font-family: 'Segoe UI', system-ui, sans-serif;
                animation: cs-guard-slidein 0.25s cubic-bezier(0.34,1.56,0.64,1);
            }
            @keyframes cs-guard-slidein {
                from { opacity: 0; transform: scale(0.88) translateY(20px); }
                to   { opacity: 1; transform: scale(1)    translateY(0px);  }
            }
            #cs-redirect-modal .cs-guard-icon {
                font-size: 44px;
                text-align: center;
                margin-bottom: 12px;
                filter: drop-shadow(0 0 12px rgba(255,80,80,0.6));
            }
            #cs-redirect-modal h2 {
                color: #ff5252;
                font-size: 18px;
                font-weight: 800;
                text-align: center;
                margin: 0 0 8px;
                letter-spacing: 0.3px;
            }
            #cs-redirect-modal .cs-guard-subtitle {
                color: #94a3b8;
                font-size: 13px;
                text-align: center;
                margin-bottom: 18px;
                line-height: 1.5;
            }
            #cs-redirect-modal .cs-guard-url-box {
                background: rgba(255,82,82,0.08);
                border: 1px solid rgba(255,82,82,0.25);
                border-radius: 10px;
                padding: 10px 14px;
                margin-bottom: 20px;
                word-break: break-all;
                font-size: 11.5px;
                color: #ff8a80;
                font-family: 'Consolas','Courier New',monospace;
                max-height: 56px;
                overflow: hidden;
                text-overflow: ellipsis;
                display: -webkit-box;
                -webkit-line-clamp: 3;
                -webkit-box-orient: vertical;
            }
            #cs-redirect-modal .cs-guard-warning-list {
                background: rgba(255,255,255,0.03);
                border: 1px solid rgba(255,255,255,0.07);
                border-radius: 10px;
                padding: 12px 14px;
                margin-bottom: 22px;
                font-size: 12px;
                color: #cbd5e1;
                line-height: 1.8;
            }
            #cs-redirect-modal .cs-guard-warning-list li {
                list-style: none;
                padding-left: 4px;
            }
            #cs-redirect-modal .cs-guard-warning-list li::before {
                content: '⚠️  ';
            }
            #cs-redirect-modal .cs-guard-actions {
                display: grid;
                grid-template-columns: 1fr 1fr;
                gap: 12px;
            }
            #cs-guard-goback-btn {
                padding: 13px;
                background: linear-gradient(135deg, #1a3a2a, #0d2a1a);
                border: 1.5px solid rgba(0,200,100,0.5);
                border-radius: 11px;
                color: #00e676;
                font-weight: 800;
                font-size: 13px;
                cursor: pointer;
                transition: all 0.2s;
                letter-spacing: 0.4px;
            }
            #cs-guard-goback-btn:hover {
                background: linear-gradient(135deg, #1e4a30, #122e1c);
                border-color: rgba(0,230,118,0.8);
                transform: translateY(-1px);
                box-shadow: 0 4px 16px rgba(0,200,100,0.25);
            }
            #cs-guard-proceed-btn {
                padding: 13px;
                background: linear-gradient(135deg, rgba(220,38,38,0.18), rgba(220,38,38,0.06));
                border: 1.5px solid rgba(220,38,38,0.45);
                border-radius: 11px;
                color: #ff6b6b;
                font-weight: 700;
                font-size: 12px;
                cursor: pointer;
                transition: all 0.2s;
                letter-spacing: 0.3px;
            }
            #cs-guard-proceed-btn:hover {
                background: linear-gradient(135deg, rgba(220,38,38,0.28), rgba(220,38,38,0.12));
                border-color: rgba(220,38,38,0.75);
                transform: translateY(-1px);
            }
        `;
        document.head.appendChild(style);
    }

    // Show the redirect guard modal
    function showRedirectGuard(targetUrl, onProceed, onGoBack) {
        // Remove any existing guard modal first
        const existing = document.getElementById('cs-redirect-overlay');
        if (existing) existing.remove();

        injectGuardStyles();

        const overlay = document.createElement('div');
        overlay.id = 'cs-redirect-overlay';

        const displayUrl = targetUrl.length > 80
            ? targetUrl.substring(0, 77) + '...'
            : targetUrl;

        overlay.innerHTML = `
            <div id="cs-redirect-modal" role="dialog" aria-modal="true" aria-labelledby="cs-guard-title">

                <div class="cs-guard-icon">🛡️</div>

                <h2 id="cs-guard-title">⚠ Suspicious Link Detected</h2>

                <p class="cs-guard-subtitle">
                    CyberShield has flagged this link as potentially dangerous.<br>
                    Are you sure you want to proceed?
                </p>

                <div class="cs-guard-url-box" title="${targetUrl}">${targetUrl}</div>

                <ul class="cs-guard-warning-list">
                    <li>This URL matches known scam/phishing patterns</li>
                    <li>It may steal your personal or financial information</li>
                    <li>You could be redirected to a fake website</li>
                </ul>

                <div class="cs-guard-actions">
                    <button id="cs-guard-goback-btn">✅ Go Back (Safe)</button>
                    <button id="cs-guard-proceed-btn">⚠ Proceed Anyway</button>
                </div>

            </div>
        `;

        document.body.appendChild(overlay);

        const modal = overlay.querySelector('#cs-redirect-modal');

        // Go Back — dismiss and stay on page
        overlay.querySelector('#cs-guard-goback-btn').addEventListener('click', () => {
            dismissGuard(overlay);
            if (onGoBack) onGoBack();
        });

        // Proceed — open the URL
        overlay.querySelector('#cs-guard-proceed-btn').addEventListener('click', () => {
            dismissGuard(overlay);
            if (onProceed) onProceed();
        });

        // Clicking the dark backdrop = go back (safe default)
        overlay.addEventListener('click', (e) => {
            if (e.target === overlay) {
                dismissGuard(overlay);
                if (onGoBack) onGoBack();
            }
        });

        // ESC key = go back
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                document.removeEventListener('keydown', escHandler);
                dismissGuard(overlay);
                if (onGoBack) onGoBack();
            }
        };
        document.addEventListener('keydown', escHandler);
    }

    function dismissGuard(overlay) {
        if (!overlay) return;
        overlay.style.transition = 'opacity 0.25s ease';
        overlay.style.opacity = '0';
        setTimeout(() => { if (overlay.parentNode) overlay.remove(); }, 260);
    }

    // Resolve the final href from a click target (walk up to <a>)
    function getAnchorHref(target) {
        let el = target;
        while (el && el !== document.body) {
            if (el.tagName === 'A' && el.href) return el.href;
            el = el.parentElement;
        }
        return null;
    }

    // Global click interceptor — capture phase so we always run first
    document.addEventListener('click', function csGuardClickHandler(e) {
        // Only intercept on WhatsApp Web and Gmail
        const host = location.hostname;
        const isWhatsApp = host.includes('whatsapp.com');
        const isGmail    = host.includes('mail.google.com');
        if (!isWhatsApp && !isGmail) return;

        const href = getAnchorHref(e.target);
        if (!href) return;
        if (!isScamUrl(href)) return;

        // Block the default navigation
        e.preventDefault();
        e.stopImmediatePropagation();

        console.log(`🛡️ [CyberShield] Redirect guard triggered for: ${href}`);

        showRedirectGuard(
            href,
            // onProceed — user accepted the risk
            () => {
                console.log(`⚠️  [CyberShield] User chose to proceed to: ${href}`);
                window.open(href, '_blank', 'noopener,noreferrer');
            },
            // onGoBack — user stayed safe
            () => {
                console.log(`✅ [CyberShield] User blocked redirect to: ${href}`);
            }
        );

    }, true); // true = capture phase

    console.log('✓ CyberShield URL Redirect Guard active');

})();


// ============ PREMIUM ACTIVATED BADGE ============

function injectActivatedBadge(platform) {
    // Only on WhatsApp and Gmail
    if (platform !== 'whatsapp' && platform !== 'gmail') return;
    // Don't inject twice
    if (document.getElementById('cs-activated-badge')) return;

    // Inject keyframe styles once
    if (!document.getElementById('cs-badge-styles')) {
        const style = document.createElement('style');
        style.id = 'cs-badge-styles';
        style.textContent = `
            @keyframes cs-pulse {
                0%   { box-shadow: 0 0 0 0 rgba(0,255,136,0.8); transform: scale(1); }
                70%  { box-shadow: 0 0 0 8px rgba(0,255,136,0);  transform: scale(1.1); }
                100% { box-shadow: 0 0 0 0 rgba(0,255,136,0);    transform: scale(1); }
            }
            @keyframes cs-slidein {
                from { opacity: 0; transform: translateY(-20px) scale(0.9); }
                to   { opacity: 1; transform: translateY(0px)   scale(1);   }
            }
            @keyframes cs-scanline {
                0%   { background-position: 0 0; }
                100% { background-position: 0 100%; }
            }
            #cs-activated-badge {
                animation: cs-slidein 0.5s cubic-bezier(0.34,1.56,0.64,1) forwards;
            }
            #cs-activated-badge:hover {
                border-color: rgba(0,255,136,0.6) !important;
                box-shadow: 0 8px 32px rgba(0,0,0,0.5), 0 0 30px rgba(0,255,136,0.25) !important;
                transform: translateY(-2px);
                transition: all 0.25s ease;
            }
            #cs-close-btn:hover { color: #ff4757 !important; }
        `;
        document.head.appendChild(style);
    }

    const badge = document.createElement('div');
    badge.id = 'cs-activated-badge';

    badge.innerHTML = `
        <div style="display:flex;align-items:center;gap:10px;">

            <!-- Shield icon -->
            <svg width="18" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                <path d="M12 2L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6L12 2z"
                      fill="url(#shieldGrad)" opacity="0.9"/>
                <path d="M9 12l2 2 4-4" stroke="#0a192f" stroke-width="2"
                      stroke-linecap="round" stroke-linejoin="round"/>
                <defs>
                    <linearGradient id="shieldGrad" x1="0" y1="0" x2="1" y2="1">
                        <stop offset="0%" stop-color="#00ff88"/>
                        <stop offset="100%" stop-color="#00b8ff"/>
                    </linearGradient>
                </defs>
            </svg>

            <!-- Text block -->
            <div style="display:flex;flex-direction:column;gap:1px;">
                <span style="
                    font-size:11px;letter-spacing:2px;text-transform:uppercase;
                    color:#8892b0;font-weight:600;line-height:1;
                ">CyberShield AI</span>
                <span style="
                    background:linear-gradient(90deg,#00ff88 0%,#00b8ff 60%,#7b2ff7 100%);
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                    font-size:13px;font-weight:800;letter-spacing:0.5px;line-height:1.3;
                ">&#x2726; ACTIVATED</span>
            </div>

            <!-- Pulse dot -->
            <div style="
                width:9px;height:9px;border-radius:50%;
                background:#00ff88;
                box-shadow:0 0 8px #00ff88,0 0 16px rgba(0,255,136,0.4);
                animation:cs-pulse 2s infinite;
                flex-shrink:0;
            "></div>

            <!-- Close button -->
            <button id="cs-close-btn" style="
                background:none;border:none;cursor:pointer;
                color:#4a5568;font-size:17px;line-height:1;
                padding:0 0 0 4px;outline:none;flex-shrink:0;
                transition:color 0.2s;
            " title="Dismiss">&times;</button>
        </div>
    `;

    badge.style.cssText = `
        position: fixed;
        top: 22px;
        right: 22px;
        z-index: 2147483647;
        background: rgba(9, 18, 36, 0.88);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid rgba(0,255,136,0.25);
        border-radius: 10px;
        padding: 10px 16px;
        font-family: 'Consolas','Courier New',monospace;
        box-shadow: 0 8px 28px rgba(0,0,0,0.45), inset 0 0 24px rgba(0,255,136,0.04);
        cursor: default;
        user-select: none;
    `;

    document.body.appendChild(badge);

    document.getElementById('cs-close-btn').addEventListener('click', () => {
        badge.style.transition = 'opacity 0.3s, transform 0.3s';
        badge.style.opacity = '0';
        badge.style.transform = 'translateY(-10px) scale(0.95)';
        setTimeout(() => badge.remove(), 320);
    });
}