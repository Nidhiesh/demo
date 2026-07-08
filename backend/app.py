"""
CYBER SHIELD BACKEND API (2026)
Flask server that uses the bank-scam-only ML model to detect bank/UPI
fraud in real time on WhatsApp Web & Gmail.
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import pickle
from datetime import datetime
import logging
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np
import threading
import subprocess

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ============ LOAD MODEL ============

try:
    with open('model.pkl', 'rb') as f:
        model = pickle.load(f)
    logger.info("[OK] Model loaded successfully")
except FileNotFoundError:
    logger.error("[ERROR] model.pkl not found. Run train_model_bank2026.py first!")
    model = None

try:
    with open('vectorizer.pkl', 'rb') as f:
        vectorizer = pickle.load(f)
    logger.info("[OK] Vectorizer loaded successfully")
except FileNotFoundError:
    logger.error("[ERROR] vectorizer.pkl not found. Run train_model_bank2026.py first!")
    vectorizer = None

CURRENT_SCAM_TEMPLATES = [
    {"id":"S01","category":"OTP Phishing","template":"Dear customer your SBI account will be blocked. Update your KYC immediately. Click here and enter your OTP to verify."},
    {"id":"S02","category":"UPI Collect Request","template":"We are sending you a refund of Rs 4999. Please approve the collect request on your UPI app immediately."},
    {"id":"S03","category":"QR Code Scam","template":"You have received a cashback of Rs 2000. Scan this QR code to receive money directly in your account."},
    {"id":"S04","category":"Remote Access","template":"This is HDFC Bank fraud department. Please download AnyDesk app and share the 9-digit code to secure your account."},
    {"id":"S05","category":"SIM Swap","template":"Your SIM will be deactivated within 24 hours. Please call our helpline or press 1 to port your number and avoid disconnection."},
    {"id":"S06","category":"Digital Arrest","template":"This is CBI cybercrime division. Your Aadhaar is linked to a money laundering case. You are under digital arrest. Do not disconnect."},
    {"id":"S07","category":"Fake KYC","template":"Your ICICI bank KYC is expired. Update now using this link or your account will be permanently suspended within 24 hours."},
    {"id":"S08","category":"Loan App Extortion","template":"Congratulations your personal loan of Rs 50000 is approved. Pay processing fee of Rs 999 to release the funds immediately."},
    {"id":"S09","category":"Investment Fraud","template":"Join our SEBI registered stock tips group. Guaranteed 30 percent returns monthly. Pay Rs 5000 registration to join now."},
    {"id":"S10","category":"Vishing Setup","template":"Your account shows suspicious activity. Call our bank officer immediately on this number to prevent your account from being blocked."},
    {"id":"S11","category":"Card Detail Harvest","template":"Your Axis Bank debit card is blocked due to unusual activity. Share your 16-digit card number CVV and OTP to reactivate immediately."},
    {"id":"S12","category":"Insurance Fraud","template":"Your LIC policy maturity amount of Rs 85000 is ready. Share your Aadhaar and bank account number to receive the amount within 2 hours."},
    {"id":"S13","category":"Fake Reward","template":"You have won Rs 10 lakh in Jio lucky draw. To claim your prize share your bank account details and OTP received on your number."},
    {"id":"S14","category":"UPI PIN Harvest","template":"This is PhonePe support. We need to verify your account. Please share your UPI PIN to confirm your identity."},
    {"id":"S15","category":"Customs Parcel Scam","template":"Your international parcel is held at customs. Pay Rs 3500 clearance fee via UPI within 2 hours or parcel will be destroyed."},
]

_template_vectors = None

def _init_template_vectors():
    global _template_vectors
    if vectorizer is not None:
        _template_vectors = vectorizer.transform([t["template"] for t in CURRENT_SCAM_TEMPLATES])

_init_template_vectors()

stats = {
    'total_checks': 0,
    'scams_detected': 0,
    'safe_messages': 0,
    'last_check': None
}

# ============ BANK-SCAM-ONLY GATING ============

BANK_TERMS = [
    # Indian bank names
    'sbi', 'hdfc', 'icici', 'axis', 'boi', 'pnb', 'kotak', 'canara',
    'union bank', 'idbi', 'yes bank', 'rbl bank', 'federal bank',
    'indusind', 'bandhan bank', 'indian bank', 'uco bank', 'bank of baroda',
    'bob', 'central bank', 'indian overseas bank', 'iob', 'karnataka bank',
    'south indian bank', 'city union bank',
    # Generic banking
    'bank', 'netbanking', 'net banking', 'online banking', 'mobile banking',
    'internet banking', 'banking app', 'ibanking',
    # Account
    'account number', 'account locked', 'account suspended', 'account compromised',
    'account blocked', 'account freeze', 'account deactivated', 'account closed',
    'account verification', 'account update', 'savings account', 'current account',
    # Cards
    'debit card', 'credit card', 'card details', 'card blocked', 'card expired',
    'card activation', 'card upgrade', 'cvv', 'card number', 'expiry date',
    'virtual card', 'prepaid card', 'rupay card', 'visa card', 'mastercard',
    # UPI / Payments
    'upi', 'upi pin', 'upi id', 'upi link', 'google pay', 'gpay',
    'phonepe', 'paytm', 'bhim', 'payment request', 'collect request',
    'pay now', 'payment link', 'money transfer', 'fund transfer', 'wallet',
    # Transfer codes
    'ifsc', 'neft', 'rtgs', 'imps', 'micr',
    # ATM
    'atm', 'atm card', 'atm pin', 'cash withdrawal', 'cash deposit',
    # KYC / Identity
    'kyc', 'kyc update', 'kyc pending', 'kyc expired', 'kyc verification',
    'aadhaar', 'aadhar', 'pan card', 'pan number', 'voter id', 'cibil', 'credit score',
    # OTP
    'otp', 'one time password', 'one time pin', 'verification code',
    'security code', 'enter code', 'share the code',
    # QR
    'qr code', 'scan qr', 'scan this qr', 'scan to receive', 'qr payment', 'bhim qr',
    # Remote access
    'anydesk', 'teamviewer', 'screen share', 'remote access', 'quicksupport',
    'airdroid', 'remote desktop', 'share your screen',
    # SIM
    'sim card', 'sim swap', 'sim deactivated', 'sim will be blocked', 'port your number', 'mnp',
    # Loan
    'loan app', 'loan approved', 'personal loan', 'instant loan', 'easy loan',
    'emi', 'emi overdue', 'processing fee', 'loan disbursement', 'release funds',
    'credit limit', 'overdraft', 'gold loan', 'home loan',
    # Investment
    'fixed deposit', 'fd', 'rd account', 'recurring deposit',
    'mutual fund', 'investment', 'trading account', 'stock broker', 'sebi',
    # Fake legal
    'digital arrest', 'cyber crime', 'cbi notice', 'ed notice',
    'income tax notice', 'money laundering', 'arrest warrant', 'customs',
    'parcel held', 'narcotics', 'drug case', 'fir registered',
    # Physical banking
    'cheque', 'demand draft', 'passbook', 'branch', 'locker',
    # Reward bait
    'cashback', 'reward points', 'redeem points', 'scratch card',
    'lucky draw', 'refund', 'insurance claim',
    # Fake customer care
    'customer care', 'toll free', '1800', 'helpline', 'bank helpline',
    'contact our executive', 'call back',
    # Multilingual (Hindi Romanized)
    'khata', 'khata band', 'otp share karo', 'otp batao', 'otp bhejo',
    'upi pin bhejo', 'kyc karo', 'loan mil gaya',
    # Multilingual (Tamil/Telugu Romanized)
    'otp kudu', 'account block', 'ungal account', 'otp pampandi', 'mee account',
]

def is_bank_related(message: str) -> bool:
    text = message.lower()
    return any(term in text for term in BANK_TERMS)

# ============ THREAT EXTRACTION (2026 patterns) ============

SCAM_PATTERNS = {
    "OTP Phishing": [
        'otp', 'one time password', 'one time pin', 'verification code',
        'enter the code', 'share the code', 'share otp', 'otp share karo',
        'otp batao', 'otp bhejo', 'otp kudu', 'otp pampandi',
    ],
    "UPI PIN Harvesting": [
        'upi pin', 'enter your pin', 'enter pin', 'upi pin bhejo',
        'share your upi', 'confirm your upi pin',
    ],
    "UPI Collect-Request Scam": [
        'collect request', 'payment request', 'approve the request',
        'accept the request', 'sending you money', 'advance payment via upi',
        'refund via upi', 'cashback request',
    ],
    "QR Code Scam": [
        'scan this qr', 'scan the qr', 'scan to receive', 'qr code',
        'bhim qr', 'upi qr', 'scan qr to get',
    ],
    "Fake KYC / Identity Harvest": [
        'kyc update', 'kyc pending', 'kyc expired', 'kyc verification',
        'aadhaar', 'aadhar', 'pan card', 'pan number',
        'update your kyc', 'complete kyc', 'kyc nahi hua',
    ],
    "Fake Bank Customer Care": [
        'customer care', 'toll free', '1800', 'helpline', 'bank helpline',
        'contact our executive', 'call back', 'our agent will call',
        'call our toll', 'bank representative',
    ],
    "Remote-Access App Request": [
        'anydesk', 'teamviewer', 'screen share', 'remote access',
        'quicksupport', 'airdroid', 'share your screen', 'install anydesk',
        'download teamviewer', 'allow screen access',
    ],
    "SIM Swap / Port Fraud": [
        'sim card', 'sim swap', 'sim will be deactivated', 'sim deactivat',
        'port your number', 'sim block', 'mnp', 'mobile number portability',
    ],
    "Digital Arrest / Fake Legal Notice": [
        'digital arrest', 'cbi notice', 'cyber crime', 'ed notice',
        'income tax notice', 'money laundering', 'arrest warrant',
        'narcotics', 'drug case', 'customs clearance', 'parcel held',
        'fir registered', 'police complaint', 'court notice',
    ],
    "Loan-App Extortion": [
        'loan app', 'processing fee', 'loan approved', 'emi overdue',
        'release funds', 'instant loan', 'easy loan', 'personal loan approved',
        'pay processing fee',
    ],
    "Investment / Trading Fraud": [
        'stock tips', 'guaranteed returns', 'trading account', 'sebi registered',
        'crypto investment', 'forex trading', 'double your money',
        'high returns', 'profit guarantee',
    ],
    "Insurance / Claim Fraud": [
        'insurance claim', 'policy expired', 'claim your bonus',
        'insurance premium', 'maturity amount', 'surrender value',
        'lic policy', 'claim settlement',
    ],
    "Fake Reward / Cashback Lure": [
        'cashback', 'reward points', 'redeem points', 'scratch card',
        'lucky draw', 'you have won', 'claim your prize', 'free recharge',
        'refund pending', 'bonus credited',
    ],
    "Account-Block / Suspension Threat": [
        'will be blocked', 'will be suspended', 'will be deactivated',
        'permanently suspend', 'account freeze', 'account will be closed',
        'service will stop', 'account locked',
    ],
    "Urgency / Pressure Tactic": [
        'urgent', 'immediately', 'within 24 hours', 'within 1 hour',
        'within 30 minutes', 'act now', 'last chance', 'final warning',
        'expires today', 'do it now', 'tatkal', 'turant',
    ],
    "Suspicious / Phishing Link": [
        'bit.ly', 'tinyurl', 'goo.gl', 'ow.ly', '.xyz', 'click here to verify',
        'click the link', 'verify via link', 't.me/', 'wa.me/', 'cutt.ly', 'rb.gy',
    ],
    "Vishing (Voice Phishing Setup)": [
        'call us at', 'call this number', 'call back on', 'please call',
        'our officer will call', 'contact on whatsapp', 'video call verification',
    ],
    "Card Detail Harvest": [
        'card details', 'card number', 'cvv', 'expiry date', 'card blocked',
        'card upgrade', 'card activation', 'enter card details',
        'debit card number', 'credit card number',
    ],
}

def extract_threats(message: str) -> list:
    threats = []
    text = message.lower()
    for label, keywords in SCAM_PATTERNS.items():
        if any(kw in text for kw in keywords):
            threats.append(label)
        if len(threats) == 5:
            break
    return threats

# ============ API ENDPOINTS ============

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'online',
        'model_loaded': model is not None,
        'vectorizer_loaded': vectorizer is not None,
        'scope': 'bank-related scams only',
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/detect', methods=['POST'])
def detect():
    """
    Main endpoint - ONLY flags bank/UPI-related scam messages.
    Non-bank messages are always returned as 'safe' with no analysis,
    by design - this extension focuses exclusively on bank fraud.

    Request:  {"message": "text to check"}
    Response: {"risk_level": "safe/suspicious/scam", "confidence": 0-1,
               "threats": [...], "matches_training_patterns": bool, ...}
    """
    if model is None or vectorizer is None:
        return jsonify({'error': 'Model not loaded. Run train_model_bank2026.py first!', 'status': 'error'}), 500

    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'error': 'Missing "message" field'}), 400

        message = data.get('message', '').strip()

        if len(message) < 3:
            return jsonify({'error': 'Message too short'}), 400
        if len(message) > 1000:
            message = message[:1000]

        bank_related = is_bank_related(message)

        # Non-bank content is out of scope for this detector - always safe.
        if not bank_related:
            stats['total_checks'] += 1
            stats['safe_messages'] += 1
            stats['last_check'] = datetime.now().isoformat()
            return jsonify({
                'prediction': 0,
                'confidence': 0.0,
                'risk_level': 'safe',
                'threats': [],
                'matches_training_patterns': False,
                'in_scope': False,
                'check_id': f"CHK_{stats['total_checks']:06d}",
                'timestamp': datetime.now().isoformat()
            }), 200

        # Bank-related -> run through the ML model
        msg_vec = vectorizer.transform([message])
        prediction = int(model.predict(msg_vec)[0])
        probability = model.predict_proba(msg_vec)[0]
        scam_probability = float(probability[1])

        if scam_probability >= 0.65:
            risk_level = 'scam'
        elif scam_probability >= 0.50:
            risk_level = 'suspicious'
        else:
            risk_level = 'safe'

        matches_training_patterns = scam_probability >= 0.50
        
        # Keyword escalation: even if ML is uncertain, flag as suspicious
        # if the message contains known scam patterns
        if risk_level == 'safe':
            keyword_threats = extract_threats(message)
            if keyword_threats:
                risk_level = 'suspicious'
                matches_training_patterns = True
        
        sim_data = {}
        if bank_related and _template_vectors is not None:
            msg_vec2 = vectorizer.transform([message])
            sims = cosine_similarity(msg_vec2, _template_vectors)[0]
            top_idx = int(np.argmax(sims))
            max_sim = float(sims[top_idx])
            best = CURRENT_SCAM_TEMPLATES[top_idx]
            verdict = "high_match" if max_sim >= 0.60 else "moderate_match" if max_sim >= 0.30 else "low_match"
            sim_data = {
                "max_similarity": round(max_sim, 4),
                "verdict": verdict,
                "closest_match": {
                    "category": best["category"],
                    "similarity_percent": f"{max_sim*100:.1f}%",
                    "template_id": best["id"]
                }
            }
            # Safety net: if ML says safe but similarity is high, escalate
            if verdict == "high_match" and risk_level == "safe":
                risk_level = "suspicious"
                matches_training_patterns = True

        threats = extract_threats(message) if risk_level != 'safe' else []

        stats['total_checks'] += 1
        if risk_level != 'safe':
            stats['scams_detected'] += 1
        else:
            stats['safe_messages'] += 1
        stats['last_check'] = datetime.now().isoformat()

        result = {
            'prediction': prediction,
            'confidence': scam_probability,
            'risk_level': risk_level,
            'threats': threats,
            'matches_training_patterns': bool(matches_training_patterns),
            'in_scope': True,
            'scam_similarity': sim_data,
            'check_id': f"CHK_{stats['total_checks']:06d}",
            'timestamp': datetime.now().isoformat()
        }
        return jsonify(result), 200

    except Exception as e:
        logger.error(f"Error in /detect: {str(e)}")
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/compare', methods=['POST'])
def compare_scams():
    if vectorizer is None or _template_vectors is None:
        return jsonify({'error': 'Model not loaded'}), 500
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Missing message field'}), 400
    message = data['message'].strip()[:1000]
    msg_vec = vectorizer.transform([message])
    sims = cosine_similarity(msg_vec, _template_vectors)[0]
    top_idx = np.argsort(sims)[::-1][:3]
    top_matches = []
    for rank, idx in enumerate(top_idx, 1):
        score = float(sims[idx])
        t = CURRENT_SCAM_TEMPLATES[idx]
        top_matches.append({
            "rank": rank,
            "similarity": round(score, 4),
            "similarity_percent": f"{score*100:.1f}%",
            "category": t["category"],
            "template_id": t["id"],
            "template_preview": t["template"][:120] + "..."
        })
    max_sim = top_matches[0]["similarity"] if top_matches else 0.0
    verdict = "high_match" if max_sim >= 0.60 else "moderate_match" if max_sim >= 0.30 else "low_match"
    return jsonify({
        "top_matches": top_matches,
        "max_similarity": round(max_sim, 4),
        "verdict": verdict,
        "message_checked": message[:80] + "..." if len(message) > 80 else message
    }), 200


@app.route('/patterns', methods=['GET'])
def list_patterns():
    return jsonify({
        "total_patterns": len(CURRENT_SCAM_TEMPLATES),
        "categories": list({t["category"] for t in CURRENT_SCAM_TEMPLATES}),
        "patterns": CURRENT_SCAM_TEMPLATES,
        "last_updated": "2026-07"
    }), 200


@app.route('/stats', methods=['GET'])
def get_stats():
    return jsonify({
        'total_checks': stats['total_checks'],
        'scams_detected': stats['scams_detected'],
        'safe_messages': stats['safe_messages'],
        'last_check': stats['last_check']
    }), 200


@app.route('/', methods=['GET'])
def info():
    return jsonify({
        'service': 'Cyber Shield - Bank Scam Detector (2026)',
        'version': '4.0',
        'scope': 'Bank/UPI related scams only',
        'endpoints': {
            '/health': 'Server health',
            '/detect': 'Detect bank scam (POST)',
            '/compare': 'Compare message similarity to known scams (POST)',
            '/patterns': 'List known scam patterns (GET)',
            '/stats': 'Statistics',
            '/retrain': 'Trigger dynamic model retraining (POST)'
        }
    }), 200

is_training = False

def background_retrain():
    global model, vectorizer, is_training, _template_vectors
    try:
        logger.info("Starting background retraining...")
        # Run the training script in a subprocess
        subprocess.run(["python", "train_model_with_huggingface.py"], check=True)
        
        logger.info("Retraining complete. Reloading model and vectorizer...")
        with open('model.pkl', 'rb') as f:
            new_model = pickle.load(f)
        with open('vectorizer.pkl', 'rb') as f:
            new_vectorizer = pickle.load(f)
            
        model = new_model
        vectorizer = new_vectorizer
        
        # Reinitialize template vectors
        _init_template_vectors()
        
        logger.info("Dynamically reloaded new model and vectorizer successfully.")
    except Exception as e:
        logger.error(f"Error during background retraining: {e}")
    finally:
        is_training = False

@app.route('/retrain', methods=['POST'])
def retrain():
    global is_training
    if is_training:
        return jsonify({"status": "error", "message": "Training already in progress."}), 429
    
    is_training = True
    thread = threading.Thread(target=background_retrain)
    thread.start()
    
    return jsonify({
        "status": "success",
        "message": "Background retraining started. The model will be updated automatically once complete."
    }), 202


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404


@app.errorhandler(500)
def server_error(error):
    return jsonify({'error': 'Server error'}), 500


if __name__ == '__main__':
    print("\n" + "=" * 80)
    print("CYBER SHIELD - BANK SCAM DETECTOR API (2026) - STARTING SERVER")
    print("=" * 80)
    print(f"\n[OK] Model Status: {'Loaded' if model else 'NOT LOADED'}")
    print(f"[OK] Vectorizer Status: {'Loaded' if vectorizer else 'NOT LOADED'}")
    print(f"[OK] Template Vectors: {'Loaded' if _template_vectors is not None else 'NOT LOADED'}")
    print("[OK] Scope: BANK / UPI related scams only")
    print("\nServer running on: http://localhost:5000")
    print("=" * 80)

    if model and vectorizer:
        app.run(debug=True, host='0.0.0.0', port=5000)
    else:
        print("\n[ERROR] Model or vectorizer not loaded! Run train_model_bank2026.py")
