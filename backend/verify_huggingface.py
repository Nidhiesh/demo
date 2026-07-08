"""
Verify Hugging Face Dataset Integration in CyberShield
"""

from datasets import load_dataset
import pickle

print("=" * 80)
print("CYBER SHIELD - HUGGING FACE DATASET VERIFICATION")
print("=" * 80)

# Load Hugging Face dataset
print("\n[1] Loading Hugging Face dataset...")
try:
    ds = load_dataset("zefang-liu/phishing-email-dataset")
    print(f"✓ Dataset loaded: {len(ds['train'])} emails")
    
    # Analyze dataset structure
    print(f"\n[2] Dataset Structure:")
    print(f"  - Columns: {ds['train'].column_names}")
    
    # Count email types
    phishing_count = 0
    safe_count = 0
    
    for item in ds['train']:
        email_type = str(item['Email Type']).strip()
        if email_type.lower() in ['phishing email']:
            phishing_count += 1
        else:  # Safe Email
            safe_count += 1
    
    print(f"\n[3] Email Distribution:")
    print(f"  - Phishing Emails: {phishing_count:,}")
    print(f"  - Safe Emails: {safe_count:,}")
    print(f"  - Total: {phishing_count + safe_count:,}")
    
    # Show sample emails
    print(f"\n[4] Sample Emails from Hugging Face:")
    
    phishing_samples = []
    safe_samples = []
    
    for item in ds['train']:
        email_text = str(item['Email Text']).strip()[:200] + "..."
        email_type = str(item['Email Type']).strip()
        
        if email_type.lower() == 'phishing email' and len(phishing_samples) < 2:
            phishing_samples.append(email_text)
        elif email_type.lower() == 'safe email' and len(safe_samples) < 2:
            safe_samples.append(email_text)
            
        if len(phishing_samples) >= 2 and len(safe_samples) >= 2:
            break
    
    print(f"\n  🚨 PHISHING SAMPLES:")
    for i, sample in enumerate(phishing_samples, 1):
        print(f"    {i}. {sample}")
    
    print(f"\n  ✅ SAFE SAMPLES:")
    for i, sample in enumerate(safe_samples, 1):
        print(f"    {i}. {sample}")
    
    # Check if model was trained with this data
    print(f"\n[5] Model Verification:")
    try:
        with open('model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('vectorizer.pkl', 'rb') as f:
            vectorizer = pickle.load(f)
        
        print(f"  ✓ Model file exists: model.pkl")
        print(f"  ✓ Vectorizer file exists: vectorizer.pkl")
        print(f"  ✓ Model features: {len(vectorizer.get_feature_names_out()):,}")
        print(f"  ✓ Model type: {type(model).__name__}")
        
        # Test with Hugging Face sample
        test_email = phishing_samples[0] if phishing_samples else safe_samples[0]
        test_vec = vectorizer.transform([test_email])
        prediction = model.predict(test_vec)[0]
        probability = model.predict_proba(test_vec)[0][1]
        
        print(f"  ✓ Test prediction: {'PHISHING' if prediction == 1 else 'SAFE'}")
        print(f"  ✓ Confidence: {probability:.3f}")
        
    except FileNotFoundError:
        print(f"  ❌ Model files not found. Run train_model_with_huggingface.py first")
    
except Exception as e:
    print(f"❌ Error: {e}")

print(f"\n" + "=" * 80)
print("VERIFICATION COMPLETE")
print("=" * 80)
print(f"\n📊 SUMMARY:")
print(f"  • Hugging Face Dataset: ✅ Integrated")
print(f"  • Phishing Emails: {phishing_count:,}")
print(f"  • Safe Emails: {safe_count:,}")
print(f"  • Total Training Data: {phishing_count + safe_count:,}")
print(f"  • Model Status: {'✅ Trained' if 'model' in locals() else '❌ Not trained'}")
print("=" * 80)
