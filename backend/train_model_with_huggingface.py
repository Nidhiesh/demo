import os
import pickle
import logging
from datasets import load_dataset
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def train_model():
    logger.info("Starting model training with Hugging Face dataset...")
    
    # 1. Fetch dataset
    logger.info("Downloading dataset 'zefang-liu/phishing-email-dataset'...")
    ds = load_dataset("zefang-liu/phishing-email-dataset")
    
    # 2. Prepare data
    logger.info("Preparing data...")
    texts = []
    labels = []
    
    # We will use the train split
    for item in ds['train']:
        text = str(item.get('Email Text', '')).strip()
        label_str = str(item.get('Email Type', '')).strip().lower()
        if not text:
            continue
            
        # Labeling: 1 for phishing, 0 for safe
        if label_str == 'phishing email':
            labels.append(1)
            texts.append(text)
        elif label_str == 'safe email':
            labels.append(0)
            texts.append(text)
            
    logger.info(f"Loaded {len(texts)} samples (Phishing: {sum(labels)}, Safe: {len(labels) - sum(labels)})")
    
    # 3. Vectorize
    logger.info("Training TF-IDF Vectorizer...")
    vectorizer = TfidfVectorizer(max_features=10000, stop_words='english', max_df=0.9, min_df=5)
    X = vectorizer.fit_transform(texts)
    y = labels
    
    # 4. Train model
    logger.info("Training Logistic Regression model...")
    model = LogisticRegression(class_weight='balanced', max_iter=1000)
    model.fit(X, y)
    
    # 5. Save model and vectorizer
    logger.info("Saving updated model and vectorizer...")
    with open('vectorizer_new.pkl', 'wb') as f:
        pickle.dump(vectorizer, f)
    with open('model_new.pkl', 'wb') as f:
        pickle.dump(model, f)
        
    # Replace old files
    if os.path.exists('vectorizer.pkl'):
        os.remove('vectorizer.pkl')
    os.rename('vectorizer_new.pkl', 'vectorizer.pkl')
    
    if os.path.exists('model.pkl'):
        os.remove('model.pkl')
    os.rename('model_new.pkl', 'model.pkl')
    
    logger.info("[OK] Training complete. model.pkl and vectorizer.pkl have been updated.")
    return True

if __name__ == '__main__':
    train_model()
