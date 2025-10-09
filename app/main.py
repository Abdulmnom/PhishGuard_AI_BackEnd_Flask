from fastapi import FastAPI, Depends, HTTPException, status, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import text, desc

from .database import SessionLocal, engine, Base
from .models import User, ScanLog
from .schemas import RegisterRequest, UserOut, TokenResponse, LoginRequest
from .auth import hash_password, verify_password, create_access_token, decode_access_token

# --- New imports for URL scanning ---
import re
import dns.resolver
import requests
from urllib.parse import urlparse
import logging
import json as jsonlib

# --- New imports for email validation ---
from email_validator import validate_email, EmailNotValidError
from typing import Optional

# --- New imports for ML functionality ---
import pandas as pd
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, classification_report
import numpy as np
from fastapi import File, UploadFile


Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI-based Phishing Detection System - API")

# Create necessary directories for ML
import os
os.makedirs('data', exist_ok=True)
os.makedirs('models', exist_ok=True)

# --- one-time lightweight migration to drop users.full_name if exists ---
with engine.connect() as conn:
    try:
        # Check if column exists
        res = conn.execute(text("PRAGMA table_info(users)"))
        cols = [row[1] for row in res.fetchall()]
        if "full_name" in cols:
            # Recreate table without full_name
            conn.execute(text("BEGIN TRANSACTION"))
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS users_new (\n"
                "  id INTEGER PRIMARY KEY,\n"
                "  email VARCHAR(255) NOT NULL,\n"
                "  username VARCHAR(255) NOT NULL,\n"
                "  password_hash VARCHAR(255) NOT NULL\n"
                ")"
            ))
            conn.execute(text(
                "INSERT INTO users_new (id, email, username, password_hash)\n"
                "SELECT id, email, username, password_hash FROM users"
            ))
            conn.execute(text("DROP TABLE users"))
            conn.execute(text("ALTER TABLE users_new RENAME TO users"))
            # Recreate indexes/constraints
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_email ON users(email)"))
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username ON users(username)"))
            conn.execute(text("COMMIT"))
    except Exception:
        # Best-effort: ignore if migration not needed or fails
        pass

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


logger = logging.getLogger(__name__)

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "account", "verify", "secure", "update", "suspended",
    "urgent", "click", "winner", "prize", "free", "offer", "limited",
    "paypal", "amazon", "microsoft", "google", "apple", "bank", "credit",
]

# Disposable email domains (subset; extend as needed)
DISPOSABLE_EMAIL_DOMAINS = {
    "10minutemail.com", "guerrillamail.com", "mailinator.com", "tempmail.org",
    "yopmail.com", "throwaway.email", "temp-mail.org", "getnada.com",
    "maildrop.cc", "sharklasers.com", "guerrillamailblock.com", "pokemail.net",
    "spam4.me", "bccto.me", "chacuo.net", "dispostable.com", "fakeinbox.com",
    "mailnesia.com", "mytrashmail.com", "tempail.com", "trashmail.com",
}


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_optional_user_id(request: Request, db: Session) -> int | None:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    subject = decode_access_token(token)
    if subject is None:
        return None
    try:
        user_id = int(subject)
    except ValueError:
        return None
    user = db.get(User, user_id)
    return user.id if user else None


@app.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, db: Session = Depends(get_db)):
    existing_email = db.query(User).filter(User.email == payload.email).first()
    if existing_email is not None:
        raise HTTPException(status_code=400, detail="Email already registered")

    existing_username = db.query(User).filter(User.username == payload.username).first()
    if existing_username is not None:
        raise HTTPException(status_code=400, detail="Username already taken")

    user = User(
        email=payload.email,
        username=payload.username,
        password_hash=hash_password(payload.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    token = create_access_token(subject=str(user.id))
    return TokenResponse(access_token=token)


@app.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    token = create_access_token(subject=str(user.id))
    return TokenResponse(access_token=token)


# --- Helpers for URL scan ---
def validate_url_format(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc]) and result.scheme in ["http", "https"]
    except Exception:
        return False


def get_dns_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "A")
        return [str(rdata) for rdata in answers]
    except Exception as exc:
        logger.warning(f"DNS resolution failed for {domain}: {exc}")
        return []


def analyze_suspicious_content(url: str, content: str, content_type: str):
    suspicious_score = 0
    reasons = []

    url_lower = url.lower()
    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in url_lower:
            suspicious_score += 1
            reasons.append(f"Suspicious keyword in URL: {keyword}")

    if re.search(r"\d+\.\d+\.\d+\.\d+", url):
        suspicious_score += 2
        reasons.append("URL uses IP address instead of domain")

    if len(re.findall(r"[.-]", urlparse(url).netloc)) > 3:
        suspicious_score += 1
        reasons.append("URL has suspicious subdomain structure")

    if content and content_type and "text/html" in content_type.lower():
        content_lower = content.lower()
        keyword_matches = sum(1 for keyword in SUSPICIOUS_KEYWORDS if keyword in content_lower)
        if keyword_matches > 3:
            suspicious_score += keyword_matches
            reasons.append(f"Multiple suspicious keywords in content ({keyword_matches})")
        if "<form" in content_lower and ("password" in content_lower or "login" in content_lower):
            suspicious_score += 2
            reasons.append("Contains login/password form")

    return {"is_suspicious": suspicious_score > 2, "score": suspicious_score, "reasons": reasons}


# --- FastAPI endpoint for URL scan ---
@app.post("/api/scan/url")
def scan_url(payload: dict, request: Request, db: Session = Depends(get_db)):
    data = payload or {}
    url = (data.get("url") or "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    if not validate_url_format(url):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    parsed = urlparse(url)
    domain = parsed.netloc
    dns_records = get_dns_records(domain)

    response_data = {
        "reachable": False,
        "status_code": None,
        "content_type": None,
        "content_length": None,
        "dns_records": dns_records,
        "suspicious": None,
    }

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        }
        resp = requests.get(
            url,
            timeout=5,
            allow_redirects=True,
            headers=headers,
            stream=True,
        )
        response_data["reachable"] = True
        response_data["status_code"] = resp.status_code
        response_data["content_type"] = resp.headers.get("content-type", "")
        response_data["content_length"] = resp.headers.get("content-length")

        content = ""
        if response_data["content_type"].startswith("text/"):
            content = resp.content[:2000].decode("utf-8", errors="ignore")
        response_data["suspicious"] = analyze_suspicious_content(url, content, response_data["content_type"])

    except requests.exceptions.RequestException as exc:
        logger.warning(f"HTTP request failed for {url}: {exc}")
        response_data["suspicious"] = analyze_suspicious_content(url, "", "")

    # --- persist log ---
    user_id = get_optional_user_id(request, db)
    log = ScanLog(
        user_id=user_id,
        scan_type="url",
        input_value=url,
        reachable=response_data["reachable"],
        status_code=response_data["status_code"],
        result_json=jsonlib.dumps(response_data, ensure_ascii=False),
    )
    db.add(log)
    db.commit()

    return response_data


# --- Email scan helpers ---
def get_mx_records(domain: str):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def get_a_aaaa_records(domain: str):
    records = []
    try:
        answers = dns.resolver.resolve(domain, "A")
        records.extend([str(rdata) for rdata in answers])
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(domain, "AAAA")
        records.extend([str(rdata) for rdata in answers])
    except Exception:
        pass
    return records


def is_disposable_email(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_EMAIL_DOMAINS


# --- FastAPI endpoint for email scan ---
@app.post("/api/scan/email")
def scan_email(payload: dict, request: Request, db: Session = Depends(get_db)):
    data = payload or {}
    email = (data.get("email") or "").strip()
    if not email:
        raise HTTPException(status_code=400, detail="Email is required")

    try:
        valid = validate_email(email)
        email_address = valid.email
        domain = email_address.split("@")[1]
        valid_format = True
    except EmailNotValidError:
        result = {
            "valid_format": False,
            "domain": None,
            "has_mx": False,
            "mx_records": [],
            "resolved_ips": [],
            "is_disposable": False,
        }
        # persist even invalid format
        user_id = get_optional_user_id(request, db)
        log = ScanLog(
            user_id=user_id,
            scan_type="email",
            input_value=email,
            reachable=None,
            status_code=None,
            result_json=jsonlib.dumps(result, ensure_ascii=False),
        )
        db.add(log)
        db.commit()
        return result

    mx_records = get_mx_records(domain)
    has_mx = len(mx_records) > 0

    resolved_ips = []
    if not has_mx:
        resolved_ips = get_a_aaaa_records(domain)

    result = {
        "valid_format": valid_format,
        "domain": domain,
        "has_mx": has_mx,
        "mx_records": mx_records,
        "resolved_ips": resolved_ips,
        "is_disposable": is_disposable_email(domain),
    }

    user_id = get_optional_user_id(request, db)
    log = ScanLog(
        user_id=user_id,
        scan_type="email",
        input_value=email,
        reachable=None,
        status_code=None,
        result_json=jsonlib.dumps(result, ensure_ascii=False),
    )
    db.add(log)
    db.commit()

    return result


# --- Health check ---
@app.get("/health")
def health_check():
    return {"status": "healthy"}



def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    subject = decode_access_token(token)
    if subject is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = db.get(User, int(subject))
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user


@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


@app.get("/api/scan/logs")
def get_scan_logs(
    scan_type: Optional[str] = Query(default=None, pattern="^(url|email)$"),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    q = db.query(ScanLog).filter(ScanLog.user_id == current_user.id)
    if scan_type:
        q = q.filter(ScanLog.scan_type == scan_type)
    total = q.count()
    items = (
        q.order_by(desc(ScanLog.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "items": [
            {
                "id": it.id,
                "scan_type": it.scan_type,
                "input_value": it.input_value,
                "reachable": it.reachable,
                "status_code": it.status_code,
                "result": jsonlib.loads(it.result_json),
                "created_at": it.created_at.isoformat(),
            }
            for it in items
        ],
    }


# ==================== MACHINE LEARNING ENDPOINTS ====================

@app.post("/upload-dataset")
async def upload_dataset(file: UploadFile = File(...)):
    """Upload a CSV dataset for training"""
    try:
        if not file.filename.endswith('.csv'):
            raise HTTPException(status_code=400, detail="File must be a CSV")
        
        # Save uploaded file
        file_path = f"data/{file.filename}"
        with open(file_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
        
        # Validate CSV format
        try:
            df = pd.read_csv(file_path)
            if 'text' not in df.columns or 'label' not in df.columns:
                os.remove(file_path)
                raise HTTPException(
                    status_code=400, 
                    detail="CSV must contain 'text' and 'label' columns"
                )
            
            # Check label values
            unique_labels = df['label'].unique()
            if not all(label in ['phishing', 'legitimate'] for label in unique_labels):
                os.remove(file_path)
                raise HTTPException(
                    status_code=400,
                    detail="Labels must be 'phishing' or 'legitimate'"
                )
            
            return {
                "message": "Dataset uploaded successfully",
                "filename": file.filename,
                "rows": len(df),
                "columns": list(df.columns),
                "labels": unique_labels.tolist()
            }
            
        except Exception as e:
            os.remove(file_path)
            raise HTTPException(status_code=400, detail=f"Invalid CSV format: {str(e)}")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.post("/train")
async def train_model():
    """Train the machine learning model"""
    try:
        # Find the most recent CSV file
        csv_files = [f for f in os.listdir('data') if f.endswith('.csv')]
        if not csv_files:
            raise HTTPException(status_code=400, detail="No dataset found. Please upload a CSV file first.")
        
        # Use the most recent file
        latest_file = max(csv_files, key=lambda x: os.path.getctime(os.path.join('data', x)))
        file_path = f"data/{latest_file}"
        
        # Load and preprocess data
        df = pd.read_csv(file_path)
        
        # Clean text data
        df['text'] = df['text'].str.lower()
        df['text'] = df['text'].str.replace(r'[^a-zA-Z\s]', '', regex=True)
        
        # Prepare features and labels
        X = df['text']
        y = df['label'].map({'phishing': 1, 'legitimate': 0})
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Vectorize text
        vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        X_train_vec = vectorizer.fit_transform(X_train)
        X_test_vec = vectorizer.transform(X_test)
        
        # Train model
        model = RandomForestClassifier(n_estimators=100, random_state=42)
        model.fit(X_train_vec, y_train)
        
        # Evaluate model
        y_pred = model.predict(X_test_vec)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        # Save model and vectorizer
        joblib.dump(model, 'models/random_forest_model.pkl')
        joblib.dump(vectorizer, 'models/tfidf_vectorizer.pkl')
        
        return {
            "message": "Model trained successfully",
            "dataset": latest_file,
            "training_samples": len(X_train),
            "test_samples": len(X_test),
            "metrics": {
                "precision": round(precision, 3),
                "recall": round(recall, 3),
                "f1_score": round(f1, 3)
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Training failed: {str(e)}")


@app.post("/predict")
async def predict(payload: dict):
    """Make a prediction using the trained model"""
    try:
        text = payload.get('text', '').strip()
        if not text:
            raise HTTPException(status_code=400, detail="Text is required")
        
        # Check if model exists
        if not os.path.exists('models/random_forest_model.pkl') or not os.path.exists('models/tfidf_vectorizer.pkl'):
            raise HTTPException(status_code=400, detail="Model not trained. Please train the model first.")
        
        # Load model and vectorizer
        model = joblib.load('models/random_forest_model.pkl')
        vectorizer = joblib.load('models/tfidf_vectorizer.pkl')
        
        # Preprocess text
        text_clean = text.lower()
        text_clean = re.sub(r'[^a-zA-Z\s]', '', text_clean)
        
        # Vectorize
        text_vec = vectorizer.transform([text_clean])
        
        # Predict
        prediction = model.predict(text_vec)[0]
        probability = model.predict_proba(text_vec)[0]
        
        result = "phishing" if prediction == 1 else "legitimate"
        confidence = max(probability)
        
        return {
            "text": text,
            "prediction": result,
            "confidence": round(confidence, 3),
            "probabilities": {
                "legitimate": round(probability[0], 3),
                "phishing": round(probability[1], 3)
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(e)}")


@app.get("/model-status")
async def model_status():
    """Check the status of the trained model"""
    model_exists = os.path.exists('models/random_forest_model.pkl')
    vectorizer_exists = os.path.exists('models/tfidf_vectorizer.pkl')

    status = "trained" if (model_exists and vectorizer_exists) else "not_trained"

    # Get dataset info if available
    csv_files = [f for f in os.listdir('data') if f.endswith('.csv')]
    latest_dataset = None
    if csv_files:
        latest_file = max(csv_files, key=lambda x: os.path.getctime(os.path.join('data', x)))
        latest_dataset = latest_file

    return {
        "status": status,
        "model_exists": model_exists,
        "vectorizer_exists": vectorizer_exists,
        "latest_dataset": latest_dataset,
        "available_datasets": csv_files
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
