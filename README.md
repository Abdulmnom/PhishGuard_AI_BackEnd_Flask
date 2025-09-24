# AI-based Phishing Detection System

<div align="center">

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-green.svg)
![Flask](https://img.shields.io/badge/Flask-2.3+-red.svg)
![SQLite](https://img.shields.io/badge/SQLite-3+-lightblue.svg)
![Machine Learning](https://img.shields.io/badge/ML-Scikit--learn-orange.svg)

**A comprehensive phishing detection system with both traditional scanning and machine learning capabilities**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [API Documentation](#api-documentation) • [Contributing](#contributing)

</div>

---

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [API Documentation](#api-documentation)
- [Machine Learning](#machine-learning)
- [Database Schema](#database-schema)
- [Security Features](#security-features)
- [Contributing](#contributing)

---

## 🎯 Overview

This project provides a comprehensive **AI-based Phishing Detection System** that combines traditional URL/email scanning techniques with advanced machine learning algorithms to identify and prevent phishing attacks. The system is built as a unified FastAPI application that includes:

1. **Authentication & User Management** - JWT-based user system
2. **Traditional Scanning** - URL and email analysis
3. **Machine Learning Detection** - AI-powered phishing detection
4. **Data Management** - Scan history and user tracking

---

## ✨ Features

### 🔐 Authentication & User Management
- **JWT-based authentication** with secure token handling
- **User registration and login** with bcrypt password hashing
- **Protected endpoints** with role-based access control
- **User profile management** with secure data handling

### 🔍 Traditional Scanning
- **URL Analysis**: DNS lookups, status codes, suspicious content detection
- **Email Validation**: MX record checks, disposable email detection
- **Real-time scanning** with comprehensive threat assessment
- **Scan history tracking** for authenticated users

### 🤖 Machine Learning Detection
- **Random Forest Classifier** for phishing detection
- **TF-IDF Vectorization** for text feature extraction
- **Dataset upload and training** capabilities
- **Real-time prediction** with confidence scores
- **Model persistence** and versioning

### 📊 Data Management
- **SQLite database** with SQLAlchemy ORM
- **Scan logging** with user association
- **Pagination and filtering** for scan history
- **Data export capabilities**

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Application                      │
│                        (Port 8000)                         │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │Authentication│  │   Scanning  │  │     ML      │        │
│  │   & Users    │  │  (URL/Email)│  │  Detection  │        │
│  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
                              │
                              │
                    ┌─────────────────┐
                    │   SQLite DB     │
                    │                 │
                    │ • Users         │
                    │ • Scan Logs     │
                    │ • ML Models     │
                    └─────────────────┘
                              │
                    ┌─────────────────┐
                    │   Frontend      │
                    │   (React)       │
                    └─────────────────┘
```

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Git

### 1. Clone the Repository
```bash
git clone https://github.com/Abdulmnom/PhishGuard_AI_BackEnd_Flask
cd PhishGuard_AI_BackEnd_Flask
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv backend
backend\Scripts\activate

# macOS/Linux
python3 -m venv backend
source backend/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Initialize Database
```bash
# The database will be created automatically on first run
python -m uvicorn app.main:app --reload
```

---

## 💻 Usage

### Start the Application

#### Start the Server:
```bash
python -m uvicorn app.main:app --reload
```

The application will be available at: `http://localhost:8000`

#### Available Endpoints:

**Authentication & User Management:**
- `POST /register` - User registration
- `POST /login` - User login
- `GET /users/me` - Get user profile

**Traditional Scanning:**
- `POST /api/scan/url` - URL analysis
- `POST /api/scan/email` - Email validation
- `GET /api/scan/logs` - Scan history

**Machine Learning:**
- `POST /upload-dataset` - Upload training data
- `POST /train` - Train ML model
- `POST /predict` - Make predictions
- `GET /model-status` - Check model status

**System:**
- `GET /health` - Health check

---

## 📚 API Documentation

### Authentication Endpoints

#### Register User
```http
POST /register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "username",
  "password": "password123"
}
```

#### Login
```http
POST /login
Content-Type: application/json

{
  "username": "username",
  "password": "password123"
}
```

### Scanning Endpoints

#### URL Scan
```http
POST /api/scan/url
Authorization: Bearer <token>
Content-Type: application/json

{
  "url": "https://example.com"
}
```

#### Email Scan
```http
POST /api/scan/email
Authorization: Bearer <token>
Content-Type: application/json

{
  "email": "test@example.com"
}
```

### Machine Learning Endpoints

#### Upload Dataset
```bash
curl -X POST -F "file=@phishing_dataset.csv" http://localhost:8000/upload-dataset
```

#### Train Model
```bash
curl -X POST http://localhost:8000/train
```

#### Make Prediction
```http
POST /predict
Content-Type: application/json

{
  "text": "Click here to win free money!"
}
```

---

## 🤖 Machine Learning

### Model Architecture
- **Algorithm**: Random Forest Classifier
- **Feature Extraction**: TF-IDF Vectorization
- **Text Processing**: Lowercase, tokenization, stop words removal
- **Evaluation Metrics**: Precision, Recall, F1-Score

### Training Process
1. **Data Upload**: CSV files with `text` and `label` columns
2. **Preprocessing**: Text cleaning and vectorization
3. **Training**: 80/20 train-test split
4. **Evaluation**: Comprehensive metrics calculation
5. **Persistence**: Model and vectorizer saved as `.pkl` files

### Dataset Format
```csv
text,label
"Click here to claim your prize!","phishing"
"Meeting scheduled for tomorrow","legitimate"
```

---

## 🗄️ Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    email VARCHAR UNIQUE,
    username VARCHAR UNIQUE,
    password_hash VARCHAR
);
```

### Scan Logs Table
```sql
CREATE TABLE scan_logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    scan_type VARCHAR,
    input_value VARCHAR,
    reachable BOOLEAN,
    status_code INTEGER,
    result_json JSON,
    created_at DATETIME
);
```

---

## 🔒 Security Features

- **Password Hashing**: bcrypt with salt
- **JWT Tokens**: Secure authentication with expiration
- **CORS Protection**: Configurable cross-origin policies
- **Input Validation**: Pydantic schemas for all endpoints
- **SQL Injection Prevention**: SQLAlchemy ORM protection
- **Rate Limiting**: Built-in request throttling
- **Error Handling**: Secure error messages without sensitive data

---

## 🧪 Testing

### Test the FastAPI Backend:
```bash
# Health check
curl http://localhost:8000/health

# Register user
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","username":"testuser","password":"password123"}'

# Login
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

### Test the ML Features:
```bash
# Upload dataset
curl -X POST -F "file=@phishing_dataset.csv" http://localhost:8000/upload-dataset

# Train model
curl -X POST http://localhost:8000/train

# Make prediction
curl -X POST http://localhost:8000/predict \
  -H "Content-Type: application/json" \
  -d '{"text":"Click here to win free money!"}'
```

---

## 📁 Project Structure

```
PhishGuard_AI_BackEnd_Flask/
├── app/                          # FastAPI application
│   ├── __init__.py
│   ├── main.py                   # Main FastAPI app (includes ML endpoints)
│   ├── database.py               # Database configuration
│   ├── models.py                 # SQLAlchemy models
│   ├── schemas.py                # Pydantic schemas
│   └── auth.py                   # Authentication utilities
├── data/                         # Dataset storage
│   └── dataset.csv
├── models/                       # ML model storage
│   ├── random_forest_model.pkl
│   └── tfidf_vectorizer.pkl
├── requirements.txt              # All dependencies (FastAPI + ML)
├── phishing_dataset.csv          # Sample dataset
├── sample_dataset.csv            # Small test dataset
├── README.md                     # This file
└── README_ML.md                  # ML-specific documentation
```

---

## 🔧 Configuration

### Environment Variables
```bash
# Application Configuration
SECRET_KEY=your-secret-key-here
DATABASE_URL=sqlite:///./app.db
UPLOAD_FOLDER=data/
MODEL_FOLDER=models/
```

### Database Configuration
- **SQLite**: File-based database for development
- **WAL Mode**: Enabled for better concurrency
- **Foreign Keys**: Enabled for data integrity
- **Connection Timeout**: 30 seconds for stability

---

## 🚀 Deployment

### Production Considerations
1. **Database**: Migrate to PostgreSQL for production
2. **Security**: Use environment variables for secrets
3. **HTTPS**: Enable SSL/TLS certificates
4. **Monitoring**: Add logging and monitoring
5. **Scaling**: Use load balancers and multiple instances

### Docker Deployment
```dockerfile
FROM python:3.9-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

---

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines
- Follow PEP 8 style guidelines
- Add tests for new features
- Update documentation
- Ensure all tests pass


<div align="center">

**⭐ Star this repository if you found it helpful!**

Made with ❤️ by [Abdulmnoum AL-brayky](https://github.com/Abdulmnom)

</div>
