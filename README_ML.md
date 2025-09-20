# Flask ML Phishing Detection API

This Flask application extends the original phishing detection scanner with Machine Learning capabilities.

## Features

### Original Features
- URL scanning with suspicious content analysis
- Email validation and disposable email detection
- DNS record checking
- Health monitoring

### New ML Features
- **Dataset Upload**: Upload CSV datasets for training
- **Model Training**: Train RandomForest classifier with TF-IDF features
- **Prediction**: Get ML-based phishing predictions
- **Model Status**: Check if model is trained and ready

## Installation

1. Install dependencies:
```bash
pip install -r requirements_ml.txt
```

2. Run the application:
```bash
python flask_ml_phishing_app.py
```

The server will start on `http://localhost:5000`

## API Endpoints

### Original Endpoints
- `POST /api/scan/url` - Scan URLs for suspicious content
- `POST /api/scan/email` - Validate and analyze email addresses
- `GET /health` - Health check

### New ML Endpoints

#### 1. Upload Dataset
```http
POST /upload-dataset
Content-Type: multipart/form-data

file: dataset.csv
```

**Dataset Format:**
- CSV file with columns: `text`, `label`
- `text`: URL or email content to analyze
- `label`: "phishing" or "legitimate"

#### 2. Train Model
```http
POST /train
```

**Response:**
```json
{
  "message": "Model trained successfully",
  "training_samples": 800,
  "test_samples": 200,
  "metrics": {
    "precision": 0.9234,
    "recall": 0.9156,
    "f1_score": 0.9194
  },
  "detailed_report": {...},
  "model_saved": true
}
```

#### 3. Make Prediction
```http
POST /predict
Content-Type: application/json

{
  "text": "https://suspicious-site.com/login"
}
```

**Response:**
```json
{
  "text": "https://suspicious-site.com/login",
  "prediction": "phishing",
  "confidence": 0.8765,
  "probabilities": {
    "legitimate": 0.1235,
    "phishing": 0.8765
  }
}
```

#### 4. Check Model Status
```http
GET /model-status
```

**Response:**
```json
{
  "model_trained": true,
  "model_path": "models/random_forest_model.pkl",
  "vectorizer_path": "models/tfidf_vectorizer.pkl",
  "message": "Model is ready for predictions"
}
```

## Usage Examples

### 1. Upload and Train
```bash
# Upload dataset
curl -X POST -F "file=@sample_dataset.csv" http://localhost:5000/upload-dataset

# Train model
curl -X POST http://localhost:5000/train
```

### 2. Make Predictions
```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"text": "https://fake-bank-login.com"}'
```

### 3. Check Status
```bash
curl http://localhost:5000/model-status
```

## File Structure

```
project/
├── flask_ml_phishing_app.py    # Main Flask application
├── requirements_ml.txt         # Python dependencies
├── sample_dataset.csv          # Example training dataset
├── data/                       # Uploaded datasets
│   └── dataset.csv
└── models/                     # Trained models
    ├── random_forest_model.pkl
    └── tfidf_vectorizer.pkl
```

## ML Pipeline Details

### Data Preprocessing
- **TF-IDF Vectorization**: Converts text to numerical features
- **Feature Selection**: Max 5000 features, removes stop words
- **N-grams**: Uses unigrams and bigrams (1-2 word combinations)

### Model Training
- **Algorithm**: Random Forest Classifier
- **Parameters**: 100 trees, max depth 10, min samples split 5
- **Validation**: 80/20 train/test split with stratification

### Evaluation Metrics
- **Precision**: Accuracy of positive predictions
- **Recall**: Ability to find all positive cases
- **F1-Score**: Harmonic mean of precision and recall

## Error Handling

- Model not trained: Returns error message for `/predict` endpoint
- Invalid dataset format: Validates CSV structure and required columns
- Missing files: Checks for dataset and model files before operations

## Sample Dataset

The `sample_dataset.csv` file contains 20 examples of phishing and legitimate content for testing the ML pipeline.
