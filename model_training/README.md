# 📘 Machine Learning Model — Training & Integration

To enhance detection accuracy beyond classical rule-based intrusion detection, this system includes a lightweight machine learning component responsible for anomaly scoring. The ML pipeline follows these steps:

---

## **1. Feature Extraction**

For each incoming HTTP event, the model extracts four numerical features derived directly from the request:

- **path_length** — length of the URL path  
- **payload_length** — length of the request body  
- **has_admin** — binary flag if `"admin"` appears in the payload  
- **has_select** — binary flag if `"select"` appears in the payload (SQL injection indicator)  

These features match the logic used in the runtime scoring function located in  
`ids_core/model.py`.

---

## **2. Training Data Generation**

Since no real attack dataset was provided, a synthetic dataset is generated to simulate normal and malicious traffic patterns.

### **Benign examples include:**
- Paths such as `/home`, `/products`, `/login`
- Small, harmless payloads such as `"hello world"` or `"username=user&password=test"`

### **Malicious examples include:**
- Suspicious paths such as `/admin`, `/wp-admin`, `/phpmyadmin`
- Injection payloads like:
  - `' OR 1=1`
  - `UNION SELECT`
  - `DROP TABLE`
  - `'; DROP TABLE users; --`

Noise and randomness are intentionally added to avoid overfitting and to better simulate real-world variability.

---

## **3. Model Training**

A **RandomForestClassifier** with 200 trees is trained using a **75/25 train-test split**.  
Evaluation metrics such as:

- Accuracy  
- Precision & Recall  
- Confusion Matrix  

are computed automatically to validate model performance.

---

## **4. Deployment**

After training completes:

- The trained model is saved to: ids_core/model.pkl
- Additional metadata is saved to: ids_core/model_info.json
    This metadata includes:
    - Model accuracy  
    - Confusion matrix  
    - Algorithm details  
    - Timestamp of training  
    - Feature definitions  
- This info is accessible through the API endpoint: GET /model_info

---

## **5. Runtime Integration**

At runtime:

1. The API loads the trained model lazily (on first request).
2. The ML model computes an anomaly probability score for each event.
3. This ML score is **combined with the rule-based detection score** to produce a final decision.

This hybrid IDS design provides:

- **High recall:** rules catch obvious SQL injection / path anomalies  
- **Low false positives:** ML filters out normal-but-large events  
- **High transparency:** metadata available via `/model_info` and the dashboard  

---

## **Summary**

The combination of:
- rule-based detection,
- machine learning scoring,
- GCP deployment,
- and monitoring

creates a resilient, cloud-native IDS suitable for lightweight real-time detection on both Google App Engine and Google Compute Engine.


