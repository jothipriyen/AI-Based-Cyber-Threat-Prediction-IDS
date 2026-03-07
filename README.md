# 🔐 AI-Based Authentication Threat Detection System (MVP)

## 📌 Overview

This project implements a behavior-based cybersecurity threat detection system focused on authentication activity monitoring. 

The system uses an unsupervised machine learning model (Isolation Forest) to detect anomalous login patterns and classify them into risk levels.

This is a Minimum Viable Product (MVP) demonstrating how AI can enhance authentication-layer security monitoring.

---

## 🎯 Problem Statement

Traditional cybersecurity systems are often reactive and detect breaches only after damage occurs. 

Authentication systems are common entry points for attackers through:
- Brute-force login attempts
- Credential stuffing
- Suspicious login timing
- Foreign IP access

This project provides an AI-based approach to detect suspicious login behavior early.

---

## 🧠 Solution Approach

The system follows a modular architecture:

1. **Data Ingestion**
   - Reads authentication logs from a CSV file.

2. **Feature Engineering**
   - Uses numerical features such as:
     - Login hour
     - Failed attempts
     - Foreign IP indicator

3. **Anomaly Detection**
   - Applies Isolation Forest (unsupervised learning)
   - Detects abnormal login behavior

4. **Threat Scoring**
   - Converts anomaly output into:
     - LOW RISK
     - MEDIUM RISK
     - HIGH RISK

5. **Visualization**
   - Displays results through a Flask-based dashboard

---

## 🏗 System Architecture

Authentication Logs → Feature Processing → Isolation Forest Model → Risk Classification → Web Dashboard

---

## 🛠 Tech Stack

- Python 3.11+
- Flask
- Pandas
- Scikit-learn
- HTML / CSS



---

## 🚀 How to Run the Project

### 1️⃣ Clone the Repository

git clone <your-repo-link>
cd <project-folder>


### 2️⃣ Create Virtual Environment

python -m venv venv
venv\Scripts\activate


### 3️⃣ Install Dependencies

pip install flask pandas scikit-learn


### 4️⃣ Run the Application

python app.py


### 5️⃣ Open Browser

http://127.0.0.1:5000


---

## 📊 Example Detection Scenario

| hour | failed_attempts | foreign_ip | anomaly | risk |
|------|----------------|------------|---------|------|
| 2    | 6              | 1          | -1      | HIGH RISK |

The system flags this as a high-risk authentication attempt.

---

## 🔮 Future Enhancements

- Real-time log streaming
- Email alert notifications
- Network traffic anomaly module
- Database integration
- Advanced deep learning models

---

## 👨‍💻 Authors

CyberPulse Team  
- Jothi Priyen P  
- Dharun Kaarthick S
  
---

## 📜 License

This project is developed for academic and hackathon purposes.
