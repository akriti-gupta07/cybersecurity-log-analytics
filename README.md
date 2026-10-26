# CyberGuard: Big Data Cybersecurity Log Analytics and Anomaly Detection

A cybersecurity analytics project that uses MongoDB, Python, and Machine Learning to analyze network traffic records, classify normal and malicious traffic, and visualize analytical results through an interactive web dashboard.

## Overview

CyberGuard analyzes the CIC-IDS2017 network traffic dataset to explore patterns in normal network activity and cyberattacks. It combines large-scale data storage, data preprocessing, machine learning, and web-based visualization in one system.

The project uses MongoDB to store network traffic records, a Random Forest classifier to distinguish normal traffic from attack traffic, and a web dashboard built with React and Flask to present the analysis results.

**Note:** The current implementation analyzes historical dataset records. Real-time traffic monitoring and live threat alerting are planned future enhancements.

## Key Features

- **Big Data Storage:** Stores approximately 2.83 million network traffic records in MongoDB.
- **Data Preprocessing:** Uses Python and Pandas to prepare network traffic data for analysis.
- **Machine Learning:** Implements a Random Forest classifier for binary classification of normal and attack traffic.
- **Attack Analytics:** Presents attack distribution and detection statistics.
- **Feature Importance:** Identifies features that contribute to the trained model's predictions.
- **Network Log Explorer:** Displays historical network records and supports label-based filtering.
- **Model Evaluation:** Presents classification performance and confusion matrix results.
- **Interactive Dashboard:** Provides a web interface built with React and Flask.

## Technologies Used

| Category | Technologies |
|---|---|
| Programming Language | Python, JavaScript |
| Data Processing | Pandas, NumPy |
| Machine Learning | Scikit-learn, Random Forest |
| Database | MongoDB |
| Database Connectivity | PyMongo |
| Backend | Flask, Flask API |
| Frontend | React, Vite |
| Data Visualization | Recharts |
| Dataset | CIC-IDS2017 |
| Development Tools | Visual Studio Code, Git, GitHub |

## System Architecture

The project follows this workflow:

1. **Dataset Collection:** Load network traffic records from the CIC-IDS2017 dataset.
2. **Data Preprocessing:** Use Python and Pandas to prepare the data and separate input features from target labels.
3. **Database Storage:** Store the network records in MongoDB.
4. **Model Training:** Train a Random Forest classifier using 78 input features and an 80:20 training-test split.
5. **Model Evaluation:** Evaluate the classifier using test accuracy and a confusion matrix.
6. **Backend API:** Use Flask to provide dashboard data and query MongoDB.
7. **Frontend Dashboard:** Use React to display network logs, attack statistics, feature importance, and model performance.

## Dataset

This project uses the **CIC-IDS2017** dataset, which contains labelled network traffic flows representing benign activity and different types of attacks.

- Total records: 2,830,743
- Normal records: 2,273,097
- Attack records: 557,646
- Input features used by the classifier: 78
- Classification task: Normal versus Attack

The original dataset is not included in this repository because of its size. Obtain it from the official Canadian Institute for Cybersecurity website.

Dataset source: https://www.unb.ca/cic/datasets/ids-2017.html

## Machine Learning Results

The Random Forest classifier was evaluated on the held-out test set.

| Metric | Result |
|---|---:|
| Training-test split | 80:20 |
| Test records | 566,149 |
| Test accuracy | 99.8894% |
| Correct predictions | 565,523 |
| Incorrect predictions | 626 |

### Confusion Matrix

| Actual Class | Predicted Normal | Predicted Attack |
|---|---:|---:|
| Normal | 454,317 | 303 |
| Attack | 323 | 111,206 |

These results reflect performance on the selected test dataset. They do not guarantee the same performance on real-world network traffic or previously unseen attack patterns.

## Project Structure

```text
Cybersecurity_BigData_Project/
├── backend/
│   ├── app.py
│   ├── db.py
│   ├── requirements.txt
│   └── services/
│       └── model_service.py
├── frontend/
│   ├── src/
│   │   ├── App.jsx
│   │   ├── api.js
│   │   ├── main.jsx
│   │   └── styles.css
│   ├── package.json
│   └── vite.config.js
├── attack_detection_by_type.csv
├── attack_distribution.csv
├── feature_importance.csv
├── model_predictions.csv
├── check_dataset.py
├── create_ml_dataset.py
├── import_to_mongodb.py
├── ml_model.py
├── prepare_data.py
└── .gitignore
```

## Prerequisites

Install the following before running the project:

- Python 3.11
- Node.js and npm
- MongoDB Community Server
- Git

## Setup and Installation

### 1. Clone the repository

```bash
git clone https://github.com/akriti-gupta07/cybersecurity-log-analytics.git
cd cybersecurity-log-analytics
```

### 2. Configure MongoDB

Start your local MongoDB service.

The application uses the following database configuration:

- Database: `cybersecurity_db`
- Collection: `network_logs`
- Default connection: `mongodb://localhost:27017`

Ensure the collection contains the required network records before starting the dashboard. If your database connection settings differ, configure them using the environment variables supported by your backend.

### 3. Set up the Python backend

Open a terminal in the project root and run:

**Windows PowerShell**

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Keep this terminal open while using the dashboard.

### 4. Set up the React frontend

Open a second terminal from the project root:

```powershell
cd frontend
npm install
npm run dev
```

### 5. Open the dashboard

Open the local URL printed by Vite, normally:

http://localhost:5173

The frontend requires the Flask backend and MongoDB service to be running.

## Available Dashboard Sections

- **Overview:** Summary of network records and model accuracy.
- **Attack Analytics:** Attack distribution and detection statistics.
- **Network Logs:** Browse and filter historical network records.
- **Threat Detection:** Examine historical records labelled as attacks.
- **Model Performance:** Review model metrics and confusion matrix results.

## Limitations

- The current system works with historical network traffic data rather than live traffic.
- The classifier performs binary classification: Normal or Attack.
- Performance on other datasets and real-world traffic has not been established.
- High test accuracy does not by itself establish generalization to new attack types.

## Future Enhancements

- Integrate real-time network traffic ingestion using Apache Kafka.
- Explore distributed processing with Apache Spark.
- Add live threat alerts and continuous monitoring.
- Extend classification to individual attack categories.
- Evaluate generalization using independent datasets and unseen attack scenarios.

## Security and Data Handling

- Do not commit passwords, API keys, or local `.env` files.
- Keep virtual environments and installed dependencies out of version control.
- Do not upload large raw datasets unnecessarily.
- Use `requirements.txt` and `package-lock.json` to help reproduce the development environment.

## Author

Developed as a Big Data and cybersecurity analytics project.

## License

A license has not yet been specified. Add an appropriate license before redistributing this project.
