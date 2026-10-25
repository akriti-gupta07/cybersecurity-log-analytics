import os
from pathlib import Path
import pandas as pd
from flask import Flask, jsonify, request
from flask_cors import CORS
from pymongo.errors import PyMongoError
from db import get_collection
from services.model_service import (
    get_model,
    predict_dataframe,
    ModelUnavailable
)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
CORS(app, resources={r"/api/*": {"origins": os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")}})

RESULTS = Path(__file__).resolve().parent.parent
def read_csv(name):
    path = RESULTS / name
    if not path.exists():
        return None
    try:
        return pd.read_csv(path)
    except Exception:
        return None

@app.get("/api/health")
def health():
    try:
        col = get_collection()
        count = col.estimated_document_count()
        return jsonify(status="ok", database="connected", collection_count=count)
    except Exception as exc:
        return jsonify(status="degraded", database="disconnected", error=str(exc)), 503

@app.get("/api/dashboard/summary")
def summary():
    try:
        col = get_collection()
        total = col.estimated_document_count()
        # CIC-IDS2017 uses Label; strip whitespace when original data was imported cleanly.
        benign = col.count_documents({"Label": "BENIGN"})
        if benign == 0:
            benign = col.count_documents({"Label": " BENIGN"})
        return jsonify(total=total, normal=benign, attack=max(total-benign, 0),
                       accuracy_percent=99.8894, source="MongoDB")
    except Exception as exc:
        # Fallback to the verified project summary if DB is unavailable.
        return jsonify(total=2830743, normal=2273097, attack=557646,
                       accuracy_percent=99.8894, source="saved project baseline",
                       warning="MongoDB unavailable; showing saved baseline", error=str(exc))

@app.get("/api/analytics/attack-types")
def attack_types():
    df = read_csv("attack_distribution.csv")
    if df is not None and len(df.columns) >= 2:
        df.columns = [str(c).strip() for c in df.columns]
        return jsonify(data=[{"attack_type": str(r.iloc[0]), "count": int(r.iloc[1])}
                             for _, r in df.iterrows()])
    try:
        col = get_collection()
        pipeline = [{"$group": {"_id": "$Label", "count": {"$sum": 1}}},
                    {"$sort": {"count": -1}}]
        return jsonify(data=[{"attack_type": x["_id"] or "Unknown", "count": x["count"]}
                             for x in col.aggregate(pipeline, allowDiskUse=True)])
    except Exception as exc:
        return jsonify(data=[], error=str(exc)), 503

@app.get("/api/analytics/detection-rates")
def detection_rates():
    df = read_csv("attack_detection_by_type.csv")
    if df is None:
        return jsonify(data=[], error="attack_detection_by_type.csv not found")
    df.columns = [str(c).strip() for c in df.columns]
    data = []
    for _, r in df.iterrows():
        rate = float(r.get("Detection_Rate", 0))
        data.append({"attack_type": str(r.get("Attack_Type", "Unknown")),
                     "total": int(r.get("Total", 0)),
                     "detection_rate": round(rate, 4)})
    return jsonify(data=data)

@app.get("/api/analytics/feature-importance")
def feature_importance():
    df = read_csv("feature_importance.csv")
    if df is None:
        return jsonify(data=[], error="feature_importance.csv not found")
    df.columns = [str(c).strip() for c in df.columns]
    feature_col = "Feature" if "Feature" in df.columns else df.columns[0]
    importance_col = "Importance" if "Importance" in df.columns else df.columns[1]
    df[importance_col] = pd.to_numeric(df[importance_col], errors="coerce").fillna(0)
    df = df.sort_values(importance_col, ascending=False).head(15)
    return jsonify(data=[{"feature": str(r[feature_col]), "importance": float(r[importance_col])}
                         for _, r in df.iterrows()])

@app.get("/api/model/metrics")
def model_metrics():
    # Use metrics calculated from the saved confusion matrix.
    return jsonify(accuracy_percent=99.8894, test_records=566149,
                   correct_predictions=565523, incorrect_predictions=626,
                   note="Accuracy is from the existing held-out test split.")

@app.get("/api/model/confusion-matrix")
def confusion_matrix():
    return jsonify(labels=["Normal", "Attack"],
                   matrix=[[454317, 303], [323, 111206]])


@app.get("/api/logs")
def logs():
    try:
        col = get_collection()

        page = max(int(request.args.get("page", 1)), 1)
        page_size = min(max(int(request.args.get("page_size", 25)), 1), 100)

        label = request.args.get("label", "").strip()
        q = request.args.get("q", "").strip()
        port = request.args.get("destination_port", "").strip()
        attacks_only = request.args.get("attacks_only", "false").lower() == "true"

        # Build the MongoDB query
        query = {}

        # Threat Detection excludes normal traffic
        if attacks_only:
            query["Label"] = {"$ne": "BENIGN"}

        # Apply the selected label
        if label:
            query["Label"] = label

            # Prevent BENIGN records from appearing in Threat Detection
            if attacks_only and label == "BENIGN":
                return jsonify(
                    data=[],
                    page=page,
                    page_size=page_size,
                    total=0
                )

        if port:
            try:
                query["Destination Port"] = int(port)
            except ValueError:
                return jsonify(error="destination_port must be an integer"), 400

        if q:
            query["$or"] = [
                {"Label": {"$regex": q, "$options": "i"}},
                {"Destination IP": {"$regex": q, "$options": "i"}},
                {"Source IP": {"$regex": q, "$options": "i"}},
            ]

        total = col.count_documents(query)

        projection = {
            "Label": 1,
            "Destination Port": 1,
            "Flow Duration": 1,
            "Total Fwd Packets": 1,
            "Total Backward Packets": 1,
            "Source IP": 1,
            "Destination IP": 1
        }

        cursor = (
            col.find(query, projection)
            .skip((page - 1) * page_size)
            .limit(page_size)
        )

        rows = []
        for doc in cursor:
            doc["_id"] = str(doc["_id"])
            rows.append(doc)

        return jsonify(
            data=rows,
            page=page,
            page_size=page_size,
            total=total
        )

    except Exception as exc:
        return jsonify(data=[], error=str(exc)), 503

@app.post("/api/predict/upload")
def predict_upload():
    if "file" not in request.files:
        return jsonify(error="Choose a CSV file first."), 400
    file = request.files["file"]
    if not file.filename.lower().endswith(".csv"):
        return jsonify(error="Only CSV files are accepted."), 400
    try:
        df = pd.read_csv(file, nrows=100001)
        if df.empty:
            return jsonify(error="The CSV has no rows."), 400
        if len(df) > 100000:
            return jsonify(error="Maximum 100,000 rows per upload. Split the file and retry."), 413
        df.columns = df.columns.str.strip()
        model = get_model()
        predictions = predict_dataframe(model, df)
        counts = pd.Series(predictions).value_counts().to_dict()
        preview = []
        for i, pred in enumerate(predictions[:200]):
            preview.append({"row": i + 1, "prediction": str(pred)})
        return jsonify(rows_processed=len(predictions),
                       normal=int(counts.get("Normal", 0)),
                       attack=int(counts.get("Attack", 0)),
                       preview=preview,
                       warning="Showing predictions for the first 200 rows in the results table.")
    except ModelUnavailable as exc:
        return jsonify(error=str(exc)), 503
    except ValueError as exc:
        return jsonify(error=str(exc)), 400
    except Exception as exc:
        return jsonify(error=f"Could not process CSV: {exc}"), 400

if __name__ == "__main__":
    app.run(debug=True, port=5000)
