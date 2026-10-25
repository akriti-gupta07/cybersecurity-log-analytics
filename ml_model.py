from pymongo import MongoClient
import pandas as pd
import numpy as np
import time

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# 0. START TIMER
# ============================================================

total_start = time.time()


# ============================================================
# 1. CONNECT TO MONGODB
# ============================================================

client = MongoClient(
    "mongodb://localhost:27017",
    maxPoolSize=10
)

db = client["cybersecurity_db"]
collection = db["network_logs"]

print("Connected to MongoDB!")


# ============================================================
# 2. LOAD THE ENTIRE DATASET
# ============================================================

load_start = time.time()

# We are NOT using $sample here.
# We want the complete dataset.

projection = {
    "_id": 0
}

cursor = collection.find(
    {},
    projection
).batch_size(10000)

# Convert MongoDB records directly into a DataFrame
df = pd.DataFrame.from_records(cursor)

print("\nData loaded successfully!")
print("Rows:", len(df))
print("Columns:", len(df.columns))

print(
    "Data loading time:",
    round(time.time() - load_start, 2),
    "seconds"
)


# ============================================================
# 3. CLEAN COLUMN NAMES
# ============================================================

df.columns = df.columns.str.strip()


# ============================================================
# 4. LOOK AT ORIGINAL ATTACK LABELS
# ============================================================

print("\nOriginal Labels:")
print(df["Label"].value_counts())


# ============================================================
# 5. CREATE BINARY TARGET
# ============================================================

# BENIGN = Normal = 0
# Everything else = Attack = 1

df["Attack"] = (
    df["Label"] != "BENIGN"
).astype(np.int8)

print("\nNormal vs Attack:")
print(df["Attack"].value_counts())


# ============================================================
# 6. SAVE ORIGINAL ATTACK LABELS
# ============================================================

# We need these later for attack-by-attack analysis.

attack_labels = df["Label"].copy()


# ============================================================
# 7. SEPARATE FEATURES AND TARGET
# ============================================================

# Remove columns that should NOT be used by the ML model.

X = df.drop(
    columns=["Label", "Attack"],
    errors="ignore"
)

y = df["Attack"]


# ============================================================
# 8. CONVERT FEATURES TO NUMERIC
# ============================================================

# Some CIC-IDS2017 files can contain problematic values.
# errors='coerce' converts invalid values to NaN.

X = X.apply(
    pd.to_numeric,
    errors="coerce"
)


# ============================================================
# 9. HANDLE INFINITY AND MISSING VALUES
# ============================================================

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

X = X.fillna(0)


# ============================================================
# 10. REDUCE MEMORY USAGE
# ============================================================

# Random Forest can work with float32.
# float32 uses approximately half the memory of float64.

X = X.astype(
    np.float32
)

y = y.astype(
    np.int8
)

print(
    "\nMissing values after cleaning:",
    X.isna().sum().sum()
)

print(
    "Features shape:",
    X.shape
)

print(
    "Target shape:",
    y.shape
)


# ============================================================
# 11. TRAIN / TEST SPLIT
# ============================================================

split_start = time.time()

# We split indices instead of copying the entire dataset.

indices = np.arange(
    len(X)
)

train_indices, test_indices = train_test_split(
    indices,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print(
    "\nTraining rows:",
    len(train_indices)
)

print(
    "Testing rows:",
    len(test_indices)
)

print(
    "Data split time:",
    round(time.time() - split_start, 2),
    "seconds"
)


# ============================================================
# 12. CREATE TRAINING AND TESTING DATA
# ============================================================

X_train = X.iloc[
    train_indices
]

X_test = X.iloc[
    test_indices
]

y_train = y.iloc[
    train_indices
]

y_test = y.iloc[
    test_indices
]

print(
    "\nTraining data:",
    X_train.shape
)

print(
    "Testing data:",
    X_test.shape
)


# ============================================================
# 13. CREATE RANDOM FOREST
# ============================================================

model = RandomForestClassifier(
    n_estimators=100,

    # Use all available CPU cores
    n_jobs=-1,

    random_state=42
)


# ============================================================
# 14. TRAIN RANDOM FOREST
# ============================================================

print("\n==============================")
print("TRAINING RANDOM FOREST")
print("==============================")

train_start = time.time()

model.fit(
    X_train,
    y_train
)

train_time = time.time() - train_start

print(
    "\nRandom Forest training completed!"
)

print(
    "Training time:",
    round(train_time, 2),
    "seconds"
)


# ============================================================
# 15. MAKE PREDICTIONS
# ============================================================

prediction_start = time.time()

y_pred = model.predict(
    X_test
)

prediction_time = time.time() - prediction_start

print(
    "\nPredictions completed!"
)

print(
    "Number of predictions:",
    len(y_pred)
)

print(
    "Prediction time:",
    round(prediction_time, 2),
    "seconds"
)


# ============================================================
# 16. MODEL EVALUATION
# ============================================================

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n==============================")
print("MODEL RESULTS")
print("==============================")

print(
    "Accuracy:",
    accuracy
)

print(
    "\nClassification Report:"
)

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Normal",
            "Attack"
        ]
    )
)

print(
    "\nConfusion Matrix:"
)

cm = confusion_matrix(
    y_test,
    y_pred
)

print(cm)


# ============================================================
# 17. CREATE ATTACK-TYPE TEST RESULTS
# ============================================================

# Only create the small columns we actually need.
# We DO NOT copy all 78 features again.

test_attack_types = attack_labels.iloc[
    test_indices
].reset_index(drop=True)

test_actual = y_test.reset_index(
    drop=True
)

test_predicted = pd.Series(
    y_pred
)


# ============================================================
# 18. ATTACK-BY-ATTACK ANALYSIS
# ============================================================

attack_results = pd.DataFrame({
    "Attack_Type": test_attack_types,
    "Actual": test_actual,
    "Predicted": test_predicted
})

# Remove BENIGN traffic
attack_results = attack_results[
    attack_results["Attack_Type"] != "BENIGN"
]

attack_summary = (
    attack_results
    .groupby("Attack_Type")
    .agg(
        Total=("Actual", "count"),

        Correct=(
            "Predicted",
            lambda x: (x == 1).sum()
        )
    )
)

attack_summary["Detection_Rate"] = (
    attack_summary["Correct"]
    /
    attack_summary["Total"]
) * 100

attack_summary = attack_summary.sort_values(
    by="Total",
    ascending=False
)

print("\n==============================")
print("ATTACK TYPE DETECTION")
print("==============================")

print(
    attack_summary.to_string()
)


# Save attack analysis

attack_summary.to_csv(
    "attack_detection_by_type.csv"
)

print(
    "\nAttack detection analysis saved to "
    "attack_detection_by_type.csv"
)


# ============================================================
# 19. FEATURE IMPORTANCE
# ============================================================

feature_importance = pd.DataFrame({
    "Feature": X.columns,
    "Importance": model.feature_importances_
})

feature_importance = (
    feature_importance
    .sort_values(
        by="Importance",
        ascending=False
    )
)

print("\nTop 15 Important Features:")

print(
    feature_importance
    .head(15)
    .to_string(index=False)
)


feature_importance.to_csv(
    "feature_importance.csv",
    index=False
)

print(
    "\nFeature importance saved to "
    "feature_importance.csv"
)


# ============================================================
# 20. SAVE MODEL PREDICTIONS
# ============================================================

# IMPORTANT:
# We only save the information needed for analysis.
# We don't save all 78 features again.

prediction_results = pd.DataFrame({
    "Attack_Type": test_attack_types,
    "Actual": test_actual,
    "Predicted": test_predicted
})

prediction_results["Actual_Label"] = (
    prediction_results["Actual"]
    .map({
        0: "Normal",
        1: "Attack"
    })
)

prediction_results["Predicted_Label"] = (
    prediction_results["Predicted"]
    .map({
        0: "Normal",
        1: "Attack"
    })
)

prediction_results.to_csv(
    "model_predictions.csv",
    index=False
)

print(
    "\nPredictions saved to model_predictions.csv"
)


# ============================================================
# 21. ATTACK TYPE DISTRIBUTION
# ============================================================

attack_counts = (
    df["Label"]
    .value_counts()
    .reset_index()
)

attack_counts.columns = [
    "Attack_Type",
    "Count"
]

print(
    "\nAttack Type Distribution:"
)

print(
    attack_counts.to_string(
        index=False
    )
)


attack_counts.to_csv(
    "attack_distribution.csv",
    index=False
)

print(
    "\nAttack distribution saved to "
    "attack_distribution.csv"
)


# ============================================================
# 22. TOTAL EXECUTION TIME
# ============================================================

total_time = (
    time.time()
    -
    total_start
)

print("\n==============================")
print("EXECUTION SUMMARY")
print("==============================")

print(
    "Total execution time:",
    round(total_time, 2),
    "seconds"
)

print(
    "Total execution time:",
    round(total_time / 60, 2),
    "minutes"
)

print(
    "Total rows processed:",
    len(df)
)

print(
    "CPU cores used by Random Forest: ALL"
)

print("\nDone!")