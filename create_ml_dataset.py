from pymongo import MongoClient
import pandas as pd


# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017")

db = client["cybersecurity_db"]
collection = db["network_logs"]

print("Connected to MongoDB!")

# Randomly select 10,000 records ONCE
data = list(
    collection.aggregate([
        {"$sample": {"size": 100000}}
    ])
)

df = pd.DataFrame(data)

# Save the fixed dataset
df.to_csv(
    "ml_dataset.csv",
    index=False
)

print("ML dataset created successfully!")
print("Rows:", len(df))
print("Columns:", len(df.columns))
print("Saved as: ml_dataset.csv")