from pymongo import MongoClient
import pandas as pd
import glob
import os

# Connect to MongoDB
client = MongoClient("mongodb://localhost:27017")

db = client["cybersecurity_db"]
collection = db["network_logs"]

print("Connected to MongoDB successfully!")

# Delete previous test data
collection.delete_many({})
print("Old test data deleted.")

# Find all CSV files
files = glob.glob(r"data/raw/*.csv")

print("CSV files found:", len(files))

total_records = 0

# Import each CSV file
for file_path in files:

    print("\nProcessing:", os.path.basename(file_path))

    df = pd.read_csv(file_path)

    # Remove extra spaces from column names
    df.columns = df.columns.str.strip()

    # Convert NaN values to None
    df = df.where(pd.notnull(df), None)

    records = df.to_dict("records")

    collection.insert_many(records)

    total_records += len(records)

    print("Records inserted:", len(records))

print("\nAll files imported successfully!")
print("Total records inserted:", total_records)