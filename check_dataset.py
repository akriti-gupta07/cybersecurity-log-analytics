import pandas as pd

file_path = r"data/raw/Monday-WorkingHours.pcap_ISCX.csv"

df = pd.read_csv(file_path, nrows=1000)

# Remove extra spaces from column names
df.columns = df.columns.str.strip()

df.to_csv("data/processed_test.csv", index=False)

print("Test file created successfully!")
print("Rows:", len(df))
print("Columns:", len(df.columns))
print("Label column:", "Label" in df.columns)