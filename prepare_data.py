import pandas as pd

# Load the complete dataset from MongoDB later.
# For now, we'll test the label conversion on one CSV.

file_path = r"data/raw/Tuesday-WorkingHours.pcap_ISCX.csv"

df = pd.read_csv(file_path)

# Remove spaces from column names
df.columns = df.columns.str.strip()

# Create binary attack label
df["Attack"] = df["Label"].apply(
    lambda x: 0 if x == "BENIGN" else 1
)

print(df[["Label", "Attack"]].value_counts())