import pandas as pd
import matplotlib.pyplot as plt
from collections import Counter

# Define CSV file path
csv_file = "captured_traffic.csv"  # Change to your actual file

# Load the CSV file
df = pd.read_csv(csv_file, low_memory=False)

# Ensure "Source IP" column exists
if "Source IP" not in df.columns:
    raise ValueError("The dataset must contain a 'Source IP' column.")

# Count occurrences of each unique Source IP
ip_counts = df["Source IP"].value_counts()

# Plot the data
plt.figure(figsize=(12, 6))
ip_counts.plot(kind="bar", color="skyblue", edgecolor="black")

# Customize plot
plt.xlabel("Source IP Address")
plt.ylabel("Number of Occurrences")
plt.title("Source IP Address vs. Frequency")
plt.xticks(rotation=45, ha="right", fontsize=8)  # Rotate labels for readability
plt.grid(axis="y", linestyle="--", alpha=0.7)

# Show the plot
plt.show()
