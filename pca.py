import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA, IncrementalPCA
import matplotlib.pyplot as plt
import numpy as np

# File path to dataset
file_path = r"C:\Users\rauna\Downloads\CSV-01-12 (1)\01-12\TFTP.csv"

# Define chunk size
chunk_size = 10000  

# Step 1: Identify Numeric Columns
df_iter = pd.read_csv(file_path, chunksize=chunk_size, low_memory=False)
first_chunk = next(df_iter)

# Drop Known Unwanted Columns
drop_cols = ['Flow ID', 'Timestamp', 'Unnamed: 0', ' Source IP', ' Destination IP', 'SimillarHTTP']
first_chunk = first_chunk.drop(columns=[col for col in drop_cols if col in first_chunk.columns], errors='ignore')

# Drop Additional Non-Numeric Columns
df_numeric = first_chunk.select_dtypes(include=['number'])
numeric_cols = df_numeric.columns  

# Step 2: Fit StandardScaler Incrementally
scaler = StandardScaler()
for chunk in pd.read_csv(file_path, usecols=numeric_cols, chunksize=chunk_size, low_memory=False):
    chunk.replace([np.inf, -np.inf], np.nan, inplace=True)  # Convert inf to NaN
    chunk.dropna(inplace=True)  # Drop NaN values
    scaler.partial_fit(chunk)  

# Step 3: Determine n_components for 95% variance using PCA on a small batch
sample_chunk = next(pd.read_csv(file_path, usecols=numeric_cols, chunksize=chunk_size, low_memory=False))
sample_chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
sample_chunk.dropna(inplace=True)
scaled_sample = scaler.transform(sample_chunk)

pca_full = PCA().fit(scaled_sample)
explained_variance = np.cumsum(pca_full.explained_variance_ratio_)
n_components_95 = np.argmax(explained_variance >= 0.95) + 1
print(f"Selected n_components: {n_components_95}")

# Step 4: Apply Standardization and Fit IncrementalPCA in Chunks
pca = IncrementalPCA(n_components=n_components_95)
transformed_data = []

for chunk in pd.read_csv(file_path, usecols=numeric_cols, chunksize=chunk_size, low_memory=False):
    chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
    chunk.dropna(inplace=True)
    scaled_chunk = scaler.transform(np.nan_to_num(chunk))  # Ensure no NaNs or Inf
    pca.partial_fit(scaled_chunk)  

# Step 5: Transform Data in Chunks and Save
for chunk in pd.read_csv(file_path, usecols=numeric_cols, chunksize=chunk_size, low_memory=False):
    chunk.replace([np.inf, -np.inf], np.nan, inplace=True)
    chunk.dropna(inplace=True)
    scaled_chunk = scaler.transform(np.nan_to_num(chunk))
    reduced_chunk = pca.transform(scaled_chunk)  
    transformed_data.append(reduced_chunk)

df_reduced = np.vstack(transformed_data)
df_reduced = pd.DataFrame(df_reduced)
df_reduced.to_csv("CICDDoS2019_PCA.csv", index=False)

# Step 6: Visualize Explained Variance
plt.figure(figsize=(10,5))
plt.plot(np.cumsum(pca_full.explained_variance_ratio_), marker='o', linestyle='--')
plt.xlabel("Number of Components")
plt.ylabel("Cumulative Explained Variance")
plt.title("PCA - Explained Variance")
plt.grid()
plt.show()

# Step 7: Identify Most Important Features
if hasattr(pca, "components_"):
    feature_importance = abs(pca.components_).sum(axis=0)
    feature_importance_df = pd.DataFrame({'Feature': numeric_cols, 'Importance': feature_importance})
    feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)
    print(feature_importance_df.head(20))  
else:
    print("PCA components are not available. Try reducing n_components.")

















