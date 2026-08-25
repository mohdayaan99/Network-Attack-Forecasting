import pandas as pd
import numpy as np

def clean_cic_ids_data(file_path):
    """
    WHAT: Raw CIC-IDS2017 CSV file ko clean karta hai.
    WHY: Extra spaces, missing values (NaN), aur Infinity values ML model ko crash karti hain.
    """
    print(f"Loading data from: {file_path}")
    df = pd.read_csv(file_path)
    
    print("Initial shape:", df.shape)
    
    # 1. Column names se extra spaces strip karo
    df.columns = df.columns.str.strip()
    
    # 2. Timestamp ko datetime format mein parse karo
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='mixed', errors='coerce')
    
    # 3. Label field ko standardize karo
    if 'Label' in df.columns:
        df['Label'] = df['Label'].astype(str).str.strip()
        
    # 4. Infinity values ko NaN se replace karke drop karo
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    
    # 5. Exact duplicate rows remove karo
    df = df.drop_duplicates()
    
    print("Cleaned shape:", df.shape)
    return df

if __name__ == "__main__":
    # Local testing ke liye path specify karke test kar sakte ho.
    # WARNING: CSV file ko kabhi bhi git push mat karna!
    pass