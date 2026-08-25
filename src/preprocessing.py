import pandas as pd
import numpy as np

def clean_and_aggregate_dataset(file_path, output_csv_path=None):
    """
    WHAT: Raw CIC-IDS2017 flow data ko clean karta hai aur 5-min intervals mein aggregate karta hai.
    WHY: Raw row-level data se direct prediction nahi hoti; 5-min window metrics ML model ka input bante hain.
    """
    print(f"Reading dataset: {file_path}...")
    df = pd.read_csv(file_path)
    
    # 1. Clean Column Names
    df.columns = df.columns.str.strip()
    
    # 2. Datetime Parsing
    if 'Timestamp' in df.columns:
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='mixed', errors='coerce')
        df = df.dropna(subset=['Timestamp'])
        df = df.set_index('Timestamp').sort_index()
    else:
        raise KeyError("Timestamp column nahi mila!")

    # 3. Clean Labels (BENIGN vs ATTACK)
    if 'Label' in df.columns:
        df['Label'] = df['Label'].astype(str).str.strip()
        df['is_attack'] = df['Label'].apply(lambda x: 0 if x.upper() == 'BENIGN' else 1)
    else:
        df['is_attack'] = 0

    # 4. Handle Infinity and NaNs
    df = df.replace([np.inf, -np.inf], np.nan).dropna()

    # 5. Resample to 5-Minute Time Windows
    print("Resampling data into 5-minute time windows...")
    aggregated_df = df.resample('5min').agg(
        total_packets=('Total Fwd Packets', 'sum') if 'Total Fwd Packets' in df.columns else ('is_attack', 'count'),
        total_bytes=('Total Length of Fwd Packets', 'sum') if 'Total Length of Fwd Packets' in df.columns else ('is_attack', 'count'),
        avg_flow_duration=('Flow Duration', 'mean') if 'Flow Duration' in df.columns else ('is_attack', 'count'),
        attack_count=('is_attack', 'sum'),
        total_flows=('is_attack', 'count')
    ).fillna(0)

    # Calculate Binary Attack Target for Window (1 if attack happened in window, else 0)
    aggregated_df['target_attack'] = (aggregated_df['attack_count'] > 0).astype(int)

    if output_csv_path:
        aggregated_df.to_csv(output_csv_path)
        print(f"Cleaned & aggregated data saved to: {output_csv_path}")

    return aggregated_df

if __name__ == "__main__":
    print("Preprocessing engine ready.")