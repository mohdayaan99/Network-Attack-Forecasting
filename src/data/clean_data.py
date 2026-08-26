"""
Data cleaning module for CIC-IDS2017 dataset.
Handles: whitespace columns, duplicate columns, NaN, Inf, duplicates, timestamp parsing.
"""
import pandas as pd
import numpy as np
from pathlib import Path


def clean_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip whitespace from column names."""
    df = df.copy()
    df.columns = df.columns.str.strip()
    print(f"  Cleaned column names: {len(df.columns)} columns")
    return df


def handle_duplicate_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Remove duplicate columns (keep first occurrence)."""
    df = df.copy()
    dup_cols = df.columns[df.columns.duplicated()].tolist()
    if dup_cols:
        print(f"  Found duplicate columns: {dup_cols}")
        df = df.loc[:, ~df.columns.duplicated()]
        print(f"  Removed duplicates, remaining: {len(df.columns)} columns")
    return df


def parse_timestamps(df: pd.DataFrame) -> pd.DataFrame:
    """Parse timestamp column explicitly."""
    df = df.copy()
    # Format: M/D/YYYY H:MM (e.g., 7/7/2017 1:00)
    df['Timestamp'] = pd.to_datetime(df['Timestamp'], format='%m/%d/%Y %H:%M')
    print(f"  Parsed timestamps: range {df['Timestamp'].min()} to {df['Timestamp'].max()}")
    return df


def sort_chronologically(df: pd.DataFrame) -> pd.DataFrame:
    """Sort by timestamp."""
    df = df.copy()
    df = df.sort_values('Timestamp').reset_index(drop=True)
    print(f"  Sorted chronologically")
    return df


def handle_missing_and_infinite(df: pd.DataFrame) -> pd.DataFrame:
    """Handle NaN and infinite values in numeric columns."""
    df = df.copy()
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    # Replace inf with NaN
    inf_count = 0
    for col in numeric_cols:
        inf_mask = np.isinf(df[col])
        inf_count += inf_mask.sum()
        if inf_mask.any():
            df.loc[inf_mask, col] = np.nan
    
    # Fill NaN with column median
    nan_count = df[numeric_cols].isna().sum().sum()
    if nan_count > 0:
        df[numeric_cols] = df[numeric_cols].fillna(df[numeric_cols].median())
        print(f"  Filled {nan_count} NaN values (including {inf_count} from Inf) with column medians")
    
    return df


def remove_duplicate_rows(df: pd.DataFrame) -> pd.DataFrame:
    """Remove exact duplicate rows."""
    df = df.copy()
    dup_count = df.duplicated().sum()
    if dup_count > 0:
        df = df.drop_duplicates().reset_index(drop=True)
        print(f"  Removed {dup_count} duplicate rows")
    return df


def create_binary_label(df: pd.DataFrame) -> pd.DataFrame:
    """Create binary attack label: BENIGN=0, everything else=1. Keep original."""
    df = df.copy()
    df['original_label'] = df['Label']
    df['is_attack'] = (df['Label'] != 'BENIGN').astype(int)
    print(f"  Binary label distribution:\n{df['is_attack'].value_counts().to_string()}")
    return df


def clean_data(input_path: str, output_path: str) -> pd.DataFrame:
    """Full cleaning pipeline."""
    print(f"Loading: {input_path}")
    df = pd.read_csv(input_path)
    print(f"  Raw shape: {df.shape}")
    
    df = clean_column_names(df)
    df = handle_duplicate_columns(df)
    df = parse_timestamps(df)
    df = sort_chronologically(df)
    df = handle_missing_and_infinite(df)
    df = remove_duplicate_rows(df)
    df = create_binary_label(df)
    
    print(f"  Clean shape: {df.shape}")
    
    # Save processed data
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(output_path, index=False)
    print(f"  Saved to: {output_path}")
    
    return df


if __name__ == "__main__":
    input_file = "data/raw/Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv"
    output_file = "data/processed/cleaned_data.parquet"
    clean_data(input_file, output_file)