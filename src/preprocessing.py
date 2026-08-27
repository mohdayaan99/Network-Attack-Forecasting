"""
Data Preprocessing & Dynamic Window Aggregation Pipeline for NTRO Network Attack Forecaster
"""
import os
import logging
import numpy as np
import pandas as pd
from typing import Generator, List, Optional

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PreprocessingPipeline")


def clean_network_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Cleans column names, trims whitespaces, and safely handles inf and NaN values.
    """
    # 1. Clean whitespace from headers and string columns
    df.columns = df.columns.str.strip().str.replace(' ', '_').str.lower()
    
    # 2. Replace inf and -inf with NaN, then fill or impute
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
    df[numeric_cols] = df[numeric_cols].fillna(0.0)
    
    # Fill object types if present
    object_cols = df.select_dtypes(include=['object']).columns
    df[object_cols] = df[object_cols].fillna("Unknown")

    return df


def extract_derived_features(df: pd.DataFrame) -> pd.DataFrame:
    """
    Computes packet-level metrics, scan indicators, and flow rate statistics.
    """
    # Calculate bytes per packet ratio
    packets = df["total_fwd_packets"] if "total_fwd_packets" in df.columns else df.get("total_packets", 1)
    bytes_count = df["total_length_of_fwd_packets"] if "total_length_of_fwd_packets" in df.columns else df.get("total_bytes", 0)
    
    df["bytes_per_packet"] = bytes_count / np.maximum(packets, 1)

    # Sequential Port Scan Indicator: High SYN, low packet duration, low byte transfer
    syn_count = df.get("syn_flag_count", df.get("fwd_syn_flags", 0))
    duration = np.maximum(df.get("flow_duration", 0), 1e-5)
    
    df["syn_rate"] = syn_count / duration
    df["port_scan_indicator"] = (
        (syn_count > 0) & (df["bytes_per_packet"] < 100) & (packets < 5)
    ).astype(int)

    return df


def load_dataset_in_chunks(
    filepath: str, 
    chunksize: int = 50000, 
    usecols: Optional[List[str]] = None
) -> Generator[pd.DataFrame, None, None]:
    """
    Memory-efficient chunk loader for massive CSV files (CIC-IDS2017/2018).
    """
    if not os.path.exists(filepath):
        logger.error(f"Dataset path not found: {filepath}")
        raise FileNotFoundError(f"File not found: {filepath}")

    logger.info(f"Reading {filepath} in chunks of {chunksize} rows...")
    
    for idx, chunk in enumerate(pd.read_csv(filepath, chunksize=chunksize, usecols=usecols, low_memory=False)):
        cleaned_chunk = clean_network_dataframe(chunk)
        processed_chunk = extract_derived_features(cleaned_chunk)
        logger.info(f"Chunk {idx + 1} processed: {processed_chunk.shape[0]} rows.")
        yield processed_chunk


def aggregate_sliding_windows(
    df: pd.DataFrame, 
    timestamp_col: str = "timestamp", 
    window_size: str = "5min"
) -> pd.DataFrame:
    """
    Aggregates flow metrics into dynamic time windows and calculates estimated data loss (MB).
    """
    logger.info(f"Aggregating features into {window_size} time windows...")
    
    if timestamp_col not in df.columns:
        logger.warning(f"'{timestamp_col}' not found. Generating sequential timestamps.")
        df[timestamp_col] = pd.date_range(start="2026-01-01", periods=len(df), freq="1s")

    df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    df = df.set_index(timestamp_col)

    # Aggregations for flow behavior & anomaly detection
    agg_rules = {
        "total_bytes": "sum" if "total_bytes" in df.columns else "count",
        "total_packets": "sum" if "total_packets" in df.columns else "count",
        "syn_rate": "mean" if "syn_rate" in df.columns else "count",
        "port_scan_indicator": "sum" if "port_scan_indicator" in df.columns else "count"
    }
    
    agg_rules = {k: v for k, v in agg_rules.items() if k in df.columns}
    windowed_df = df.resample(window_size).agg(agg_rules).fillna(0)

    # Compute data volume metrics in MB
    if "total_bytes" in windowed_df.columns:
        windowed_df["data_volume_mb"] = windowed_df["total_bytes"] / (1024 * 1024)
        windowed_df["est_data_risk_mb"] = np.where(
            windowed_df["port_scan_indicator"] > 0, 
            windowed_df["data_volume_mb"] * 0.25, 
            0.0
        )

    logger.info(f"Aggregation complete. Output shape: {windowed_df.shape}")
    return windowed_df.reset_index()


if __name__ == "__main__":
    logger.info("Running standalone pipeline test...")
    dummy_data = pd.DataFrame({
        " Timestamp ": pd.date_range("2026-08-28 00:00:00", periods=1000, freq="10s"),
        " Total Packets ": np.random.randint(1, 100, 1000),
        " Total Bytes ": np.random.randint(500, 500000, 1000),
        " Flow Duration ": np.random.uniform(0.1, 10.0, 1000),
        " SYN Flag Count ": np.random.choice([0, 1, 5], 1000, p=[0.8, 0.15, 0.05])
    })
    
    clean_df = clean_network_dataframe(dummy_data)
    features_df = extract_derived_features(clean_df)
    aggregated_df = aggregate_sliding_windows(features_df, timestamp_col="timestamp", window_size="5min")
    
    print("\n--- Aggregated 5-Minute Window Sample ---")
    print(aggregated_df.head())