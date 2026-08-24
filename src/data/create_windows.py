"""
Create 5-minute network state windows and future attack targets.
This is the core forecasting dataset creation.
"""
import pandas as pd
import numpy as np
from pathlib import Path


WINDOW_MINUTES = 5
FORECAST_HORIZON_MINUTES = 5  # Predict next 5-minute window


def create_time_windows(df: pd.DataFrame) -> pd.DataFrame:
    """Assign each flow to a 5-minute window."""
    df = df.copy()
    # Floor timestamp to 5-minute boundary
    df['window_start'] = df['Timestamp'].dt.floor(f'{WINDOW_MINUTES}min')
    df['window_end'] = df['window_start'] + pd.Timedelta(minutes=WINDOW_MINUTES)
    print(f"  Time range: {df['window_start'].min()} to {df['window_end'].max()}")
    print(f"  Number of windows: {df['window_start'].nunique()}")
    return df


def aggregate_window_features(df: pd.DataFrame) -> pd.DataFrame:
    """Aggregate flow-level features into window-level network state features."""
    print("  Aggregating window features...")
    
    # Group by window
    grouped = df.groupby('window_start')
    
    # Basic counts
    features = pd.DataFrame()
    features['total_flows'] = grouped.size()
    features['total_packets'] = grouped['Total Fwd Packets'].sum() + grouped['Total Backward Packets'].sum()
    features['total_bytes'] = grouped['Total Length of Fwd Packets'].sum() + grouped['Total Length of Bwd Packets'].sum()
    
    # Unique IPs and ports
    features['unique_source_ips'] = grouped['Source IP'].nunique()
    features['unique_dest_ips'] = grouped['Destination IP'].nunique()
    features['unique_source_ports'] = grouped['Source Port'].nunique()
    features['unique_dest_ports'] = grouped['Destination Port'].nunique()
    
    # Protocol distribution
    features['tcp_flow_count'] = grouped.apply(lambda x: (x['Protocol'] == 6).sum())
    features['udp_flow_count'] = grouped.apply(lambda x: (x['Protocol'] == 17).sum())
    
    # TCP flag counts
    features['syn_count'] = grouped['SYN Flag Count'].sum()
    features['ack_count'] = grouped['ACK Flag Count'].sum()
    features['rst_count'] = grouped['RST Flag Count'].sum()
    features['fin_count'] = grouped['FIN Flag Count'].sum()
    features['psh_count'] = grouped['PSH Flag Count'].sum()
    features['urg_count'] = grouped['URG Flag Count'].sum()
    
    # Flow duration statistics
    features['avg_flow_duration'] = grouped['Flow Duration'].mean()
    features['max_flow_duration'] = grouped['Flow Duration'].max()
    features['std_flow_duration'] = grouped['Flow Duration'].std()
    
    # Packet size statistics
    features['avg_packet_size'] = grouped['Average Packet Size'].mean()
    features['max_packet_size'] = grouped['Max Packet Length'].max()
    features['min_packet_size'] = grouped['Min Packet Length'].min()
    features['std_packet_size'] = grouped['Packet Length Std'].mean()
    
    # Flow rate statistics
    features['avg_flow_bytes_per_sec'] = grouped['Flow Bytes/s'].mean()
    features['avg_flow_packets_per_sec'] = grouped['Flow Packets/s'].mean()
    
    # Fwd/Bwd packet ratios
    features['avg_fwd_packets'] = grouped['Total Fwd Packets'].mean()
    features['avg_bwd_packets'] = grouped['Total Backward Packets'].mean()
    features['avg_fwd_bytes'] = grouped['Total Length of Fwd Packets'].mean()
    features['avg_bwd_bytes'] = grouped['Total Length of Bwd Packets'].mean()
    
    # IAT (Inter-Arrival Time) statistics
    features['avg_flow_iat_mean'] = grouped['Flow IAT Mean'].mean()
    features['avg_fwd_iat_mean'] = grouped['Fwd IAT Mean'].mean()
    features['avg_bwd_iat_mean'] = grouped['Bwd IAT Mean'].mean()
    
    # Active/Idle statistics
    features['avg_active_mean'] = grouped['Active Mean'].mean()
    features['avg_idle_mean'] = grouped['Idle Mean'].mean()
    
    # Subflow statistics
    features['avg_subflow_fwd_pkts'] = grouped['Subflow Fwd Packets'].mean()
    features['avg_subflow_bwd_pkts'] = grouped['Subflow Bwd Packets'].mean()
    
    # Window end time for reference
    features['window_end'] = grouped['window_end'].first()
    
    # Attack label for THIS window (for reference, not for training input)
    features['window_attack_count'] = grouped['is_attack'].sum()
    features['window_attack_ratio'] = grouped['is_attack'].mean()
    features['window_dominant_label'] = grouped['original_label'].agg(lambda x: x.mode().iloc[0] if not x.mode().empty else 'BENIGN')
    
    features = features.reset_index()
    features = features.rename(columns={'window_start': 'window_start'})
    
    print(f"  Created {len(features)} windows with {len(features.columns)-2} features")
    return features


def create_future_target(features: pd.DataFrame) -> pd.DataFrame:
    """Create future attack target: attack in NEXT window?"""
    features = features.copy()
    features = features.sort_values('window_start').reset_index(drop=True)
    
    # Binary indicator: does THIS window have any attack?
    features['window_has_attack'] = (features['window_attack_count'] > 0).astype(int)
    
    # Target: is there an attack in the NEXT window? (binary)
    features['future_attack'] = features['window_has_attack'].shift(-1).fillna(0).astype(int)
    features['future_attack_ratio'] = features['window_attack_ratio'].shift(-1).fillna(0)
    features['future_dominant_label'] = features['window_dominant_label'].shift(-1).fillna('BENIGN')
    
    # The last window has no future - mark for removal
    features['has_future'] = features['future_attack'].notna()
    
    attack_windows = features['future_attack'].sum()
    total_windows = len(features) - 1  # exclude last
    print(f"  Future attack distribution: {int(attack_windows)}/{total_windows} windows ({attack_windows/total_windows*100:.1f}%)")
    
    return features


def create_forecasting_dataset(input_path: str, output_path: str) -> pd.DataFrame:
    """Full pipeline: load cleaned data -> windows -> features -> future target."""
    print(f"Loading cleaned data: {input_path}")
    df = pd.read_parquet(input_path)
    print(f"  Loaded shape: {df.shape}")
    
    df = create_time_windows(df)
    features = aggregate_window_features(df)
    features = create_future_target(features)
    
    # Remove last window (no future)
    features = features[features['has_future']].reset_index(drop=True)
    features = features.drop(columns=['has_future'])
    
    print(f"  Final dataset shape: {features.shape}")
    
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    features.to_parquet(output_path, index=False)
    print(f"  Saved to: {output_path}")
    
    return features


if __name__ == "__main__":
    input_file = "data/processed/cleaned_data.parquet"
    output_file = "data/processed/windowed_data.parquet"
    create_forecasting_dataset(input_file, output_file)