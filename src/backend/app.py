import os
import time
import random
import logging
from typing import Dict, Any, Optional

import numpy as np
import pandas as pd
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# 1. Modules import
from src.mitigation import analyze_attacker_path
from src.preprocessing import clean_network_dataframe, extract_derived_features

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("BackendAPI")

app = FastAPI(
    title="NTRO Network Threat Detection & Attack Forecaster",
    description="Real-time network security monitoring, preprocessing pipeline, and prediction API",
    version="1.1.0"
)

# ----------------------------------------------------
# CORS Setup (Frontend Compatibility)
# ----------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------------------------------------------
# Request & Response Schemas
# ----------------------------------------------------
class NetworkMetricsRequest(BaseModel):
    total_packets: int = Field(..., ge=0, description="Total packet count")
    total_bytes: int = Field(..., ge=0, description="Total transferred bytes")
    avg_flow_duration: float = Field(..., ge=0.0, description="Average flow duration in seconds")
    packet_length_std: float = Field(..., ge=0.0, description="Standard deviation of packet length")
    syn_flag_count: int = Field(..., ge=0, description="Number of SYN flags detected")

class PredictionResponse(BaseModel):
    attack_probability: float
    risk_level: str
    is_threat: bool
    predicted_attack_type: str
    features_engineered: Dict[str, Any]
    threat_analysis: Dict[str, Any]

# ----------------------------------------------------
# Preprocessing & Inference Logic
# ----------------------------------------------------
def run_feature_pipeline(raw_metrics: NetworkMetricsRequest) -> pd.DataFrame:
    """Passes incoming network data through preprocessing and feature engineering."""
    df_raw = pd.DataFrame([{
        "total_packets": raw_metrics.total_packets,
        "total_bytes": raw_metrics.total_bytes,
        "flow_duration": raw_metrics.avg_flow_duration,
        "packet_length_std": raw_metrics.packet_length_std,
        "syn_flag_count": raw_metrics.syn_flag_count
    }])
    
    cleaned_df = clean_network_dataframe(df_raw)
    engineered_df = extract_derived_features(cleaned_df)
    return engineered_df


def predict_threat_engine(features_df: pd.DataFrame):
    """Calculates threat metrics from engineered features."""
    row = features_df.iloc[0]
    
    port_scan_detected = row.get("port_scan_indicator", 0) == 1
    syn_rate = row.get("syn_rate", 0.0)
    bytes_per_pkt = row.get("bytes_per_packet", 0.0)
    total_pkts = row.get("total_packets", 0)
    total_bytes = row.get("total_bytes", 0)

    # 1. DDoS Detection
    if total_pkts > 10000 and row.get("syn_flag_count", 0) > 500:
        return 0.95, "CRITICAL", True, "DDoS"

    # 2. PortScan Detection
    elif port_scan_detected or (syn_rate > 50.0 and bytes_per_pkt < 120):
        return 0.86, "HIGH", True, "PortScan"

    # 3. Data Exfiltration
    elif total_bytes > 50000000:
        return 0.68, "MEDIUM", True, "DataExfiltration"

    # 4. BENIGN (Normal)
    else:
        return 0.04, "LOW", False, "BENIGN"

# ----------------------------------------------------
# Endpoint: POST /predict
# ----------------------------------------------------
@app.post("/predict", response_model=PredictionResponse, status_code=status.HTTP_200_OK)
def predict_threat(input_data: NetworkMetricsRequest):
    try:
        # Step 1: Preprocess data
        proc_df = run_feature_pipeline(input_data)
        
        # Step 2: Prediction logic
        attack_prob, risk_lvl, is_threat, attack_type = predict_threat_engine(proc_df)
        
        # Step 3: Mitigation analysis
        threat_analysis = analyze_attacker_path(
            {"total_packets": input_data.total_packets, "total_bytes": input_data.total_bytes},
            attack_prob
        )
        
        engineered_meta = {
            "bytes_per_packet": round(float(proc_df.iloc[0]["bytes_per_packet"]), 2),
            "syn_rate": round(float(proc_df.iloc[0]["syn_rate"]), 2),
            "port_scan_flag": int(proc_df.iloc[0]["port_scan_indicator"])
        }

        return {
            "attack_probability": attack_prob,
            "risk_level": risk_lvl,
            "is_threat": is_threat,
            "predicted_attack_type": attack_type,
            "features_engineered": engineered_meta,
            "threat_analysis": threat_analysis
        }
    except Exception as e:
        logger.error(f"Error in /predict: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference pipeline failure: {str(e)}"
        )

# ----------------------------------------------------
# Endpoint: GET /live-feed
# ----------------------------------------------------
@app.get("/live-feed", status_code=status.HTTP_200_OK)
def get_live_feed():
    try:
        raw_simulated = {
            "total_packets": random.randint(10, 12000),
            "total_bytes": random.randint(1000, 60000000),
            "avg_flow_duration": round(random.uniform(0.1, 30.0), 2),
            "packet_length_std": round(random.uniform(5.0, 400.0), 2),
            "syn_flag_count": random.randint(0, 900),
        }
        
        req_obj = NetworkMetricsRequest(**raw_simulated)
        proc_df = run_feature_pipeline(req_obj)
        prob, risk, is_threat, attack = predict_threat_engine(proc_df)
        
        threat_analysis = analyze_attacker_path(
            {"total_packets": req_obj.total_packets, "total_bytes": req_obj.total_bytes},
            prob
        )
        
        return {
            "timestamp": int(time.time()),
            "raw_metrics": raw_simulated,
            "engineered_features": {
                "bytes_per_packet": round(float(proc_df.iloc[0]["bytes_per_packet"]), 2),
                "syn_rate": round(float(proc_df.iloc[0]["syn_rate"]), 2),
                "port_scan_indicator": int(proc_df.iloc[0]["port_scan_indicator"])
            },
            "threat_metrics": {
                "attack_probability": prob,
                "risk_level": risk,
                "is_threat": is_threat,
                "predicted_attack_type": attack,
                "threat_analysis": threat_analysis
            }
        }
    except Exception as e:
        logger.error(f"Error in /live-feed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Live simulation failure: {str(e)}"
        )