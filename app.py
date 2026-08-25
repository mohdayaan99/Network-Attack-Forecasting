"""
FastAPI backend for Network Attack Forecasting.
Supports both REAL MODEL MODE (trained Logistic Regression) and DEMO MODE (fallback).
"""
import os
import json
from pathlib import Path
from typing import Optional
from contextlib import asynccontextmanager

import numpy as np
import pandas as pd
import joblib
from fastapi import FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, validator
from typing import List, Literal


MODEL_DIR = Path("models/baseline")
FEATURE_COLS_PATH = MODEL_DIR / "feature_cols.json"
MODEL_PATH = MODEL_DIR / "model.joblib"
SCALER_PATH = MODEL_DIR / "scaler.joblib"
METRICS_PATH = MODEL_DIR / "metrics.json"

_model = None
_scaler = None
_feature_cols = None
_model_loaded = False
_model_load_error = None


class WindowFeatures(BaseModel):
    """Input features for a single 5-minute network window."""
    total_flows: float = Field(..., ge=0, description="Total number of flows in the window")
    total_packets: float = Field(..., ge=0, description="Total packets (fwd + bwd)")
    total_bytes: float = Field(..., ge=0, description="Total bytes (fwd + bwd)")
    unique_source_ips: float = Field(..., ge=0, description="Unique source IP count")
    unique_dest_ips: float = Field(..., ge=0, description="Unique destination IP count")
    unique_source_ports: float = Field(..., ge=0, description="Unique source port count")
    unique_dest_ports: float = Field(..., ge=0, description="Unique destination port count")
    tcp_flow_count: float = Field(..., ge=0, description="TCP flow count")
    udp_flow_count: float = Field(..., ge=0, description="UDP flow count")
    syn_count: float = Field(..., ge=0, description="SYN flag count")
    ack_count: float = Field(..., ge=0, description="ACK flag count")
    rst_count: float = Field(..., ge=0, description="RST flag count")
    fin_count: float = Field(..., ge=0, description="FIN flag count")
    psh_count: float = Field(..., ge=0, description="PSH flag count")
    urg_count: float = Field(..., ge=0, description="URG flag count")
    avg_flow_duration: float = Field(..., description="Average flow duration")
    max_flow_duration: float = Field(..., description="Maximum flow duration")
    std_flow_duration: float = Field(..., description="Std deviation of flow duration")
    avg_packet_size: float = Field(..., description="Average packet size")
    max_packet_size: float = Field(..., description="Maximum packet length")
    min_packet_size: float = Field(..., description="Minimum packet length")
    std_packet_size: float = Field(..., description="Std deviation of packet length")
    avg_flow_bytes_per_sec: float = Field(..., description="Average flow bytes per second")
    avg_flow_packets_per_sec: float = Field(..., description="Average flow packets per second")
    avg_fwd_packets: float = Field(..., description="Average forward packets per flow")
    avg_bwd_packets: float = Field(..., description="Average backward packets per flow")
    avg_fwd_bytes: float = Field(..., description="Average forward bytes per flow")
    avg_bwd_bytes: float = Field(..., description="Average backward bytes per flow")
    avg_flow_iat_mean: float = Field(..., description="Average flow IAT mean")
    avg_fwd_iat_mean: float = Field(..., description="Average forward IAT mean")
    avg_bwd_iat_mean: float = Field(..., description="Average backward IAT mean")
    avg_active_mean: float = Field(..., description="Average active mean")
    avg_idle_mean: float = Field(..., description="Average idle mean")
    avg_subflow_fwd_pkts: float = Field(..., description="Average subflow forward packets")
    avg_subflow_bwd_pkts: float = Field(..., description="Average subflow backward packets")

    @validator('*', pre=True)
    def replace_nan_inf(cls, v):
        if isinstance(v, float) and (np.isnan(v) or np.isinf(v)):
            return 0.0
        return v


class PredictRequest(BaseModel):
    """Request body for /predict endpoint."""
    features: WindowFeatures
    threshold: Optional[float] = Field(0.5, ge=0.0, le=1.0, description="Decision threshold for binary prediction")


class PredictResponse(BaseModel):
    """Response body for /predict endpoint."""
    attack_probability: float = Field(..., ge=0.0, le=1.0, description="Probability of attack in next 5-minute window")
    prediction: int = Field(..., ge=0, le=1, description="Binary prediction (1=attack likely, 0=normal)")
    status: Literal["ATTACK_LIKELY", "NORMAL"] = Field(..., description="Human-readable status")
    mode: Literal["REAL_MODEL", "DEMO"] = Field(..., description="Whether prediction used real model or demo fallback")
    threshold_used: float = Field(..., description="Threshold used for binary decision")


class HealthResponse(BaseModel):
    """Response body for /health endpoint."""
    status: Literal["healthy", "degraded"]
    model_loaded: bool
    model_mode: Literal["REAL_MODEL", "DEMO"]
    model_info: Optional[dict] = None


class RootResponse(BaseModel):
    """Response body for / endpoint."""
    message: str
    version: str
    endpoints: dict


def load_model_artifacts():
    """Load model, scaler, and feature columns from disk."""
    global _model, _scaler, _feature_cols, _model_loaded, _model_load_error
    
    try:
        if not MODEL_PATH.exists() or not SCALER_PATH.exists() or not FEATURE_COLS_PATH.exists():
            raise FileNotFoundError(f"Model artifacts not found in {MODEL_DIR}")
        
        _model = joblib.load(MODEL_PATH)
        _scaler = joblib.load(SCALER_PATH)
        
        with open(FEATURE_COLS_PATH) as f:
            _feature_cols = json.load(f)
        
        _model_loaded = True
        _model_load_error = None
        print(f"✅ Loaded real model from {MODEL_DIR}")
        print(f"   Features: {len(_feature_cols)}")
        
    except Exception as e:
        _model_load_error = str(e)
        _model_loaded = False
        print(f"⚠️ Failed to load real model: {e}")
        print("   Falling back to DEMO MODE")


def get_model_info() -> Optional[dict]:
    """Get model metadata if available."""
    if not METRICS_PATH.exists():
        return None
    try:
        with open(METRICS_PATH) as f:
            return json.load(f)
    except Exception:
        return None


def predict_real_model(features: WindowFeatures, threshold: float) -> tuple:
    """Predict using the real trained model."""
    if not _model_loaded:
        raise RuntimeError("Real model not loaded")
    
    # Convert to DataFrame with correct column order
    feature_dict = features.dict()
    X = pd.DataFrame([feature_dict])[_feature_cols]
    
    # Handle NaN/Inf (same as training)
    X = X.replace([np.inf, -np.inf], np.nan)
    X = X.fillna(X.median())
    
    # Scale and predict
    X_scaled = _scaler.transform(X)
    proba = float(_model.predict_proba(X_scaled)[:, 1][0])
    pred = int(proba >= threshold)
    
    return proba, pred


def predict_demo_mode(features: WindowFeatures, threshold: float) -> tuple:
    """
    Demo mode fallback: simple heuristic based on attack-like features.
    This is NOT a trained model - clearly marked as DEMO.
    """
    # Simple heuristic: high SYN count, high unique ports, high flow count -> suspicious
    syn_rate = features.syn_count / max(features.total_flows, 1)
    port_diversity = (features.unique_source_ports + features.unique_dest_ports) / max(features.total_flows, 1)
    flow_intensity = features.total_flows / 1000.0  # normalize
    
    # Heuristic score (0-1)
    score = min(1.0, (syn_rate * 2.0) + (port_diversity * 1.5) + (flow_intensity * 0.5))
    
    # Add some randomness to simulate model uncertainty
    np.random.seed(int(features.total_flows * 1000) % 2**32)
    score = np.clip(score + np.random.normal(0, 0.1), 0, 1)
    
    proba = float(score)
    pred = int(proba >= threshold)
    
    return proba, pred


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler."""
    load_model_artifacts()
    yield
    # Cleanup if needed


app = FastAPI(
    title="Network Attack Forecasting API",
    description="Predict attack likelihood in the next 5-minute window based on current network behavior",
    version="1.0.0",
    lifespan=lifespan
)


@app.get("/", response_model=RootResponse)
async def root():
    """Root endpoint with API information."""
    return RootResponse(
        message="Network Attack Forecasting API",
        version="1.0.0",
        endpoints={
            "health": "GET /health - Check API and model status",
            "predict": "POST /predict - Predict attack probability for next 5-minute window",
            "docs": "GET /docs - Interactive API documentation (Swagger UI)"
        }
    )


@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    model_info = get_model_info()
    
    if _model_loaded:
        return HealthResponse(
            status="healthy",
            model_loaded=True,
            model_mode="REAL_MODEL",
            model_info={
                "algorithm": "Logistic Regression",
                "features": len(_feature_cols) if _feature_cols else 0,
                "window_size_minutes": 5,
                "forecast_horizon_minutes": 5,
                "test_metrics": model_info.get("test") if model_info else None
            }
        )
    else:
        return HealthResponse(
            status="degraded",
            model_loaded=False,
            model_mode="DEMO",
            model_info={
                "note": "Real model not loaded, using demo fallback",
                "error": _model_load_error,
                "window_size_minutes": 5,
                "forecast_horizon_minutes": 5
            }
        )


@app.post("/predict", response_model=PredictResponse)
async def predict(request: PredictRequest):
    """
    Predict attack probability for the next 5-minute window.
    
    Input: 35 aggregated network-state features from the current 5-minute window.
    Output: Attack probability, binary prediction, and status.
    """
    features = request.features
    threshold = request.threshold
    
    try:
        if _model_loaded:
            proba, pred = predict_real_model(features, threshold)
            mode = "REAL_MODEL"
        else:
            proba, pred = predict_demo_mode(features, threshold)
            mode = "DEMO"
        
        status_str = "ATTACK_LIKELY" if pred == 1 else "NORMAL"
        
        return PredictResponse(
            attack_probability=proba,
            prediction=pred,
            status=status_str,
            mode=mode,
            threshold_used=threshold
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Prediction failed: {str(e)}"
        )


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail}
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)