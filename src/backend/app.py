from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import os
import pandas as pd

app = FastAPI(title="Network Attack Forecasting API", version="1.0")

class NetworkWindowInput(BaseModel):
    total_packets: float
    total_bytes: float
    avg_flow_duration: float

@app.get("/")
def home():
    return {"status": "Online", "service": "Network Attack Forecasting Engine"}

@app.post("/predict")
def predict_threat(data: NetworkWindowInput):
    model_path = os.path.join("models", "baseline_model.pkl")
    
    if os.path.exists(model_path):
        model = joblib.load(model_path)
        input_df = pd.DataFrame([[data.total_packets, data.total_bytes, data.avg_flow_duration]], 
                                 columns=['total_packets', 'total_bytes', 'avg_flow_duration'])
        prob = float(model.predict_proba(input_df)[0][1])
    else:
        prob = 0.85 if data.total_packets > 300 or data.total_bytes > 20000 else 0.12

    risk_level = "HIGH" if prob > 0.7 else ("MEDIUM" if prob > 0.3 else "LOW")
    
    return {
        "attack_probability": round(prob, 4),
        "risk_level": risk_level,
        "is_threat": prob > 0.5
    }