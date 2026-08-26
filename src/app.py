import streamlit as st
import requests
import pandas as pd
import numpy as np
import time

st.set_page_config(page_title="Network Attack Forecasting", layout="wide")

st.title("🛡️ Network Attack Forecasting & Proactive Defense System")
st.markdown("Real-time network anomaly prediction & automated threat mitigation engine.")

# Sidebar Controls
st.sidebar.header("Traffic Parameters")
total_packets = st.sidebar.slider("Total Fwd Packets", 10, 1000, 150)
total_bytes = st.sidebar.slider("Total Length of Packets", 100, 50000, 1200)
avg_duration = st.sidebar.slider("Flow Duration (ms)", 1, 1000, 50)

# Main Dashboard Layout
col1, col2 = st.columns([1, 1])

with col1:
    st.subheader("📊 Live Prediction Analysis")
    if st.button("Analyze Threat Level", use_container_width=True):
        try:
            # Backend API Call
            payload = {
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "avg_flow_duration": avg_duration
            }
            res = requests.post("http://127.0.0.1:8000/predict", json=payload)
            data = res.json()
            
            st.metric("Attack Probability", f"{data.get('attack_probability', 0) * 100:.1f}%")
            
            risk = data.get('risk_level', 'LOW')
            if risk == "HIGH" or risk == "CRITICAL":
                st.error(f"⚠️ RISK LEVEL: {risk}")
            else:
                st.success(f"✅ RISK LEVEL: {risk}")

            # Attacker Path & Mitigation Details
            threat_info = data.get("threat_analysis", {})
            if threat_info:
                st.subheader("🎯 Attacker Next Move & Defense Rules")
                st.warning(f"**Detected Stage:** {threat_info.get('detected_stage')}")
                st.info(f"**Predicted Next Move:** {threat_info.get('predicted_next_move')}")
                st.error(f"**Action Required:** {threat_info.get('action_required')}")
                st.code(threat_info.get('firewall_rule'), language="bash")

        except Exception as e:
            st.error("FastAPI Backend Server connected nahi hai! Pehle uvicorn backend chalao.")

with col2:
    st.subheader("📈 Real-time Network Traffic Feed")
    chart_data = pd.DataFrame(
        np.random.randn(20, 2),
        columns=['Forward Traffic', 'Backward Traffic']
    )
    st.line_chart(chart_data)
