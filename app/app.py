"""
Streamlit dashboard for Network Attack Forecaster.
Supports any CIC-IDS2017 GeneratedLabelledFlows CSV file.
"""
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path
import sys

# Add src to path
sys.path.append(str(Path(__file__).parent.parent))

from src.models.predict import process_csv_for_dashboard, load_model


st.set_page_config(
    page_title="Network Attack Forecaster",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)


@st.cache_resource
def load_model_cached(model_dir):
    """Load model with caching."""
    return load_model(model_dir)


@st.cache_data
def process_csv_cached(csv_path, model_dir):
    """Process CSV with caching."""
    return process_csv_for_dashboard(csv_path, model_dir)


def find_csv_files():
    """Find available CSV files in data/raw/."""
    raw_dir = Path("data/raw")
    if raw_dir.exists():
        return list(raw_dir.glob("*.csv"))
    return []


def main():
    st.title("🛡️ Network Attack Forecaster")
    st.markdown("**MVP #1** — Predict attack likelihood in the next 5-minute window using Logistic Regression baseline")
    
    # Sidebar
    with st.sidebar:
        st.header("⚙️ Configuration")
        model_dir = st.text_input("Model Directory", value="models/baseline")
        
        st.divider()
        st.header("📁 Input Data")
        
        # File uploader (works with any CIC-IDS2017 CSV)
        uploaded_file = st.file_uploader(
            "Upload CIC-IDS2017 CSV", 
            type=["csv"],
            help="Any GeneratedLabelledFlows CSV (Monday, Tuesday, Wednesday, Thursday, Friday files)"
        )
        
        # Auto-detect local CSV files
        local_files = find_csv_files()
        local_options = ["None"] + [f.name for f in local_files]
        selected_local = st.selectbox("Or select local file:", local_options)
        
        # Demo sample (small, bundled with repo)
        use_demo = st.checkbox("Use bundled demo sample (50k rows)", value=True)
        
        if st.button("🔍 ANALYZE", type="primary", use_container_width=True):
            st.session_state.run_analysis = True
    
    # Main content
    if not st.session_state.get('run_analysis', False):
        st.info("👈 Configure settings in sidebar and click **ANALYZE** to start")
        
        # Show supported formats
        with st.expander("📋 Supported CSV Formats"):
            st.markdown("""
            **CIC-IDS2017 GeneratedLabelledFlows** (all files have same columns):
            - `Monday-WorkingHours.pcap_ISCX.csv`
            - `Tuesday-WorkingHours.pcap_ISCX.csv`
            - `Wednesday-workingHours.pcap_ISCX.csv`
            - `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv`
            - `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv`
            - `Friday-WorkingHours-Morning.pcap_ISCX.csv`
            - `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv`
            - `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`
            
            **Required columns:** Flow ID, Source IP, Source Port, Destination IP, Destination Port, Protocol, Timestamp, Flow Duration, Total Fwd Packets, Total Backward Packets, ... Label
            """)
        return
    
    # Determine input file (priority: upload > local > demo)
    csv_path = None
    
    if uploaded_file is not None:
        csv_path = "data/raw/uploaded.csv"
        Path(csv_path).parent.mkdir(parents=True, exist_ok=True)
        uploaded_file.seek(0)
        with open(csv_path, "wb") as f:
            f.write(uploaded_file.read())
        st.success(f"✅ Using uploaded file: {uploaded_file.name}")
        
    elif selected_local != "None":
        csv_path = f"data/raw/{selected_local}"
        st.success(f"✅ Using local file: {selected_local}")
        
    elif use_demo:
        csv_path = "data/raw/demo_sample.csv"
        if not Path(csv_path).exists():
            st.error("Demo sample not found. Please upload a CSV file.")
            return
        st.info("📦 Using bundled demo sample (50k rows, Friday PortScan)")
        
    else:
        st.error("Please upload a CSV file, select a local file, or enable demo sample.")
        return
    
    # Validate CSV format before processing
    try:
        test_df = pd.read_csv(csv_path, nrows=1)
        required_cols = ['Timestamp', 'Label', 'Flow Duration', 'Total Fwd Packets', 'Protocol']
        missing = [c for c in required_cols if c not in test_df.columns and c.strip() not in test_df.columns]
        if missing:
            st.warning(f"⚠️ CSV may not be CIC-IDS2017 format. Missing: {missing}")
    except Exception as e:
        st.error(f"Cannot read CSV: {e}")
        return
    
    # Run analysis
    with st.spinner("Processing data and running predictions..."):
        try:
            results_df = process_csv_cached(csv_path, model_dir)
        except Exception as e:
            st.error(f"Error processing data: {e}")
            st.exception(e)
            return
    
    # Display results
    st.success(f"✅ Analysis complete: {len(results_df)} windows processed")
    
    # Current state (latest window)
    latest = results_df.iloc[-1]
    
    st.divider()
    st.header("📊 Current Network State")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Current Window", f"{latest['window_start'].strftime('%H:%M')} – {latest['window_end'].strftime('%H:%M')}")
    with col2:
        st.metric("Future Window", f"{latest['window_end'].strftime('%H:%M')} – {(latest['window_end'] + pd.Timedelta(minutes=5)).strftime('%H:%M')}")
    with col3:
        prob_pct = latest['attack_probability'] * 100
        st.metric("Attack Probability", f"{prob_pct:.1f}%")
    with col4:
        pred_label = "⚠ ATTACK LIKELY" if latest['predicted_attack'] == 1 else "✅ NORMAL"
        st.metric("Prediction", pred_label)
    
    # Risk gauge
    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number",
        value=prob_pct,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Attack Risk"},
        gauge={
            'axis': {'range': [0, 100]},
            'bar': {'color': "darkred" if prob_pct > 50 else "darkgreen"},
            'steps': [
                {'range': [0, 30], 'color': "lightgreen"},
                {'range': [30, 70], 'color': "yellow"},
                {'range': [70, 100], 'color': "lightcoral"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 50
            }
        }
    ))
    fig_gauge.update_layout(height=300)
    st.plotly_chart(fig_gauge, use_container_width=True)
    
    # Timeline
    st.divider()
    st.header("📈 Risk Timeline")
    
    fig_timeline = go.Figure()
    
    # Actual attacks
    actual_attacks = results_df[results_df['future_attack_actual'] == 1]
    fig_timeline.add_trace(go.Scatter(
        x=actual_attacks['window_start'],
        y=actual_attacks['attack_probability'] * 100,
        mode='markers',
        name='Actual Attack (Next Window)',
        marker=dict(color='red', size=12, symbol='x'),
        hovertemplate='Time: %{x}<br>Prob: %{y:.1f}%<br>Actual: ATTACK<extra></extra>'
    ))
    
    # Normal windows
    normal_windows = results_df[results_df['future_attack_actual'] == 0]
    fig_timeline.add_trace(go.Scatter(
        x=normal_windows['window_start'],
        y=normal_windows['attack_probability'] * 100,
        mode='markers',
        name='Actual Normal (Next Window)',
        marker=dict(color='green', size=8, symbol='circle'),
        hovertemplate='Time: %{x}<br>Prob: %{y:.1f}%<br>Actual: NORMAL<extra></extra>'
    ))
    
    # Prediction line
    fig_timeline.add_trace(go.Scatter(
        x=results_df['window_start'],
        y=results_df['attack_probability'] * 100,
        mode='lines+markers',
        name='Predicted Probability',
        line=dict(color='blue', width=2),
        marker=dict(size=6),
        hovertemplate='Time: %{x}<br>Prob: %{y:.1f}%<extra></extra>'
    ))
    
    # Threshold line
    fig_timeline.add_hline(y=50, line_dash="dash", line_color="gray", 
                          annotation_text="Decision Threshold (50%)")
    
    fig_timeline.update_layout(
        xaxis_title="Time Window",
        yaxis_title="Attack Probability (%)",
        height=400,
        hovermode='x unified'
    )
    st.plotly_chart(fig_timeline, use_container_width=True)
    
    # Detailed table
    st.divider()
    st.header("📋 Detailed Results")
    
    display_df = results_df.copy()
    display_df['Time Window'] = display_df['window_start'].dt.strftime('%H:%M') + ' – ' + display_df['window_end'].dt.strftime('%H:%M')
    display_df['Future Window'] = display_df['window_end'].dt.strftime('%H:%M') + ' – ' + (display_df['window_end'] + pd.Timedelta(minutes=5)).dt.strftime('%H:%M')
    display_df['Attack Probability'] = (display_df['attack_probability'] * 100).round(1).astype(str) + '%'
    display_df['Prediction'] = display_df['predicted_attack'].map({1: '⚠ ATTACK', 0: '✅ NORMAL'})
    display_df['Actual Next Window'] = display_df['future_attack_actual'].map({1: '⚠ ATTACK', 0: '✅ NORMAL'})
    display_df['Actual Label'] = display_df['future_label']
    
    st.dataframe(
        display_df[['Time Window', 'Future Window', 'total_flows', 'Attack Probability', 
                    'Prediction', 'Actual Next Window', 'Actual Label']],
        use_container_width=True,
        hide_index=True
    )
    
    # Confusion Matrix
    st.divider()
    st.header("🎯 Model Performance (on this dataset)")
    
    y_true = results_df['future_attack_actual'].values
    y_pred = results_df['predicted_attack'].values
    y_proba = results_df['attack_probability'].values
    
    from sklearn.metrics import (precision_score, recall_score, f1_score,
                                  average_precision_score, confusion_matrix,
                                  roc_auc_score)
    
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)
    pr_auc = average_precision_score(y_true, y_proba)
    roc_auc = roc_auc_score(y_true, y_proba)
    cm = confusion_matrix(y_true, y_pred)
    
    col1, col2, col3, col4, col5, col6 = st.columns(6)
    col1.metric("Precision", f"{precision:.3f}")
    col2.metric("Recall", f"{recall:.3f}")
    col3.metric("F1 Score", f"{f1:.3f}")
    col4.metric("PR-AUC", f"{pr_auc:.3f}")
    col5.metric("ROC-AUC", f"{roc_auc:.3f}")
    col6.metric("FPR", f"{cm[0,1]/(cm[0,0]+cm[0,1]) if (cm[0,0]+cm[0,1])>0 else 0:.3f}")
    
    # Confusion matrix heatmap
    fig_cm = px.imshow(
        cm,
        text_auto=True,
        labels=dict(x="Predicted", y="Actual", color="Count"),
        x=['Normal', 'Attack'],
        y=['Normal', 'Attack'],
        color_continuous_scale='Blues'
    )
    fig_cm.update_layout(height=300, title="Confusion Matrix")
    st.plotly_chart(fig_cm, use_container_width=True)
    
    # Attack distribution
    st.divider()
    st.header("📊 Attack Distribution")
    
    dist = results_df['future_attack_actual'].value_counts().sort_index()
    fig_dist = px.bar(
        x=['Normal', 'Attack'],
        y=[dist.get(0, 0), dist.get(1, 0)],
        labels={'x': 'Class', 'y': 'Count'},
        color=['Normal', 'Attack'],
        color_discrete_map={'Normal': 'green', 'Attack': 'red'}
    )
    fig_dist.update_layout(height=300, showlegend=False)
    st.plotly_chart(fig_dist, use_container_width=True)
    
    # Model info
    st.divider()
    st.header("ℹ️ Model Info")
    model, scaler, feature_cols = load_model_cached(model_dir)
    st.write(f"**Algorithm:** Logistic Regression (class_weight=balanced)")
    st.write(f"**Features:** {len(feature_cols)} aggregated network state features")
    st.write(f"**Window Size:** 5 minutes")
    st.write(f"**Forecast Horizon:** 5 minutes (next window)")
    st.write(f"**Training:** Chronological split (60% train, 20% val, 20% test)")
    st.write(f"**Input File:** {Path(csv_path).name}")


if __name__ == "__main__":
    main()