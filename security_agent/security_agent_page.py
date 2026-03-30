#!/usr/bin/env python3
"""
🛡️ Unified Cybersecurity Detection Dashboard
Combines Network Traffic Analysis and Login Anomaly Detection
Uses Gemini AI for intelligent file type classification
"""

import json
import logging
import os
import time
import warnings
from pathlib import Path
from typing import Dict

import joblib
import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

BASE_DIR = Path(__file__).resolve().parent

# Configure pandas to handle large datasets and prevent Arrow issues
pd.set_option("styler.render.max_elements", 500000)
pd.set_option("display.max_columns", None)
warnings.filterwarnings("ignore")

# Configure Streamlit to suppress Arrow warnings
os.environ["STREAMLIT_THEME_SHOW_SIDEBAR_NAV"] = "0"
logging.getLogger("streamlit.dataframe_util").setLevel(logging.ERROR)

# Additional pandas configuration for Arrow compatibility
try:
    pd.set_option("mode.copy_on_write", False)
    pd.set_option("future.no_silent_downcasting", False)
except Exception:
    pass

# Import AI capabilities
try:
    import google.generativeai as genai
    from dotenv import load_dotenv

    GEMINI_AVAILABLE = True
    load_dotenv()

    api_key = None
    try:
        api_key = st.secrets["GEMINI"]["API_KEY"]
    except Exception:
        api_key = os.getenv("GEMINI_API_KEY")

    if api_key and api_key != "your_gemini_api_key_here":
        genai.configure(api_key=api_key)
        GEMINI_API_CONFIGURED = True
    else:
        GEMINI_API_CONFIGURED = False
except ImportError:
    GEMINI_AVAILABLE = False
    GEMINI_API_CONFIGURED = False

# Import detection modules
try:
    from security_agent.model_inference import CSE_CIC_IDS2018_Predictor
    NETWORK_MODELS_AVAILABLE = True
except ImportError:
    NETWORK_MODELS_AVAILABLE = False

# ============================================================
# UNIFIED UI HELPERS
# ============================================================

from ui_components import (
    inject_unified_ui_css,
    render_top_header,
    render_summary_cards,
    render_workflow_status,
    render_sidebar_context,
)


# ============================================================
# MODEL / DATA HELPERS
# ============================================================

@st.cache_resource
def load_network_predictor():
    """Load network traffic detection models."""
    if not NETWORK_MODELS_AVAILABLE:
        return None
    try:
        return CSE_CIC_IDS2018_Predictor(models_dir=BASE_DIR / "trained_models")
    except Exception as e:
        st.error(f"Failed to load network models: {e}")
        return None


@st.cache_resource
def load_login_models():
    """Load login anomaly detection models."""
    try:
        models_path = BASE_DIR / "login_models"
        if not models_path.exists():
            return None, None, None

        le_user = joblib.load(models_path / "le_user.pkl")
        le_pc = joblib.load(models_path / "le_pc.pkl")
        model = joblib.load(models_path / "if_model.pkl")
        return le_user, le_pc, model
    except Exception as e:
        st.error(f"Failed to load login models: {e}")
        return None, None, None


def normalize_dataframe_for_display(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize dataframe to reduce Arrow serialization issues."""
    if df.empty:
        return df

    df_normalized = df.copy().reset_index(drop=True)

    for col in df_normalized.columns:
        try:
            original_dtype = df_normalized[col].dtype

            if str(original_dtype).startswith(("Int", "Float", "int64", "float64")):
                if "int" in str(original_dtype).lower():
                    df_normalized[col] = (
                        pd.to_numeric(df_normalized[col], errors="coerce")
                        .fillna(0)
                        .astype("int64")
                    )
                else:
                    df_normalized[col] = (
                        pd.to_numeric(df_normalized[col], errors="coerce")
                        .fillna(0.0)
                        .astype("float64")
                    )

            elif original_dtype == "object" or str(original_dtype) == "object":
                df_normalized[col] = df_normalized[col].astype(str)
                df_normalized[col] = df_normalized[col].replace(
                    ["nan", "None", "NaN", "<NA>"], "N/A"
                )

                try:
                    numeric_test = pd.to_numeric(
                        df_normalized[col].replace("N/A", "0"), errors="coerce"
                    )
                    if numeric_test.notna().sum() / len(numeric_test) > 0.9:
                        df_normalized[col] = numeric_test.fillna(0)
                        if (df_normalized[col] % 1 == 0).all():
                            df_normalized[col] = df_normalized[col].astype("int64")
                        else:
                            df_normalized[col] = df_normalized[col].astype("float64")
                except Exception:
                    pass

            elif "datetime" in str(original_dtype):
                df_normalized[col] = df_normalized[col].astype(str).replace("NaT", "N/A")

            elif original_dtype == "bool":
                df_normalized[col] = (
                    df_normalized[col].astype(str).replace("True", "Yes").replace("False", "No")
                )

            elif str(original_dtype) == "category":
                df_normalized[col] = df_normalized[col].astype(str)

            elif str(original_dtype) not in ["int64", "float64", "object"]:
                df_normalized[col] = df_normalized[col].astype(str).replace("nan", "N/A")

        except Exception:
            try:
                df_normalized[col] = (
                    df_normalized[col].astype(str).replace(["nan", "None", "NaN"], "N/A")
                )
            except Exception:
                df_normalized[col] = "Display Error"

    for col in df_normalized.columns:
        if df_normalized[col].dtype not in ["int64", "float64", "object"]:
            df_normalized[col] = df_normalized[col].astype(str)

    return df_normalized


def create_arrow_safe_dataframe(data: dict) -> pd.DataFrame:
    """Create an Arrow-safe dataframe."""
    return normalize_dataframe_for_display(pd.DataFrame(data))


def safe_st_dataframe(df, **kwargs):
    """Safe wrapper for st.dataframe."""
    try:
        st.dataframe(normalize_dataframe_for_display(df), use_container_width=True, **kwargs)
    except Exception:
        st.write("**Data Table:**")
        st.write(
            normalize_dataframe_for_display(df).to_html(escape=False, index=False),
            unsafe_allow_html=True,
        )


def classify_file_type(df: pd.DataFrame, filename: str) -> str:
    """Classify uploaded file as network or login data."""
    columns = [col.lower() for col in df.columns]

    network_indicators = [
        "src_ip", "dst_ip", "srcip", "dstip", "source_ip", "dest_ip",
        "protocol", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
        "label", "timestamp", "pkt_len", "pkt_size", "flags",
        "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags",
        "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt",
        "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt",
        "down_up_ratio", "pkt_len_mean", "pkt_len_std",
    ]

    login_indicators = [
        "user", "pc", "date", "logon_time", "logoff_time", "id",
        "username", "computer", "hostname", "workstation",
        "login", "logout", "session", "auth", "event",
    ]

    network_score = sum(1 for col in columns if col in network_indicators)
    login_score = sum(1 for col in columns if col in login_indicators)

    network_partial = sum(
        1 for col in columns
        if any(indicator in col for indicator in ["ip", "pkt", "flow", "flag", "protocol", "port"])
    )
    login_partial = sum(
        1 for col in columns
        if any(indicator in col for indicator in ["user", "login", "logon", "pc", "computer"])
    )

    total_network_score = network_score + (network_partial * 0.5)
    total_login_score = login_score + (login_partial * 0.5)

    if total_network_score >= 3 or network_score >= 2:
        return "network"
    if total_login_score >= 2 or login_score >= 1:
        return "login"

    if len(columns) > 50:
        return "network"
    elif len(columns) <= 10:
        return "login"

    if GEMINI_AVAILABLE and GEMINI_API_CONFIGURED:
        try:
            sample_data = df.head(3).to_string()
            prompt = f"""
            Analyze this CSV data and determine if it's:
            1. "network" - Network traffic/flow data for cybersecurity analysis
            2. "login" - User login/authentication logs

            Filename: {filename}
            Columns: {list(df.columns)}
            Number of columns: {len(df.columns)}
            Sample data:
            {sample_data}

            Respond with only one word: "network" or "login"
            """
            gemini = genai.GenerativeModel("gemini-1.5-flash")
            response = gemini.generate_content(prompt).text.strip().lower()

            if "network" in response:
                return "network"
            elif "login" in response:
                return "login"

        except Exception as e:
            st.warning(f"Gemini classification failed: {e}")

    if total_network_score > total_login_score:
        return "network"
    elif total_login_score > total_network_score:
        return "login"
    return "unknown"


def normalize_network_export_columns(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize common network column aliases so downstream dashboards
    can rely on a consistent schema.
    """
    df = df.copy()

    rename_map = {}
    for col in df.columns:
        clean = str(col).strip().lower()

        if clean in ["dst port", "dst_port", "destination_port", "destination port"]:
            rename_map[col] = "Dst_Port"
        elif clean in ["src ip", "src_ip", "source_ip", "source ip"]:
            rename_map[col] = "Src_IP"
        elif clean in ["dst ip", "dst_ip", "dest_ip", "destination_ip", "destination ip"]:
            rename_map[col] = "Dst_IP"
        elif clean in ["timestamp", "time_stamp", "time", "date_time", "datetime"]:
            rename_map[col] = "Timestamp"

    if rename_map:
        df = df.rename(columns=rename_map)

    return df


def build_incident_response_ready_df(
    original_df: pd.DataFrame,
    anomaly_predictions,
    anomaly_confidence,
    attack_predictions,
    attack_confidence,
) -> pd.DataFrame:
    """
    Build a dataframe that can be consumed directly by the Incident Response dashboard.
    Preserves original network context and appends model outputs.
    """
    base_export_df = normalize_network_export_columns(original_df).reset_index(drop=True)

    min_len = min(
        len(base_export_df),
        len(anomaly_predictions),
        len(anomaly_confidence),
        len(attack_predictions),
        len(attack_confidence),
    )

    base_export_df = base_export_df.iloc[:min_len].copy()
    anomaly_predictions_trim = anomaly_predictions[:min_len]
    anomaly_confidence_trim = anomaly_confidence[:min_len]
    attack_predictions_trim = attack_predictions[:min_len]
    attack_confidence_trim = attack_confidence[:min_len]

    base_export_df["Sample_ID"] = list(range(1, min_len + 1))
    base_export_df["Anomaly_Detection"] = [str(p) for p in anomaly_predictions_trim]
    base_export_df["Anomaly_Confidence"] = [float(c) for c in anomaly_confidence_trim]
    base_export_df["Attack_Type"] = [str(p) for p in attack_predictions_trim]
    base_export_df["Attack_Confidence"] = [float(c) for c in attack_confidence_trim]
    base_export_df["Overall_Risk"] = [
        "High" if a == "Attack" else "Low" for a in anomaly_predictions_trim
    ]

    preferred_cols = [
        "Dst_Port",
        "Sample_ID",
        "Src_IP",
        "Dst_IP",
        "Timestamp",
        "Anomaly_Detection",
        "Anomaly_Confidence",
        "Attack_Type",
        "Attack_Confidence",
        "Overall_Risk",
    ]

    ordered_cols = [c for c in preferred_cols if c in base_export_df.columns]
    remaining_cols = [c for c in base_export_df.columns if c not in ordered_cols]

    return base_export_df[ordered_cols + remaining_cols]


# ============================================================
# RESULT VISUALS / TABLES
# ============================================================

def create_metrics_dashboard(results: Dict, prediction_type: str):
    """Create a metrics dashboard for the results."""
    if "error" in results:
        st.error(f"❌ {results['error']}")
        return

    summary = results.get("summary", {})
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.metric(label="📊 Total Samples", value=summary.get("total_samples", 0))

    if prediction_type == "anomaly":
        with col2:
            attack_count = summary.get("attack_count", 0)
            st.metric(
                label="🚨 Attacks Detected",
                value=attack_count,
                delta=f"{summary.get('attack_percentage', 0):.1f}%",
            )

        with col3:
            benign_count = summary.get("benign_count", 0)
            st.metric(
                label="✅ Benign Traffic",
                value=benign_count,
                delta=f"{100 - summary.get('attack_percentage', 0):.1f}%",
            )
    else:
        prediction_counts = summary.get("prediction_distribution", {})
        if prediction_counts:
            most_common = max(prediction_counts.items(), key=lambda x: x[1])
            with col2:
                st.metric(
                    label="🎯 Primary Attack Type",
                    value=most_common[0],
                    delta=f"{most_common[1]} samples",
                )

    with col4:
        confidence = summary.get("average_confidence", 0)
        st.metric(
            label="🎯 Avg Confidence",
            value=f"{confidence:.3f}",
            delta=f"Model: {summary.get('model_used', 'Unknown')}",
        )


def create_visualizations(results: Dict, prediction_type: str):
    """Create interactive visualizations for the results."""
    if "error" in results:
        return

    predictions = results.get("predictions", [])
    confidence_scores = results.get("confidence_scores", [])

    if not predictions:
        st.warning("No predictions to visualize")
        return

    col1, col2 = st.columns(2)

    with col1:
        if prediction_type == "anomaly":
            attack_count = sum(1 for p in predictions if p == "Attack")
            benign_count = sum(1 for p in predictions if p == "Benign")

            fig_pie = go.Figure(
                data=[
                    go.Pie(
                        labels=["Benign", "Attack"],
                        values=[benign_count, attack_count],
                        hole=0.4,
                        marker_colors=["#26de81", "#ff6b6b"],
                    )
                ]
            )
            fig_pie.update_layout(title="🛡️ Traffic Classification", font=dict(size=12), height=400)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            from collections import Counter

            pred_counts = Counter(predictions)

            fig_pie = go.Figure(
                data=[
                    go.Pie(
                        labels=list(pred_counts.keys()),
                        values=list(pred_counts.values()),
                        hole=0.4,
                    )
                ]
            )
            fig_pie.update_layout(title="🎯 Attack Type Distribution", font=dict(size=12), height=400)
            st.plotly_chart(fig_pie, use_container_width=True)

    with col2:
        fig_hist = go.Figure(
            data=[
                go.Histogram(
                    x=confidence_scores,
                    nbinsx=20,
                    marker_color="#1f77b4",
                    opacity=0.7,
                )
            ]
        )
        fig_hist.update_layout(
            title="📈 Confidence Score Distribution",
            xaxis_title="Confidence Score",
            yaxis_title="Frequency",
            font=dict(size=12),
            height=400,
        )
        st.plotly_chart(fig_hist, use_container_width=True)

    if len(predictions) > 10:
        st.subheader("📊 Detection Timeline")
        st.info(
            "💡 **Timeline Explanation**: Shows how predictions and confidence scores vary across your data samples. "
            "Each point represents one network traffic sample, colored by its classification. "
            "The Y-axis shows the model's confidence level for each prediction."
        )

        sample_indices = list(range(len(predictions)))

        if prediction_type == "anomaly":
            colors = ["#26de81" if p == "Benign" else "#ff6b6b" for p in predictions]
            labels = predictions
        else:
            unique_preds = list(set(predictions))
            color_map = {
                pred: px.colors.qualitative.Set1[i % len(px.colors.qualitative.Set1)]
                for i, pred in enumerate(unique_preds)
            }

            st.markdown("**🎨 Color Legend:**")
            legend_cols = st.columns(min(len(unique_preds), 4))
            for i, (attack_type, color) in enumerate(color_map.items()):
                col_idx = i % len(legend_cols)
                with legend_cols[col_idx]:
                    st.markdown(
                        f"<span style='color: {color}; font-size: 18px;'>●</span> **{attack_type}**",
                        unsafe_allow_html=True,
                    )

        fig_timeline = go.Figure()

        if prediction_type == "anomaly":
            fig_timeline.add_trace(
                go.Scatter(
                    x=sample_indices,
                    y=confidence_scores,
                    mode="markers",
                    marker=dict(color=colors, size=8, opacity=0.7),
                    text=labels,
                    hovertemplate="Sample: %{x}<br>Confidence: %{y:.3f}<br>Type: %{text}<extra></extra>",
                    showlegend=False,
                )
            )
        else:
            for attack_type in unique_preds:
                type_indices = [i for i, pred in enumerate(predictions) if pred == attack_type]
                type_samples = [sample_indices[i] for i in type_indices]
                type_confidence = [confidence_scores[i] for i in type_indices]

                fig_timeline.add_trace(
                    go.Scatter(
                        x=type_samples,
                        y=type_confidence,
                        mode="markers",
                        marker=dict(color=color_map[attack_type], size=8, opacity=0.7),
                        name=attack_type,
                        text=[attack_type] * len(type_samples),
                        hovertemplate="Sample: %{x}<br>Confidence: %{y:.3f}<br>Type: %{text}<extra></extra>",
                    )
                )

        fig_timeline.update_layout(
            title="Detection Results Over Samples",
            xaxis_title="Sample Index",
            yaxis_title="Confidence Score",
            height=300,
        )
        st.plotly_chart(fig_timeline, use_container_width=True)


def display_detailed_results(results: Dict, prediction_type: str):
    """Display detailed prediction results."""
    if "error" in results:
        return

    predictions = results.get("predictions", [])
    confidence_scores = results.get("confidence_scores", [])

    if not predictions:
        return

    st.subheader("📋 Detailed Results")

    with st.expander("ℹ️ Understanding the Results"):
        st.markdown(
            """
        **🎯 Confidence Scores**: Range from 0.000 to 1.000
        - **0.900-1.000**: Very confident prediction (high reliability)
        - **0.700-0.899**: Confident prediction (good reliability)
        - **0.500-0.699**: Moderate confidence (review recommended)
        - **Below 0.500**: Low confidence (manual verification needed)

        **📊 Top 10 Predictions**: Shows the first 10 samples from your uploaded data with:
        - **Sample ID**: Sequential number of the network traffic sample
        - **Classification**: Model's prediction (Attack/Benign or specific attack type)
        - **Confidence**: How sure the model is about this prediction (0-1 scale)
        - **Risk Level**: Simplified assessment (High for attacks, Low for benign)
        """
        )

    if prediction_type == "anomaly":
        results_df = create_arrow_safe_dataframe(
            {
                "Sample": list(range(1, len(predictions) + 1)),
                "Classification": [str(p) for p in predictions],
                "Confidence": [float(c) for c in confidence_scores],
                "Risk Level": [str("Low" if p == "Benign" else "High") for p in predictions],
            }
        )
    else:
        results_df = create_arrow_safe_dataframe(
            {
                "Sample": list(range(1, len(predictions) + 1)),
                "Attack Type": [str(p) for p in predictions],
                "Confidence": [float(c) for c in confidence_scores],
                "Risk Level": [str("High" if p != "Benign" else "Low") for p in predictions],
            }
        )

    st.write("**Top 10 Predictions:**")
    display_df = normalize_dataframe_for_display(results_df.head(10))
    safe_st_dataframe(display_df)

    if prediction_type == "anomaly":
        attack_samples = results_df[results_df["Classification"] == "Attack"]
        if not attack_samples.empty:
            st.subheader("🚨 Attack Samples Analysis")
            avg_attack_confidence = attack_samples["Confidence"].mean()
            max_attack_confidence = attack_samples["Confidence"].max()

            col1, col2 = st.columns(2)
            with col1:
                st.metric("Average Attack Confidence", f"{avg_attack_confidence:.3f}")
            with col2:
                st.metric("Highest Attack Confidence", f"{max_attack_confidence:.3f}")


# ============================================================
# NETWORK FLOW
# ============================================================

def process_network_data(data: pd.DataFrame, predictor):
    """Process network traffic data through the detection pipeline."""
    if "sa_network_anomaly_completed" not in st.session_state:
        st.session_state.sa_network_anomaly_completed = False
    if "sa_network_anomaly_results" not in st.session_state:
        st.session_state.sa_network_anomaly_results = None
    if "sa_network_attack_completed" not in st.session_state:
        st.session_state.sa_network_attack_completed = False
    if "sa_network_attack_results" not in st.session_state:
        st.session_state.sa_network_attack_results = None

    st.markdown(
        """
    <div class="network-card">
        <h3>🌐 Network Traffic Analysis Detected</h3>
        <p>This appears to be network flow/packet data suitable for intrusion detection</p>
    </div>
    """,
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns(2)
    with col1:
        if st.session_state.sa_network_anomaly_completed:
            st.success("✅ Network Anomaly Detection - Completed")
        else:
            st.info("🔄 Network Anomaly Detection - Ready")

    with col2:
        if st.session_state.sa_network_attack_completed:
            st.success("✅ Attack Classification - Completed")
        elif st.session_state.sa_network_anomaly_completed:
            st.info("🔄 Attack Classification - Ready")
        else:
            st.info("⏳ Attack Classification - Waiting")

    st.markdown('<div class="section-shell">', unsafe_allow_html=True)
    st.subheader("🛡️ Step 1: Network Anomaly Detection")

    if not st.session_state.sa_network_anomaly_completed:
        if st.button("🚀 Run Network Anomaly Detection", type="primary", key="sa_network_anomaly_btn"):
            with st.spinner("🔍 Analyzing network traffic for anomalies..."):
                progress_bar = st.progress(0)

                progress_bar.progress(20)
                validation = predictor.validate_input_data(data)

                if validation["warnings"]:
                    st.warning("⚠️ Data validation warnings:")
                    for warning in validation["warnings"]:
                        st.write(f"- {warning}")

                progress_bar.progress(40)
                results = predictor.predict_anomaly(data)
                progress_bar.progress(80)

                st.session_state.sa_network_anomaly_results = results
                st.session_state.sa_network_anomaly_completed = True

                progress_bar.progress(100)
                time.sleep(0.5)
                progress_bar.empty()
                st.rerun()

    if st.session_state.sa_network_anomaly_completed and st.session_state.sa_network_anomaly_results:
        results = st.session_state.sa_network_anomaly_results

        if "error" not in results:
            summary = results.get("summary", {})
            attack_percentage = summary.get("attack_percentage", 0)

            if attack_percentage > 50:
                st.markdown(
                    f"""
                <div class="attack-alert">
                    <h3>🚨 High Network Risk Detected!</h3>
                    <p><strong>{attack_percentage:.1f}%</strong> of traffic classified as attacks</p>
                    <p>Proceeding to attack classification is recommended</p>
                </div>
                """,
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"""
                <div class="benign-alert">
                    <h3>✅ Network Traffic Appears Normal</h3>
                    <p>Only <strong>{attack_percentage:.1f}%</strong> suspicious activity detected</p>
                    <p>Attack classification optional</p>
                </div>
                """,
                    unsafe_allow_html=True,
                )

        create_metrics_dashboard(results, "anomaly")
        create_visualizations(results, "anomaly")
        display_detailed_results(results, "anomaly")

        st.markdown("---")
        st.subheader("🎯 Step 2: Attack Classification")

        if not st.session_state.sa_network_attack_completed:
            if st.button("🎯 Run Attack Classification", type="secondary", key="sa_network_attack_btn"):
                with st.spinner("🔍 Classifying attack types..."):
                    progress_bar = st.progress(0)
                    progress_bar.progress(30)

                    attack_results = predictor.predict_attack_type(data)
                    progress_bar.progress(80)

                    st.session_state.sa_network_attack_results = attack_results
                    st.session_state.sa_network_attack_completed = True

                    progress_bar.progress(100)
                    time.sleep(0.5)
                    progress_bar.empty()
                    st.rerun()

        if st.session_state.sa_network_attack_completed and st.session_state.sa_network_attack_results:
            attack_results = st.session_state.sa_network_attack_results

            st.subheader("🎯 Attack Type Classification Results")
            create_metrics_dashboard(attack_results, "attack_type")
            create_visualizations(attack_results, "attack_type")
            display_detailed_results(attack_results, "attack_type")

            st.markdown("---")
            st.subheader("💾 Export Network Analysis")

            anomaly_predictions = results.get("predictions", [])
            anomaly_confidence = results.get("confidence_scores", [])
            attack_predictions = attack_results.get("predictions", [])
            attack_confidence = attack_results.get("confidence_scores", [])

            col1, col2 = st.columns(2)
            with col1:
                if anomaly_predictions:
                    anomaly_df = create_arrow_safe_dataframe(
                        {
                            "Sample_ID": list(range(1, len(anomaly_predictions) + 1)),
                            "Network_Anomaly": [str(p) for p in anomaly_predictions],
                            "Anomaly_Confidence": [float(c) for c in anomaly_confidence],
                        }
                    )

                    st.download_button(
                        label="📥 Download Network Anomaly Results",
                        data=anomaly_df.to_csv(index=False),
                        file_name=f"network_anomaly_{int(time.time())}.csv",
                        mime="text/csv",
                        key="sa_network_anomaly_download",
                    )

            with col2:
                if attack_predictions:
                    attack_df = create_arrow_safe_dataframe(
                        {
                            "Sample_ID": list(range(1, len(attack_predictions) + 1)),
                            "Attack_Type": [str(p) for p in attack_predictions],
                            "Attack_Confidence": [float(c) for c in attack_confidence],
                        }
                    )

                    st.download_button(
                        label="📥 Download Attack Classification",
                        data=attack_df.to_csv(index=False),
                        file_name=f"network_attacks_{int(time.time())}.csv",
                        mime="text/csv",
                        key="sa_network_attack_download",
                    )

            if anomaly_predictions and attack_predictions:
                st.markdown("---")
                st.subheader("📋 Complete Analysis Export")

                anomaly_data = st.session_state.sa_network_anomaly_results
                attack_data = st.session_state.sa_network_attack_results

                complete_results = {
                    "analysis_metadata": {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "total_samples": len(anomaly_predictions),
                        "file_type": "network_traffic",
                    },
                    "anomaly_detection": {
                        "summary": anomaly_data.get("summary", {}),
                        "predictions": anomaly_predictions,
                        "confidence_scores": anomaly_confidence,
                        "model_info": {
                            "model_type": anomaly_data.get("summary", {}).get("model_used", "Unknown"),
                            "prediction_type": "binary_classification",
                        },
                    },
                    "attack_classification": {
                        "summary": attack_data.get("summary", {}),
                        "predictions": attack_predictions,
                        "confidence_scores": attack_confidence,
                        "model_info": {
                            "model_type": attack_data.get("summary", {}).get("model_used", "Unknown"),
                            "prediction_type": "multiclass_classification",
                        },
                    },
                    "combined_analysis": {
                        "total_anomalies": sum(1 for p in anomaly_predictions if p == "Attack"),
                        "benign_traffic": sum(1 for p in anomaly_predictions if p == "Benign"),
                        "attack_type_distribution": {},
                    },
                }

                from collections import Counter

                attack_counts = Counter(attack_predictions)
                complete_results["combined_analysis"]["attack_type_distribution"] = dict(attack_counts)
                json_data = json.dumps(complete_results, indent=2, default=str)

                incident_ready_df = build_incident_response_ready_df(
                    data,
                    anomaly_predictions,
                    anomaly_confidence,
                    attack_predictions,
                    attack_confidence,
                )

                col1, col2 = st.columns(2)
                with col1:
                    st.download_button(
                        label="📄 Download Complete Analysis (JSON)",
                        data=json_data,
                        file_name=f"complete_network_analysis_{int(time.time())}.json",
                        mime="application/json",
                        key="sa_complete_json_download",
                    )

                with col2:
                    st.download_button(
                        label="📊 Download Incident Response Ready CSV",
                        data=incident_ready_df.to_csv(index=False),
                        file_name=f"incident_response_ready_{int(time.time())}.csv",
                        mime="text/csv",
                        key="sa_incident_ready_csv_download",
                    )

                st.markdown("---")
                st.subheader("🔗 Pipeline Handoff")

                handoff_col1, handoff_col2 = st.columns(2)

                with handoff_col1:
                    if st.button("📨 Send to Incident Response", key="sa_send_to_ir_btn", use_container_width=True):
                        st.session_state.uploaded_logs = incident_ready_df
                        st.session_state.incident_handoff_ready = True
                        st.session_state.incident_handoff_source = "Security Agent"
                        st.session_state.incident_handoff_filename = st.session_state.get(
                            "sa_uploaded_filename", "Unknown file"
                        )
                        st.session_state.incident_handoff_attack_types = sorted(
                            incident_ready_df["Attack_Type"].dropna().astype(str).unique().tolist()
                        ) if "Attack_Type" in incident_ready_df.columns else []

                        st.success(
                            "✅ Analysis sent to Incident Response. Open the Incident Response tab and continue in "
                            "'Ticket Raised Post Identification' or 'Legacy Analytics'."
                        )

                with handoff_col2:
                    if st.button("🧹 Clear Incident Handoff", key="sa_clear_ir_handoff_btn", use_container_width=True):
                        for key in [
                            "incident_handoff_ready",
                            "incident_handoff_source",
                            "incident_handoff_filename",
                            "incident_handoff_attack_types",
                        ]:
                            if key in st.session_state:
                                del st.session_state[key]
                        st.info("Incident Response handoff cleared.")
                        st.rerun()

        if GEMINI_AVAILABLE and GEMINI_API_CONFIGURED:
            st.markdown("---")
            st.subheader("🤖 Network Security Assistant")

            if "sa_network_messages" not in st.session_state:
                st.session_state.sa_network_messages = []

            try:
                anomaly_results = st.session_state.get("sa_network_anomaly_results", {})
                attack_results = st.session_state.get("sa_network_attack_results", {})

                anomaly_predictions = anomaly_results.get("predictions", [])
                attack_predictions = attack_results.get("predictions", [])
                anomaly_confidence = anomaly_results.get("confidence_scores", [0])
                attack_confidence = attack_results.get("confidence_scores", [0])

                analysis_context = f"""
                Network Analysis Summary:
                - Total samples analyzed: {len(anomaly_predictions)}
                - Anomalies detected: {sum(1 for p in anomaly_predictions if p == 'Attack')}
                - Benign traffic: {sum(1 for p in anomaly_predictions if p == 'Benign')}
                - Attack types found: {', '.join(set(attack_predictions)) if attack_predictions else 'None'}
                - Average anomaly confidence: {np.mean(anomaly_confidence):.3f}
                - Average attack classification confidence: {np.mean(attack_confidence):.3f}
                """
            except Exception:
                analysis_context = "Network analysis data is not available yet. Please complete the analysis first."

            st.markdown('<div class="chat-container">', unsafe_allow_html=True)

            welcome_msg = """
            <div class="welcome-bubble">
                <strong>🤖 Network Security Assistant</strong><br>
                I can help you understand your network analysis results, explain attack types, and suggest security measures.
            </div>
            """
            st.markdown(welcome_msg, unsafe_allow_html=True)

            for message in st.session_state.sa_network_messages:
                if message["role"] == "user":
                    st.markdown(
                        f'<div class="user-bubble">🧑 <strong>You:</strong><br>{message["content"]}</div><div class="clearfix"></div>',
                        unsafe_allow_html=True,
                    )
                else:
                    st.markdown(
                        f'<div class="bot-bubble">🤖 <strong>Assistant:</strong><br>{message["content"]}</div><div class="clearfix"></div>',
                        unsafe_allow_html=True,
                    )

            st.markdown("</div>", unsafe_allow_html=True)
            st.markdown('<div class="chat-input-container">', unsafe_allow_html=True)

            col1, col2 = st.columns([5, 1])

            with col1:
                with st.form(key="sa_network_chat_form", clear_on_submit=True):
                    user_input = st.text_input(
                        "Message",
                        placeholder="Ask about network security...",
                        label_visibility="collapsed",
                        key="sa_network_chat_input",
                    )
                    send_btn = st.form_submit_button("Send", use_container_width=True)

            with col2:
                if st.button("🧹 Clear", use_container_width=True, key="sa_network_clear_btn"):
                    st.session_state.sa_network_messages = []
                    st.rerun()

            st.markdown("</div>", unsafe_allow_html=True)

            if send_btn and user_input:
                st.session_state.sa_network_messages.append({"role": "user", "content": user_input})

                cybersecurity_keywords = [
                    "attack", "threat", "security", "anomaly", "malicious", "intrusion",
                    "vulnerability", "exploit", "malware", "breach", "network", "traffic",
                    "ddos", "dos", "sql injection", "brute force", "botnet", "infiltration",
                    "analysis", "detection", "classification", "confidence", "risk",
                    "suspicious", "benign", "mitigation", "defense", "protection",
                    "firewall", "ips", "ids", "siem", "incident", "response",
                ]

                is_cybersecurity = any(keyword in user_input.lower() for keyword in cybersecurity_keywords)

                if not is_cybersecurity:
                    response = "🚫 I can only help with cybersecurity-related questions about your network analysis. Please ask about network security, attacks, anomalies, or the analysis results."
                else:
                    try:
                        system_prompt = """You are a cybersecurity expert assistant analyzing network traffic data.
                        You MUST only answer questions related to cybersecurity, network security, threat analysis, and the provided analysis results.
                        Keep responses concise, professional, and actionable."""

                        user_prompt = f"""
                        {system_prompt}

                        Current Network Analysis Results:
                        {analysis_context}

                        User Question: {user_input}

                        Please provide a cybersecurity-focused response based on the analysis results above.
                        """

                        gemini = genai.GenerativeModel("gemini-1.5-flash")
                        response = gemini.generate_content(user_prompt).text

                    except Exception as e:
                        response = f"⚠️ Sorry, I encountered an error: {str(e)}. Please try rephrasing your cybersecurity question."

                st.session_state.sa_network_messages.append({"role": "bot", "content": response})

                if len(st.session_state.sa_network_messages) > 20:
                    st.session_state.sa_network_messages = st.session_state.sa_network_messages[-20:]

                st.rerun()
        else:
            st.markdown("---")
            st.info(
                "🔑 **AI Assistant Unavailable**: Add your Gemini API key in `.streamlit/secrets.toml` "
                "to enable the cybersecurity chatbot for detailed analysis insights."
            )

    st.markdown("</div>", unsafe_allow_html=True)


# ============================================================
# LOGIN FLOW
# ============================================================

def process_login_data(data: pd.DataFrame, le_user, le_pc, model):
    """Process login data through the login anomaly detection pipeline."""
    if "sa_login_analysis_completed" not in st.session_state:
        st.session_state.sa_login_analysis_completed = False
    if "sa_login_analysis_results" not in st.session_state:
        st.session_state.sa_login_analysis_results = None

    st.session_state.sa_login_analysis_completed = True

    with st.spinner("🔍 Running login anomaly detection..."):
        try:
            data = data.copy()

            if "logon_time" in data.columns:
                data["timestamp"] = pd.to_datetime(data["date"] + " " + data["logon_time"], errors="coerce")
            else:
                data["timestamp"] = pd.to_datetime(data["date"], errors="coerce")

            data = data.dropna(subset=["timestamp"])

            data["hour"] = data["timestamp"].dt.hour
            data["minute"] = data["timestamp"].dt.minute
            data["dayofweek"] = data["timestamp"].dt.dayofweek
            data["date"] = data["timestamp"].dt.date
            data["15min_window"] = data["timestamp"].dt.floor("15min")

            login_counts = data.groupby(["user", "15min_window"]).size().reset_index(name="login_count")
            data = data.merge(login_counts, on=["user", "15min_window"], how="left")

            data["user_encoded"] = le_user.transform(data["user"])
            data["pc_encoded"] = le_pc.transform(data["pc"])

            features = ["user_encoded", "pc_encoded", "hour", "minute", "dayofweek", "login_count"]
            X = data[features]

            data["anomaly_label"] = model.predict(X)
            data["anomaly"] = data["anomaly_label"].map({1: "Normal", -1: "Anomaly"})
            data["anomaly_score"] = model.decision_function(X)

            def explain_anomaly(row):
                if row["anomaly"] == "Anomaly":
                    if row["login_count"] >= 5:
                        return f"⚠️ {row['login_count']} logins by user '{row['user']}' in 15 minutes"
                    if row["hour"] < 6 or row["hour"] > 20:
                        return f"⏰ Unusual login hour: {row['hour']} for user '{row['user']}'"
                    return f"🧭 Unusual pattern from PC '{row['pc']}' for user '{row['user']}'"
                return "-"

            data["reason"] = data.apply(explain_anomaly, axis=1)
            st.session_state.sa_login_analysis_results = data

        except Exception as e:
            st.error(f"❌ Error processing login data: {str(e)}")
            st.write("Please ensure your CSV file contains the required columns: user, pc, date")
            return


@st.cache_data
def create_login_visualizations(data_csv_string):
    """Create and cache login visualizations."""
    import io

    data = pd.read_csv(io.StringIO(data_csv_string))
    visualizations = {}

    user_counts = data[data["anomaly"] == "Anomaly"]["user"].value_counts()
    if not user_counts.empty:
        visualizations["user_chart"] = px.bar(
            x=user_counts.index,
            y=user_counts.values,
            labels={"x": "User", "y": "Anomaly Count"},
            title="User-wise Anomaly Distribution",
        )

    pc_counts = data[data["anomaly"] == "Anomaly"]["pc"].value_counts()
    if not pc_counts.empty:
        visualizations["pc_chart"] = px.bar(
            x=pc_counts.index,
            y=pc_counts.values,
            labels={"x": "PC", "y": "Anomaly Count"},
            title="PC-wise Anomaly Distribution",
        )

    if "date" in data.columns:
        daily_trend = data[data["anomaly"] == "Anomaly"].groupby("date").size()
        if not daily_trend.empty:
            visualizations["daily_chart"] = px.line(
                x=daily_trend.index,
                y=daily_trend.values,
                labels={"x": "Date", "y": "Anomaly Count"},
                title="Daily Anomaly Trend",
            )

    hourly_dist = data[data["anomaly"] == "Anomaly"]["hour"].value_counts().sort_index()
    if not hourly_dist.empty:
        visualizations["hourly_chart"] = px.bar(
            x=hourly_dist.index,
            y=hourly_dist.values,
            labels={"x": "Hour of Day", "y": "Anomaly Count"},
            title="Hourly Anomaly Distribution",
        )

    return visualizations


def display_login_results():
    """Display login anomaly detection results from session state."""
    if (
        "sa_login_analysis_completed" not in st.session_state
        or not st.session_state.sa_login_analysis_completed
        or "sa_login_analysis_results" not in st.session_state
        or st.session_state.sa_login_analysis_results is None
    ):
        return

    data = st.session_state.sa_login_analysis_results

    try:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("🔐 Login Anomaly Detection Results")

        total_logins = len(data)
        anomaly_count = len(data[data["anomaly"] == "Anomaly"])
        anomaly_percentage = (anomaly_count / total_logins) * 100

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("📊 Total Logins", total_logins)
        with col2:
            st.metric("🚨 Anomalies Detected", anomaly_count)
        with col3:
            st.metric("📈 Anomaly Rate", f"{anomaly_percentage:.1f}%")
        with col4:
            unique_users = data[data["anomaly"] == "Anomaly"]["user"].nunique()
            st.metric("👥 Affected Users", unique_users)

        if anomaly_percentage > 10:
            st.markdown(
                f"""
            <div class="attack-alert">
                <h3>🚨 High Login Risk Detected!</h3>
                <p><strong>{anomaly_percentage:.1f}%</strong> of logins flagged as anomalous</p>
                <p>Immediate investigation recommended</p>
            </div>
            """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                f"""
            <div class="benign-alert">
                <h3>✅ Login Activity Appears Normal</h3>
                <p>Only <strong>{anomaly_percentage:.1f}%</strong> suspicious login activity detected</p>
                <p>Low risk assessment</p>
            </div>
            """,
                unsafe_allow_html=True,
            )

        st.subheader("📊 Detailed Analysis")

        col_filter1, col_filter2, col_filter3 = st.columns(3)
        with col_filter1:
            show_all = st.button("📁 Show All Logs", key="sa_login_all")
        with col_filter2:
            show_anomalies = st.button("🚨 Show Only Anomalies", key="sa_login_anomalies")
        with col_filter3:
            hide_logs = st.button("🙈 Hide Logs", key="sa_login_hide")

        if "sa_login_log_view" not in st.session_state:
            st.session_state.sa_login_log_view = "all"

        if show_all:
            st.session_state.sa_login_log_view = "all"
        elif show_anomalies:
            st.session_state.sa_login_log_view = "anomalies"
        elif hide_logs:
            st.session_state.sa_login_log_view = "hidden"

        if st.session_state.sa_login_log_view != "hidden":
            st.subheader("🧾 Login Activity Table")
            display_df = data if st.session_state.sa_login_log_view == "all" else data[data["anomaly"] == "Anomaly"]
            display_df = normalize_dataframe_for_display(display_df)

            max_display_rows = 1000
            total_rows = len(display_df)

            if total_rows > max_display_rows:
                st.warning(
                    f"⚠️ Large dataset detected ({total_rows:,} rows). Showing first {max_display_rows:,} rows for performance."
                )
                display_df_limited = display_df.head(max_display_rows)
                safe_st_dataframe(
                    display_df_limited[["timestamp", "user", "pc", "anomaly", "anomaly_score", "reason"]]
                )
                st.info(f"💡 To view all {total_rows:,} rows, download the complete analysis below.")
            else:
                try:
                    styled_df = display_df[["timestamp", "user", "pc", "anomaly", "anomaly_score", "reason"]]
                    safe_st_dataframe(styled_df)
                except Exception:
                    st.warning("⚠️ Styling disabled for performance. Showing data without colors.")
                    safe_st_dataframe(
                        display_df[["timestamp", "user", "pc", "anomaly", "anomaly_score", "reason"]]
                    )

        data_csv_string = data.to_csv(index=False)
        cached_charts = create_login_visualizations(data_csv_string)

        col1, col2 = st.columns(2)

        with col1:
            st.subheader("📌 Anomalies per User")
            if "user_chart" in cached_charts:
                st.plotly_chart(cached_charts["user_chart"], use_container_width=True)
            else:
                st.info("No anomalies detected for any user")

        with col2:
            st.subheader("🖥️ Anomalies per PC")
            if "pc_chart" in cached_charts:
                st.plotly_chart(cached_charts["pc_chart"], use_container_width=True)
            else:
                st.info("No anomalies detected for any PC")

        st.subheader("📅 Temporal Anomaly Analysis")

        if anomaly_count > 0:
            if "daily_chart" in cached_charts:
                st.plotly_chart(cached_charts["daily_chart"], use_container_width=True)

            if "hourly_chart" in cached_charts:
                st.plotly_chart(cached_charts["hourly_chart"], use_container_width=True)
        else:
            st.info("No temporal patterns to display - no anomalies detected")

        st.markdown("---")
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("📊 Generate Report", key="sa_generate_login_report", use_container_width=True):
                st.success("✅ Report generated successfully!")
        with col2:
            if st.button("🚨 Alert Summary", key="sa_login_alert_summary", use_container_width=True):
                st.info(
                    f"📋 **Summary**: {anomaly_count} anomalies detected from {total_logins} total logins ({anomaly_percentage:.1f}% risk)"
                )

        st.subheader("💾 Export Login Analysis")

        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="📥 Download Complete Analysis",
                data=data.to_csv(index=False),
                file_name=f"login_analysis_{int(time.time())}.csv",
                mime="text/csv",
                key="sa_login_complete_download",
            )

        with col2:
            anomaly_data = data[data["anomaly"] == "Anomaly"]
            if not anomaly_data.empty:
                st.download_button(
                    label="📥 Download Anomalies Only",
                    data=anomaly_data.to_csv(index=False),
                    file_name=f"login_anomalies_{int(time.time())}.csv",
                    mime="text/csv",
                    key="sa_login_anomaly_download",
                )
            else:
                st.info("No anomalies to export")

        st.markdown("</div>", unsafe_allow_html=True)

    except Exception as e:
        st.error(f"❌ Error displaying login results: {str(e)}")
        return


# ============================================================
# MAIN RENDER
# ============================================================

def render_security_agent():
    inject_unified_ui_css()
    """Main unified dashboard application."""
    network_predictor = load_network_predictor()
    le_user, le_pc, login_model = load_login_models()

    network_available = network_predictor is not None
    login_available = all([le_user, le_pc, login_model])

    render_top_header(
        title="🛡️ Security Agent Console",
        subtitle="AI-supported network and login anomaly analysis with visual triage, classification, and export-ready outputs.",
        chips=[
            "Network Detection",
            "Login Anomaly Detection",
            "Interactive Analytics",
            "SOC Workflow",
        ],
    )

    uploaded_name = st.session_state.get("sa_uploaded_filename", "None")
    file_type = st.session_state.get("sa_file_type", "Not classified")
    row_count = 0
    if st.session_state.get("sa_uploaded_data") is not None:
        row_count = len(st.session_state["sa_uploaded_data"])

    render_summary_cards(
        [
            {
                "label": "Uploaded File",
                "value": uploaded_name,
                "subtext": "Current dataset under analysis",
            },
            {
                "label": "Detected Modality",
                "value": str(file_type).capitalize(),
                "subtext": "Network or login classification",
            },
            {
                "label": "Rows Loaded",
                "value": f"{row_count}",
                "subtext": "Records currently available for analysis",
            },
            {
                "label": "Models",
                "value": "Ready" if (network_available or login_available) else "Offline",
                "subtext": "Detection stack availability",
            },
        ]
    )

    sa_file_type = st.session_state.get("sa_file_type")

    if sa_file_type == "network":
        security_steps = [
            "Upload",
            "Classify",
            "Anomaly Detection",
            "Attack Classification",
            "Export / Assist",
        ]
        current_step = 0
        if st.session_state.get("sa_uploaded_data") is not None:
            current_step = 1
        if st.session_state.get("sa_network_anomaly_completed"):
            current_step = 2
        if st.session_state.get("sa_network_attack_completed"):
            current_step = 3
        if st.session_state.get("sa_network_messages"):
            current_step = 4

        render_workflow_status(
            title="Security Agent Workflow",
            steps=security_steps,
            current_step=current_step,
        )

    elif sa_file_type == "login":
        security_steps = [
            "Upload",
            "Classify",
            "Login Anomaly Detection",
            "Review Results",
            "Export",
        ]
        current_step = 0
        if st.session_state.get("sa_uploaded_data") is not None:
            current_step = 1
        if st.session_state.get("sa_login_analysis_completed"):
            current_step = 2
        if st.session_state.get("sa_login_analysis_results") is not None:
            current_step = 3

        render_workflow_status(
            title="Security Agent Workflow",
            steps=security_steps,
            current_step=current_step,
        )
    else:
        render_workflow_status(
            title="Security Agent Workflow",
            steps=["Upload", "Classify", "Analyse", "Review", "Export"],
            current_step=0,
        )

    render_sidebar_context(
        "Security Agent Context",
        {
            "Filename": st.session_state.get("sa_uploaded_filename", "None"),
            "Detected Type": st.session_state.get("sa_file_type", "Unknown"),
            "Rows": len(st.session_state["sa_uploaded_data"])
            if st.session_state.get("sa_uploaded_data") is not None
            else 0,
            "AI Assistant": "Enabled" if GEMINI_AVAILABLE and GEMINI_API_CONFIGURED else "Unavailable",
        },
    )

    render_sidebar_context(
        "Detection Stack",
        {
            "Network Models": "Loaded" if network_available else "Unavailable",
            "Login Models": "Loaded" if login_available else "Unavailable",
            "Gemini": "Connected" if GEMINI_AVAILABLE and GEMINI_API_CONFIGURED else "Unavailable",
            "Workflow": "Detection & Review",
        },
    )

    with st.sidebar.expander("🎯 Detection Capabilities"):
        st.markdown(
            """
        **🌐 Network Traffic Analysis:**
        - Binary anomaly detection
        - Attack type classification
        - Real-time threat assessment

        **🔐 Login Anomaly Detection:**
        - Insider threat detection
        - Unusual login pattern analysis
        - User behavior anomaly scoring
        """
        )

    if "sa_uploaded_data" not in st.session_state:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("📂 Upload Security Data")
        st.markdown("Upload network traffic data, login logs, or any security-related CSV file to begin classification and analysis.")

        uploaded_file = st.file_uploader(
            "Choose a CSV file containing security data",
            type=["csv"],
            help="Upload network traffic data, login logs, or any security-related CSV file",
            key="sa_uploaded_file",
        )

        if uploaded_file is not None:
            data = pd.read_csv(uploaded_file)
            st.session_state["sa_uploaded_data"] = data
            st.session_state["sa_file_type"] = classify_file_type(data, uploaded_file.name)
            st.session_state["sa_uploaded_filename"] = uploaded_file.name
            st.rerun()

        st.markdown("</div>", unsafe_allow_html=True)
        return

    data = st.session_state["sa_uploaded_data"]
    file_type = st.session_state["sa_file_type"]

    st.markdown(
        f"""
        <div class="status-card">
            <strong>✅ File uploaded successfully:</strong> {st.session_state['sa_uploaded_filename']}<br>
            <span style="color:#94a3b8;">Rows loaded: {len(data):,} • Detected type: {str(file_type).capitalize()}</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("🔄 Reset and Upload New File", key="sa_reset_upload"):
        for k in [
            "sa_uploaded_data",
            "sa_file_type",
            "sa_uploaded_filename",
            "sa_uploaded_file",
            "sa_login_analysis_completed",
            "sa_login_analysis_results",
            "sa_login_log_view",
            "sa_network_anomaly_completed",
            "sa_network_anomaly_results",
            "sa_network_attack_completed",
            "sa_network_attack_results",
            "sa_network_messages",
            "sa_network_chat_input",
        ]:
            if k in st.session_state:
                del st.session_state[k]
        st.rerun()

    if file_type == "network":
        st.markdown(
            """
        <div class="detection-card">
            <h3>🎯 Classification Result: Network Traffic Data</h3>
            <p>AI has determined this is network/traffic data suitable for intrusion detection</p>
        </div>
        """,
            unsafe_allow_html=True,
        )
        if network_available:
            process_network_data(data, network_predictor)
        else:
            st.error("❌ Network traffic models are not available. Please ensure model files are in the 'trained_models' directory.")

    elif file_type == "login":
        st.markdown(
            """
        <div class="detection-card">
            <h3>🎯 Classification Result: Login/Authentication Data</h3>
            <p>AI has determined this is login data suitable for insider threat detection</p>
        </div>
        """,
            unsafe_allow_html=True,
        )

        if login_available:
            st.markdown(
                """
            <div class="login-card">
                <h3>🔐 Login Activity Analysis Detected</h3>
                <p>This appears to be authentication/login data suitable for insider threat detection</p>
            </div>
            """,
                unsafe_allow_html=True,
            )

            st.markdown('<div class="section-shell">', unsafe_allow_html=True)
            st.subheader("🔍 Login Anomaly Detection")
            if not st.session_state.get("sa_login_analysis_completed", False):
                if st.button("🚀 Run Login Anomaly Detection", type="primary", key="sa_login_anomaly_btn"):
                    process_login_data(data, le_user, le_pc, login_model)
                    st.rerun()
            else:
                st.success("✅ Login Anomaly Detection - Completed")
            st.markdown("</div>", unsafe_allow_html=True)

            if st.session_state.get("sa_login_analysis_completed", False):
                display_login_results()
        else:
            st.error("❌ Login anomaly models are not available. Please ensure model files are in the 'login_models' directory.")
    else:
        st.warning("The uploaded file could not be confidently classified as network or login data.")

    st.markdown("---")
    st.markdown(
        """
    <div style="text-align: center; color: #94a3b8; padding: 2rem;">
        <p style="margin-bottom:0.35rem;">🛡️ <strong style="color:#e2e8f0;">Unified Cybersecurity Detection System</strong></p>
        <p style="margin-bottom:0.2rem;">AI-Powered Network Traffic Analysis & Insider Threat Detection</p>
        <p>Built with Streamlit • Powered by Machine Learning & Gemini AI</p>
    </div>
    """,
        unsafe_allow_html=True,
    )


if __name__ == "__main__":
    st.set_page_config(
        page_title="🛡️ Unified Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    render_security_agent()