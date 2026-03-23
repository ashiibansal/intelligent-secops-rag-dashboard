import random
from datetime import datetime

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st


def _inject_dashboard_css():
    st.markdown("""
    <style>
        .legacy-hero {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 60%, #1d4ed8 100%);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 18px;
            padding: 1.25rem 1.4rem;
            margin: 0.25rem 0 1rem 0;
            box-shadow: 0 10px 30px rgba(2, 6, 23, 0.28);
        }
        .legacy-hero h2 {
            margin: 0;
            color: #f8fafc;
            font-size: 1.75rem;
        }
        .legacy-hero p {
            margin: 0.45rem 0 0 0;
            color: #cbd5e1;
            font-size: 0.98rem;
        }
        .insight-card {
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.96) 0%, rgba(30, 41, 59, 0.96) 100%);
            border: 1px solid rgba(148, 163, 184, 0.16);
            border-radius: 16px;
            padding: 0.95rem 1rem;
            margin: 0.35rem 0 1rem 0;
        }
        .insight-title {
            color: #93c5fd;
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 0.25rem;
            font-weight: 700;
        }
        .insight-value {
            color: #f8fafc;
            font-size: 1.1rem;
            font-weight: 700;
            margin-bottom: 0.15rem;
        }
        .insight-subtext {
            color: #94a3b8;
            font-size: 0.9rem;
        }
        .section-shell {
            background: rgba(15, 23, 42, 0.72);
            border: 1px solid rgba(148, 163, 184, 0.14);
            border-radius: 18px;
            padding: 1rem 1rem 0.35rem 1rem;
            margin: 0.25rem 0 1rem 0;
        }
        .alert-shell {
            border-radius: 16px;
            padding: 0.95rem 1rem;
            margin: 0.3rem 0 1rem 0;
            border-left: 5px solid;
        }
        .alert-critical {
            background: linear-gradient(90deg, rgba(127, 29, 29, 0.65), rgba(69, 10, 10, 0.45));
            border-left-color: #ef4444;
            color: #fee2e2;
        }
        .alert-high {
            background: linear-gradient(90deg, rgba(120, 53, 15, 0.55), rgba(67, 20, 7, 0.35));
            border-left-color: #f97316;
            color: #ffedd5;
        }
        .alert-medium {
            background: linear-gradient(90deg, rgba(113, 63, 18, 0.45), rgba(68, 38, 11, 0.28));
            border-left-color: #f59e0b;
            color: #fef3c7;
        }
        .alert-low {
            background: linear-gradient(90deg, rgba(6, 78, 59, 0.45), rgba(2, 44, 34, 0.28));
            border-left-color: #10b981;
            color: #d1fae5;
        }
        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(15,23,42,0.95) 0%, rgba(30,41,59,0.95) 100%);
            border: 1px solid rgba(148, 163, 184, 0.15);
            padding: 0.8rem 0.9rem;
            border-radius: 16px;
            box-shadow: 0 6px 18px rgba(2, 6, 23, 0.18);
        }
        div[data-testid="stMetricLabel"] {
            color: #93c5fd !important;
            font-weight: 600 !important;
        }
        div[data-testid="stMetricValue"] {
            color: #f8fafc !important;
        }
        .small-note {
            color: #94a3b8;
            font-size: 0.86rem;
            margin-top: -0.25rem;
        }
    </style>
    """, unsafe_allow_html=True)


def _normalize_confidence(value):
    """Normalize confidence values into High / Medium / Low when possible."""
    if pd.isna(value):
        return "Unknown"

    value_str = str(value).strip().lower()

    if value_str in {"high", "medium", "low"}:
        return value_str.capitalize()

    try:
        numeric_value = float(value)
        if numeric_value >= 0.8:
            return "High"
        elif numeric_value >= 0.5:
            return "Medium"
        else:
            return "Low"
    except (ValueError, TypeError):
        return str(value)


def _confidence_to_numeric(value):
    normalized = _normalize_confidence(value)
    mapping = {
        "High": 3,
        "Medium": 2,
        "Low": 1,
        "Unknown": 0
    }
    return mapping.get(normalized, 0)


def _calculate_risk_score(row):
    """Risk score using confidence, target port criticality, and attack severity hints."""
    score = 0

    confidence = _normalize_confidence(row.get("Attack_Confidence"))
    score += _confidence_to_numeric(confidence)

    try:
        dst_port = int(float(row.get("Dst_Port")))
        if dst_port in [22, 80, 443]:
            score += 2
        elif dst_port in [21, 23, 25, 53, 110, 143, 3389, 8080, 8443]:
            score += 1
    except (ValueError, TypeError):
        pass

    attack_type = str(row.get("Attack_Type", "")).lower()
    if any(term in attack_type for term in ["ransom", "bot", "ddos", "dos", "brute", "infiltration", "sql"]):
        score += 2
    elif any(term in attack_type for term in ["probe", "scan", "ftp", "ssh", "web"]):
        score += 1

    return score


def _risk_level(score):
    if pd.isna(score):
        return "Unknown"
    if score >= 6:
        return "Critical"
    if score >= 4:
        return "High"
    if score >= 2:
        return "Medium"
    return "Low"


def _prepare_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [str(col).strip() for col in df.columns]

    if "Attack_Confidence" in df.columns:
        df["Attack_Confidence_Normalized"] = df["Attack_Confidence"].apply(_normalize_confidence)
        df["Attack_Confidence_Score"] = df["Attack_Confidence"].apply(_confidence_to_numeric)

    if "Dst_Port" in df.columns:
        df["Dst_Port"] = pd.to_numeric(df["Dst_Port"], errors="coerce")

    if "Timestamp" in df.columns:
        df["Timestamp"] = pd.to_datetime(df["Timestamp"], errors="coerce")

    if "Risk_Score" not in df.columns and {"Attack_Confidence", "Dst_Port"}.issubset(df.columns):
        df["Risk_Score"] = df.apply(_calculate_risk_score, axis=1)

    if "Risk_Score" in df.columns:
        df["Risk_Score"] = pd.to_numeric(df["Risk_Score"], errors="coerce")
        df["Risk_Level"] = df["Risk_Score"].apply(_risk_level)

    return df


def _get_threat_posture(df: pd.DataFrame):
    if "Risk_Score" not in df.columns or df["Risk_Score"].dropna().empty:
        return "Moderate", "Low"

    avg_risk = df["Risk_Score"].mean()
    critical_count = (df["Risk_Level"] == "Critical").sum() if "Risk_Level" in df.columns else 0

    if critical_count > 0 or avg_risk >= 5:
        return "Critical", "Critical"
    if avg_risk >= 3.5:
        return "Elevated", "High"
    if avg_risk >= 2:
        return "Moderate", "Medium"
    return "Stable", "Low"


def _render_posture_banner(df: pd.DataFrame):
    posture_text, severity_class = _get_threat_posture(df)

    top_attack = "N/A"
    if "Attack_Type" in df.columns and not df["Attack_Type"].dropna().empty:
        top_attack = df["Attack_Type"].astype(str).mode().iloc[0]

    top_port = "N/A"
    if "Dst_Port" in df.columns and not df["Dst_Port"].dropna().empty:
        top_port = int(df["Dst_Port"].dropna().mode().iloc[0])

    affected_sources = "N/A"
    if "Src_IP" in df.columns:
        affected_sources = df["Src_IP"].astype(str).nunique()

    banner_class = {
        "Critical": "alert-critical",
        "High": "alert-high",
        "Medium": "alert-medium",
        "Low": "alert-low",
    }.get(severity_class, "alert-low")

    st.markdown(
        f"""
        <div class="alert-shell {banner_class}">
            <div style="font-size:1.05rem; font-weight:700; margin-bottom:0.25rem;">
                Threat posture: {posture_text}
            </div>
            <div style="font-size:0.95rem;">
                Dominant attack pattern: <strong>{top_attack}</strong> &nbsp;•&nbsp;
                Most targeted port: <strong>{top_port}</strong> &nbsp;•&nbsp;
                Unique source IPs: <strong>{affected_sources}</strong>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_highlights(df: pd.DataFrame):
    top_attack = "N/A"
    if "Attack_Type" in df.columns and not df["Attack_Type"].dropna().empty:
        vc = df["Attack_Type"].astype(str).value_counts()
        top_attack = f"{vc.index[0]} ({vc.iloc[0]})"

    top_source = "N/A"
    if "Src_IP" in df.columns and not df["Src_IP"].dropna().empty:
        vc = df["Src_IP"].astype(str).value_counts()
        top_source = f"{vc.index[0]} ({vc.iloc[0]})"

    time_window = "N/A"
    if "Timestamp" in df.columns and df["Timestamp"].dropna().any():
        ts = df["Timestamp"].dropna()
        time_window = f"{ts.min().strftime('%Y-%m-%d %H:%M')} → {ts.max().strftime('%Y-%m-%d %H:%M')}"

    cols = st.columns(3)
    with cols[0]:
        st.markdown(
            f"""
            <div class="insight-card">
                <div class="insight-title">Dominant Attack Family</div>
                <div class="insight-value">{top_attack}</div>
                <div class="insight-subtext">Most frequent pattern in the filtered dataset</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with cols[1]:
        st.markdown(
            f"""
            <div class="insight-card">
                <div class="insight-title">Most Active Source</div>
                <div class="insight-value">{top_source}</div>
                <div class="insight-subtext">Useful for prioritising source-side triage</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with cols[2]:
        st.markdown(
            f"""
            <div class="insight-card">
                <div class="insight-title">Observed Time Window</div>
                <div class="insight-value" style="font-size:0.98rem;">{time_window}</div>
                <div class="insight-subtext">Parsed from the available timestamp field</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def _plot_attack_distribution(df: pd.DataFrame, top_n: int):
    if "Attack_Type" not in df.columns or df["Attack_Type"].dropna().empty:
        return None

    plot_df = (
        df["Attack_Type"]
        .astype(str)
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    plot_df.columns = ["Attack_Type", "Count"]

    fig = px.bar(
        plot_df,
        x="Count",
        y="Attack_Type",
        orientation="h",
        text="Count",
        template="plotly_dark",
        title="Attack Type Distribution",
    )
    fig.update_layout(
        height=420,
        yaxis_title="",
        xaxis_title="Events",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    fig.update_traces(textposition="outside")
    return fig


def _plot_confidence_donut(df: pd.DataFrame):
    if "Attack_Confidence_Normalized" not in df.columns or df["Attack_Confidence_Normalized"].dropna().empty:
        return None

    plot_df = (
        df["Attack_Confidence_Normalized"]
        .astype(str)
        .value_counts()
        .reset_index()
    )
    plot_df.columns = ["Confidence", "Count"]

    fig = px.pie(
        plot_df,
        names="Confidence",
        values="Count",
        hole=0.58,
        template="plotly_dark",
        title="Confidence Breakdown",
    )
    fig.update_layout(height=420, margin=dict(l=10, r=10, t=50, b=10))
    fig.update_traces(textinfo="percent+label")
    return fig


def _plot_risk_levels(df: pd.DataFrame):
    if "Risk_Level" not in df.columns or df["Risk_Level"].dropna().empty:
        return None

    ordered_levels = ["Low", "Medium", "High", "Critical"]
    counts = (
        df["Risk_Level"]
        .value_counts()
        .reindex(ordered_levels, fill_value=0)
        .reset_index()
    )
    counts.columns = ["Risk_Level", "Count"]

    fig = px.bar(
        counts,
        x="Risk_Level",
        y="Count",
        text="Count",
        template="plotly_dark",
        title="Risk Level Distribution",
        category_orders={"Risk_Level": ordered_levels},
    )
    fig.update_layout(
        height=380,
        xaxis_title="Risk Level",
        yaxis_title="Events",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    fig.update_traces(textposition="outside")
    return fig


def _plot_top_ports(df: pd.DataFrame, top_n: int):
    if "Dst_Port" not in df.columns or df["Dst_Port"].dropna().empty:
        return None

    plot_df = (
        df["Dst_Port"]
        .dropna()
        .astype(int)
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    plot_df.columns = ["Dst_Port", "Count"]
    plot_df["Dst_Port"] = plot_df["Dst_Port"].astype(str)

    fig = px.bar(
        plot_df,
        x="Dst_Port",
        y="Count",
        text="Count",
        template="plotly_dark",
        title="Top Targeted Ports",
    )
    fig.update_layout(
        height=380,
        xaxis_title="Destination Port",
        yaxis_title="Events",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    fig.update_traces(textposition="outside")
    return fig


def _plot_timeline(df: pd.DataFrame):
    if "Timestamp" not in df.columns or df["Timestamp"].dropna().empty:
        return None

    temp_df = df.dropna(subset=["Timestamp"]).copy()
    if temp_df.empty:
        return None

    timeline = (
        temp_df.groupby(temp_df["Timestamp"].dt.floor("H"))
        .size()
        .reset_index(name="Event_Count")
    )
    timeline.columns = ["Timestamp", "Event_Count"]

    fig = px.area(
        timeline,
        x="Timestamp",
        y="Event_Count",
        template="plotly_dark",
        title="Attack Activity Timeline",
    )
    fig.update_layout(
        height=390,
        xaxis_title="Time",
        yaxis_title="Events per Hour",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return fig


def _plot_heatmap(df: pd.DataFrame, top_n: int):
    if "Attack_Type" not in df.columns or "Dst_Port" not in df.columns:
        return None

    temp_df = df.dropna(subset=["Attack_Type", "Dst_Port"]).copy()
    if temp_df.empty:
        return None

    top_attacks = temp_df["Attack_Type"].astype(str).value_counts().head(min(top_n, 8)).index.tolist()
    top_ports = temp_df["Dst_Port"].astype(int).value_counts().head(min(top_n, 12)).index.tolist()

    temp_df = temp_df[
        temp_df["Attack_Type"].astype(str).isin(top_attacks) &
        temp_df["Dst_Port"].astype(int).isin(top_ports)
    ].copy()

    if temp_df.empty:
        return None

    pivot = pd.crosstab(
        temp_df["Attack_Type"].astype(str),
        temp_df["Dst_Port"].astype(int)
    )

    fig = px.imshow(
        pivot,
        text_auto=True,
        aspect="auto",
        template="plotly_dark",
        title="Attack Type vs Target Port Heatmap",
    )
    fig.update_layout(
        height=430,
        xaxis_title="Destination Port",
        yaxis_title="Attack Type",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return fig


def _plot_source_ips(df: pd.DataFrame, top_n: int):
    if "Src_IP" not in df.columns or df["Src_IP"].dropna().empty:
        return None

    plot_df = (
        df["Src_IP"]
        .astype(str)
        .value_counts()
        .head(top_n)
        .reset_index()
    )
    plot_df.columns = ["Src_IP", "Count"]

    fig = px.bar(
        plot_df,
        x="Count",
        y="Src_IP",
        orientation="h",
        text="Count",
        template="plotly_dark",
        title="Top Source IPs",
    )
    fig.update_layout(
        height=420,
        yaxis_title="",
        xaxis_title="Events",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    fig.update_traces(textposition="outside")
    return fig


def _plot_port_risk_scatter(df: pd.DataFrame):
    if "Dst_Port" not in df.columns or "Risk_Score" not in df.columns:
        return None

    temp_df = df.dropna(subset=["Dst_Port", "Risk_Score"]).copy()
    if temp_df.empty:
        return None

    if len(temp_df) > 1200:
        temp_df = temp_df.sample(1200, random_state=42)

    color_col = "Attack_Type" if "Attack_Type" in temp_df.columns else None
    hover_cols = [col for col in ["Attack_Type", "Attack_Confidence_Normalized", "Src_IP"] if col in temp_df.columns]

    fig = px.scatter(
        temp_df,
        x="Dst_Port",
        y="Risk_Score",
        color=color_col,
        hover_data=hover_cols,
        template="plotly_dark",
        title="Port Exposure vs Risk Score",
        opacity=0.75,
    )
    fig.update_layout(
        height=420,
        xaxis_title="Destination Port",
        yaxis_title="Risk Score",
        margin=dict(l=10, r=10, t=50, b=10),
    )
    return fig


def _priority_table(df: pd.DataFrame):
    if "Risk_Score" not in df.columns:
        return df.head(25)

    sort_cols = ["Risk_Score"]
    ascending = [False]

    if "Attack_Confidence_Score" in df.columns:
        sort_cols.append("Attack_Confidence_Score")
        ascending.append(False)

    priority_df = df.sort_values(sort_cols, ascending=ascending).copy()

    preferred_cols = [
        "Timestamp",
        "Attack_Type",
        "Attack_Confidence_Normalized",
        "Risk_Score",
        "Risk_Level",
        "Dst_Port",
        "Src_IP",
        "Dst_IP",
    ]
    available_cols = [col for col in preferred_cols if col in priority_df.columns]

    if available_cols:
        priority_df = priority_df[available_cols]

    return priority_df.head(50)


def render_dashboard(logs_df=None):
    """
    Render the upgraded legacy analytics dashboard.

    Priority:
    1. use logs_df if provided
    2. otherwise use st.session_state["uploaded_logs"]
    """
    _inject_dashboard_css()

    st.markdown("""
    <div class="legacy-hero">
        <h2>📊 Security Operations Dashboard</h2>
        <p>
            Executive threat visibility for uploaded incident CSVs — cleaner triage, stronger prioritisation,
            and interactive attack analytics that don’t look like they were assembled during a caffeine emergency.
        </p>
    </div>
    """, unsafe_allow_html=True)

    # ============================================================
    # LOAD DATA
    # ============================================================

    if logs_df is not None:
        df = logs_df.copy()
    else:
        if "uploaded_logs" not in st.session_state or st.session_state.uploaded_logs is None:
            st.info("Upload a network attack CSV in the Ticket tab to activate analytics.")
            return
        df = st.session_state.uploaded_logs.copy()

    if df.empty:
        st.warning("Uploaded dataset is empty.")
        return

    df = _prepare_dataframe(df)

    # ============================================================
    # FILTERS
    # ============================================================

    with st.expander("🔎 Exploration Controls", expanded=True):
        c1, c2, c3, c4 = st.columns([1.3, 1.1, 1.1, 0.9])

        attack_filter = ["All"]
        if "Attack_Type" in df.columns:
            attack_values = sorted(df["Attack_Type"].dropna().astype(str).unique().tolist())
            attack_filter = c1.multiselect(
                "Attack Type",
                options=attack_values,
                default=attack_values,
                key="legacy_attack_filter_v2"
            )

        confidence_filter = ["All"]
        if "Attack_Confidence_Normalized" in df.columns:
            confidence_values = sorted(df["Attack_Confidence_Normalized"].dropna().astype(str).unique().tolist())
            confidence_filter = c2.multiselect(
                "Confidence",
                options=confidence_values,
                default=confidence_values,
                key="legacy_confidence_filter_v2"
            )

        risk_filter = ["All"]
        if "Risk_Level" in df.columns:
            risk_values = ["Low", "Medium", "High", "Critical"]
            present_risk_values = [r for r in risk_values if r in df["Risk_Level"].dropna().unique()]
            risk_filter = c3.multiselect(
                "Risk Level",
                options=present_risk_values,
                default=present_risk_values,
                key="legacy_risk_filter_v2"
            )

        top_n = c4.slider("Top N", min_value=5, max_value=20, value=10, key="legacy_top_n_v2")

    filtered_df = df.copy()

    if "Attack_Type" in filtered_df.columns and attack_filter:
        filtered_df = filtered_df[filtered_df["Attack_Type"].astype(str).isin(attack_filter)]

    if "Attack_Confidence_Normalized" in filtered_df.columns and confidence_filter:
        filtered_df = filtered_df[filtered_df["Attack_Confidence_Normalized"].astype(str).isin(confidence_filter)]

    if "Risk_Level" in filtered_df.columns and risk_filter:
        filtered_df = filtered_df[filtered_df["Risk_Level"].astype(str).isin(risk_filter)]

    if filtered_df.empty:
        st.warning("No rows remain after applying the current filters.")
        return

    # ============================================================
    # SUMMARY + METRICS
    # ============================================================

    _render_posture_banner(filtered_df)
    _render_highlights(filtered_df)

    total_logs = len(filtered_df)
    unique_attacks = filtered_df["Attack_Type"].astype(str).nunique() if "Attack_Type" in filtered_df.columns else None
    avg_risk = round(filtered_df["Risk_Score"].mean(), 2) if "Risk_Score" in filtered_df.columns else None
    critical_events = int((filtered_df["Risk_Level"] == "Critical").sum()) if "Risk_Level" in filtered_df.columns else None
    high_conf_share = None
    if "Attack_Confidence_Normalized" in filtered_df.columns:
        high_conf_share = round((filtered_df["Attack_Confidence_Normalized"] == "High").mean() * 100, 1)

    metric_cols = st.columns(5)
    metric_cols[0].metric("Total Logs", f"{total_logs:,}")
    metric_cols[1].metric("Unique Attack Types", unique_attacks if unique_attacks is not None else "N/A")
    metric_cols[2].metric("Average Risk Score", avg_risk if avg_risk is not None else "N/A")
    metric_cols[3].metric("Critical Events", critical_events if critical_events is not None else "N/A")
    metric_cols[4].metric("High Confidence Share", f"{high_conf_share}%" if high_conf_share is not None else "N/A")

    st.caption(f"Filtered view contains {len(filtered_df):,} records from {len(df):,} uploaded rows.")

    # ============================================================
    # ANALYTICS TABS
    # ============================================================

    tab1, tab2, tab3, tab4 = st.tabs([
        "📈 Threat Landscape",
        "🌐 Network Intelligence",
        "🚨 Priority Queue",
        "🧾 Data Explorer"
    ])

    with tab1:
        row1_col1, row1_col2 = st.columns(2)
        attack_fig = _plot_attack_distribution(filtered_df, top_n)
        conf_fig = _plot_confidence_donut(filtered_df)

        with row1_col1:
            if attack_fig:
                st.plotly_chart(attack_fig, use_container_width=True)
            else:
                st.info("Attack type data is not available.")

        with row1_col2:
            if conf_fig:
                st.plotly_chart(conf_fig, use_container_width=True)
            else:
                st.info("Confidence information is not available.")

        row2_col1, row2_col2 = st.columns(2)
        risk_fig = _plot_risk_levels(filtered_df)
        port_fig = _plot_top_ports(filtered_df, top_n)

        with row2_col1:
            if risk_fig:
                st.plotly_chart(risk_fig, use_container_width=True)
            else:
                st.info("Risk scoring is not available for this dataset.")

        with row2_col2:
            if port_fig:
                st.plotly_chart(port_fig, use_container_width=True)
            else:
                st.info("Destination port data is not available.")

        timeline_fig = _plot_timeline(filtered_df)
        if timeline_fig:
            st.plotly_chart(timeline_fig, use_container_width=True)
        else:
            st.info("Timestamp-based activity trend could not be generated from this dataset.")

    with tab2:
        row1_col1, row1_col2 = st.columns(2)
        heatmap_fig = _plot_heatmap(filtered_df, top_n)
        src_fig = _plot_source_ips(filtered_df, top_n)

        with row1_col1:
            if heatmap_fig:
                st.plotly_chart(heatmap_fig, use_container_width=True)
            else:
                st.info("Need both `Attack_Type` and `Dst_Port` to build the heatmap.")

        with row1_col2:
            if src_fig:
                st.plotly_chart(src_fig, use_container_width=True)
            else:
                st.info("Source IP data is not available.")

        scatter_fig = _plot_port_risk_scatter(filtered_df)
        if scatter_fig:
            st.plotly_chart(scatter_fig, use_container_width=True)
        else:
            st.info("Need `Dst_Port` and `Risk_Score` to build the port-risk exposure map.")

        st.markdown("### ⚡ Threat Simulation Console")
        sim_col1, sim_col2 = st.columns([1, 1])

        if "legacy_simulated_alert" not in st.session_state:
            st.session_state.legacy_simulated_alert = None

        if sim_col1.button("Simulate New Attack", key="legacy_simulate_attack_v2", use_container_width=True):
            simulated_port = random.randint(20, 9000)
            simulated_attack = random.choice(["DDoS", "Brute Force", "SQL Injection", "Botnet", "Infiltration"])
            simulated_conf = random.choice(["High", "Medium", "Low"])
            st.session_state.legacy_simulated_alert = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "attack": simulated_attack,
                "port": simulated_port,
                "confidence": simulated_conf,
            }

        posture_label, _ = _get_threat_posture(filtered_df)
        sim_col2.metric("Current Threat Posture", posture_label)

        if st.session_state.legacy_simulated_alert is not None:
            alert = st.session_state.legacy_simulated_alert
            st.error(
                f"🚨 Simulated event | {alert['timestamp']} | "
                f"{alert['attack']} detected on port {alert['port']} "
                f"with {alert['confidence']} confidence."
            )

    with tab3:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("Priority Queue for Analyst Review")

        priority_df = _priority_table(filtered_df)
        st.dataframe(priority_df, use_container_width=True, height=420)

        st.markdown(
            "<div class='small-note'>Rows are sorted to surface the most operationally relevant events first.</div>",
            unsafe_allow_html=True,
        )

        download_col1, download_col2 = st.columns(2)
        with download_col1:
            st.download_button(
                label="📥 Download Filtered Dataset (CSV)",
                data=filtered_df.to_csv(index=False),
                file_name="filtered_security_analytics.csv",
                mime="text/csv",
                key="legacy_filtered_download"
            )
        with download_col2:
            summary_payload = {
                "total_rows": int(len(filtered_df)),
                "attack_types": filtered_df["Attack_Type"].astype(str).value_counts().to_dict()
                if "Attack_Type" in filtered_df.columns else {},
                "risk_levels": filtered_df["Risk_Level"].astype(str).value_counts().to_dict()
                if "Risk_Level" in filtered_df.columns else {},
            }
            st.download_button(
                label="📄 Download Analytics Summary (JSON)",
                data=pd.Series(summary_payload).to_json(indent=2),
                file_name="security_analytics_summary.json",
                mime="application/json",
                key="legacy_summary_download"
            )
        st.markdown('</div>', unsafe_allow_html=True)

    with tab4:
        st.markdown('<div class="section-shell">', unsafe_allow_html=True)
        st.subheader("Dataset Preview")
        st.dataframe(filtered_df.head(250), use_container_width=True, height=440)
        st.markdown(
            f"<div class='small-note'>Showing up to 250 rows from the filtered dataset. "
            f"Current row count: {len(filtered_df):,}.</div>",
            unsafe_allow_html=True,
        )
        st.markdown('</div>', unsafe_allow_html=True)

    st.success("Dashboard Active: Monitoring Threat Intelligence")