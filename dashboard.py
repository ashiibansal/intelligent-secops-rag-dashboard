import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import random
import numpy as np

# ============================================================
# DARK THEME CONFIG FOR MATPLOTLIB
# ============================================================

plt.style.use("dark_background")

sns.set_theme(style="dark")

# Match Streamlit dark background
plt.rcParams["figure.facecolor"] = "#0f172a"
plt.rcParams["axes.facecolor"] = "#1e293b"
plt.rcParams["axes.edgecolor"] = "#e2e8f0"
plt.rcParams["axes.labelcolor"] = "#e2e8f0"
plt.rcParams["xtick.color"] = "#e2e8f0"
plt.rcParams["ytick.color"] = "#e2e8f0"
plt.rcParams["text.color"] = "#e2e8f0"
plt.rcParams["grid.color"] = "#334155"


def render_dashboard():

    st.header("📊 Security Operations Dashboard")
    st.caption("Real-Time Threat Monitoring • Risk Intelligence • Attack Analytics")

    # ============================================================
    # CHECK IF LOGS EXIST
    # ============================================================

    if "uploaded_logs" not in st.session_state:
        st.info("Upload a network attack CSV in the Ticket tab to activate analytics.")
        return

    df = st.session_state.uploaded_logs.copy()

    if df.empty:
        st.warning("Uploaded dataset is empty.")
        return

    # ============================================================
    # OPTIONAL FILTERING
    # ============================================================

    st.markdown("### 🔎 Filters")

    col_f1, col_f2 = st.columns(2)

    if "Attack_Type" in df.columns:
        attack_filter = col_f1.selectbox(
            "Filter by Attack Type",
            ["All"] + sorted(df["Attack_Type"].unique().tolist())
        )
        if attack_filter != "All":
            df = df[df["Attack_Type"] == attack_filter]

    if "Attack_Confidence" in df.columns:
        confidence_filter = col_f2.selectbox(
            "Filter by Confidence",
            ["All"] + sorted(df["Attack_Confidence"].unique().tolist())
        )
        if confidence_filter != "All":
            df = df[df["Attack_Confidence"] == confidence_filter]

    st.markdown("---")

    # ============================================================
    # RISK SCORING ENGINE
    # ============================================================

    if "Attack_Confidence" in df.columns and "Dst_Port" in df.columns:

        def calculate_risk(row):
            score = 0

            if row["Attack_Confidence"] == "High":
                score += 3
            elif row["Attack_Confidence"] == "Medium":
                score += 2
            else:
                score += 1

            if row["Dst_Port"] in [22, 80, 443]:
                score += 2

            return score

        df["Risk_Score"] = df.apply(calculate_risk, axis=1)

    # ============================================================
    # KPI METRIC CARDS
    # ============================================================

    st.markdown("### 🚨 Threat Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Logs", len(df))

    if "Attack_Type" in df.columns:
        col2.metric("Unique Attack Types", df["Attack_Type"].nunique())

    if "Risk_Score" in df.columns:
        col3.metric("Average Risk Score", round(df["Risk_Score"].mean(), 2))

    if "Dst_Port" in df.columns:
        top_port = df["Dst_Port"].mode()[0]
        col4.metric("Top Targeted Port", top_port)

    st.markdown("---")

    # ============================================================
    # ATTACK TYPE DISTRIBUTION
    # ============================================================

    if "Attack_Type" in df.columns:

        st.subheader("Attack Type Distribution")

        fig, ax = plt.subplots(facecolor="#0f172a",figsize=(6, 4))
        ax.set_facecolor("#1e293b")
        sns.countplot(
            data=df,
            x="Attack_Type",
            order=df["Attack_Type"].value_counts().index,
            palette="rocket"
        )
        ax.grid(alpha=0.2)

        for spine in ax.spines.values():
            spine.set_visible(False)
        plt.xticks(rotation=45)
        plt.tight_layout()
        st.pyplot(fig, transparent=True)

    # ============================================================
    # PORT HEATMAP
    # ============================================================

    if "Attack_Type" in df.columns and "Dst_Port" in df.columns:

        st.subheader("Attack Type vs Target Port Heatmap")

        pivot = pd.crosstab(df["Attack_Type"], df["Dst_Port"])

        fig, ax = plt.subplots(facecolor="#0f172a",figsize=(8, 5))
        ax.set_facecolor("#1e293b")
        sns.heatmap(pivot, cmap="Reds")
        ax.grid(alpha=0.2)

        for spine in ax.spines.values():
            spine.set_visible(False)
        plt.tight_layout()
        st.pyplot(fig, transparent=True)

    # ============================================================
    # RISK SCORE DISTRIBUTION
    # ============================================================

    if "Risk_Score" in df.columns:

        st.subheader("Risk Score Distribution")

        fig, ax = plt.subplots(facecolor="#0f172a",figsize=(6, 4))
        ax.set_facecolor("#1e293b")
        df["Risk_Score"].value_counts().sort_index().plot(kind="bar", ax=ax)
        ax.grid(alpha=0.2)

        for spine in ax.spines.values():
            spine.set_visible(False)
        plt.tight_layout()
        st.pyplot(fig, transparent=True)

    # ============================================================
    # CONFIDENCE PIE
    # ============================================================

    if "Attack_Confidence" in df.columns:

        st.subheader("Attack Confidence Breakdown")

        fig, ax = plt.subplots(facecolor="#0f172a")
        ax.set_facecolor("#1e293b")
        df["Attack_Confidence"].value_counts().plot(
            kind="pie",
            autopct="%1.1f%%",
            ax=ax
        )
        ax.grid(alpha=0.2)

        for spine in ax.spines.values():
            spine.set_visible(False)
        ax.set_ylabel("")
        st.pyplot(fig, transparent=True)

    # ============================================================
    # ATTACK TIMELINE
    # ============================================================

    if "Timestamp" in df.columns:

        st.subheader("Attack Activity Timeline")

        df["Timestamp"] = pd.to_datetime(df["Timestamp"])
        timeline = df.groupby(df["Timestamp"].dt.date).size()

        fig, ax = plt.subplots(facecolor="#0f172a",figsize=(8, 4))
        ax.set_facecolor("#1e293b")
        timeline.plot(ax=ax)
        ax.set_xlabel("Date")
        ax.set_ylabel("Number of Attacks")
        ax.grid(alpha=0.2)

        for spine in ax.spines.values():
            spine.set_visible(False)
        plt.tight_layout()
        st.pyplot(fig, transparent=True)

    # ============================================================
    # SOURCE IP INTELLIGENCE
    # ============================================================

    if "Src_IP" in df.columns:

        st.subheader("Top Source IPs")

        fig, ax = plt.subplots(facecolor="#0f172a",figsize=(6, 4))
        ax.set_facecolor("#1e293b")
        df["Src_IP"].value_counts().head(10).plot(kind="bar", ax=ax)
        ax.grid(alpha=0.2)

        for spine in ax.spines.values():
            spine.set_visible(False)
        plt.tight_layout()
        st.pyplot(fig, transparent=True)

    # ============================================================
    # LIVE ATTACK SIMULATION
    # ============================================================

    st.markdown("---")
    st.subheader("⚡ Live Threat Simulation")

    col_sim1, col_sim2 = st.columns(2)

    if col_sim1.button("Simulate New Attack"):
        port = random.randint(20, 9000)
        st.error(f"🚨 Critical Attack Detected on Port {port}")

    threat_level = random.choice(["LOW", "MEDIUM", "HIGH"])
    col_sim2.metric("Current Threat Level", threat_level)

    st.markdown("---")

    st.success("Dashboard Active: Monitoring Threat Intelligence")