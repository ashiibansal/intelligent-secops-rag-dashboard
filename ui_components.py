import streamlit as st


def inject_unified_ui_css():
    st.markdown("""
    <style>
        .app-hero {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 55%, #1d4ed8 100%);
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 22px;
            padding: 1.35rem 1.5rem 1.2rem 1.5rem;
            margin: 0.2rem 0 1rem 0;
            box-shadow: 0 12px 32px rgba(2, 6, 23, 0.28);
        }
        .app-hero-title {
            color: #f8fafc;
            font-size: 2rem;
            font-weight: 800;
            margin: 0;
            line-height: 1.2;
        }
        .app-hero-subtitle {
            color: #cbd5e1;
            font-size: 1rem;
            margin-top: 0.45rem;
            margin-bottom: 0.9rem;
        }
        .hero-chip-row {
            display: flex;
            gap: 0.55rem;
            flex-wrap: wrap;
            margin-top: 0.4rem;
        }
        .hero-chip {
            background: rgba(255,255,255,0.1);
            color: #e2e8f0;
            border: 1px solid rgba(255,255,255,0.14);
            border-radius: 999px;
            padding: 0.35rem 0.7rem;
            font-size: 0.82rem;
            font-weight: 600;
        }

        .summary-card {
            background: linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(30, 41, 59, 0.96));
            border: 1px solid rgba(148, 163, 184, 0.14);
            border-radius: 18px;
            padding: 0.95rem 1rem;
            min-height: 112px;
            box-shadow: 0 8px 20px rgba(2, 6, 23, 0.16);
        }
        .summary-label {
            color: #93c5fd;
            font-size: 0.78rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            margin-bottom: 0.35rem;
        }
        .summary-value {
            color: #f8fafc;
            font-size: 1.55rem;
            font-weight: 800;
            line-height: 1.1;
            margin-bottom: 0.25rem;
            word-break: break-word;
        }
        .summary-subtext {
            color: #94a3b8;
            font-size: 0.88rem;
            line-height: 1.3;
        }

        .workflow-shell {
            background: rgba(15, 23, 42, 0.72);
            border: 1px solid rgba(148, 163, 184, 0.13);
            border-radius: 18px;
            padding: 0.95rem 1rem 0.7rem 1rem;
            margin: 0.2rem 0 1rem 0;
        }
        .workflow-title {
            color: #e2e8f0;
            font-size: 0.96rem;
            font-weight: 700;
            margin-bottom: 0.7rem;
        }
        .step-row {
            display: flex;
            gap: 0.55rem;
            flex-wrap: wrap;
        }
        .step-pill {
            border-radius: 999px;
            padding: 0.45rem 0.8rem;
            font-size: 0.84rem;
            font-weight: 700;
            border: 1px solid;
        }
        .step-complete {
            background: rgba(16, 185, 129, 0.12);
            color: #d1fae5;
            border-color: rgba(16, 185, 129, 0.38);
        }
        .step-current {
            background: rgba(59, 130, 246, 0.14);
            color: #dbeafe;
            border-color: rgba(59, 130, 246, 0.42);
        }
        .step-pending {
            background: rgba(148, 163, 184, 0.08);
            color: #cbd5e1;
            border-color: rgba(148, 163, 184, 0.18);
        }

        .sidebar-panel {
            background: linear-gradient(180deg, rgba(15,23,42,0.97), rgba(30,41,59,0.97));
            border: 1px solid rgba(148,163,184,0.14);
            border-radius: 16px;
            padding: 0.9rem;
            margin-bottom: 0.8rem;
        }
        .sidebar-panel-title {
            color: #93c5fd;
            font-size: 0.83rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            font-weight: 700;
            margin-bottom: 0.45rem;
        }
        .sidebar-kv {
            color: #e2e8f0;
            font-size: 0.9rem;
            margin: 0.25rem 0;
        }
        .sidebar-kv strong {
            color: #f8fafc;
        }

        .section-shell {
            background: rgba(15, 23, 42, 0.68);
            border: 1px solid rgba(148, 163, 184, 0.12);
            border-radius: 18px;
            padding: 1rem 1rem 0.8rem 1rem;
            margin-bottom: 1rem;
        }

        .status-card {
            background: linear-gradient(180deg, rgba(15,23,42,0.96), rgba(30,41,59,0.96));
            border: 1px solid rgba(148,163,184,0.14);
            border-radius: 16px;
            padding: 0.9rem 1rem;
            margin: 0.4rem 0 1rem 0;
        }

        div[data-testid="stMetric"] {
            background: linear-gradient(180deg, rgba(15,23,42,0.96), rgba(30,41,59,0.96));
            border: 1px solid rgba(148,163,184,0.14);
            padding: 0.8rem 0.9rem;
            border-radius: 16px;
            box-shadow: 0 8px 20px rgba(2, 6, 23, 0.16);
        }
        div[data-testid="stMetricLabel"] {
            color: #93c5fd !important;
            font-weight: 700 !important;
        }
        div[data-testid="stMetricValue"] {
            color: #f8fafc !important;
        }
    </style>
    """, unsafe_allow_html=True)


def render_top_header(title, subtitle, chips=None):
    chips = chips or []
    chip_html = "".join([f'<span class="hero-chip">{chip}</span>' for chip in chips])

    st.markdown(f"""
    <div class="app-hero">
        <div class="app-hero-title">{title}</div>
        <div class="app-hero-subtitle">{subtitle}</div>
        <div class="hero-chip-row">{chip_html}</div>
    </div>
    """, unsafe_allow_html=True)


def render_summary_cards(cards):
    cols = st.columns(len(cards))
    for col, card in zip(cols, cards):
        with col:
            st.markdown(f"""
            <div class="summary-card">
                <div class="summary-label">{card.get('label', '')}</div>
                <div class="summary-value">{card.get('value', '')}</div>
                <div class="summary-subtext">{card.get('subtext', '')}</div>
            </div>
            """, unsafe_allow_html=True)


def render_workflow_status(title, steps, current_step):
    pills = []
    for idx, step in enumerate(steps):
        if idx < current_step:
            cls = "step-pill step-complete"
            prefix = "✓"
        elif idx == current_step:
            cls = "step-pill step-current"
            prefix = "●"
        else:
            cls = "step-pill step-pending"
            prefix = "○"
        pills.append(f'<span class="{cls}">{prefix} {step}</span>')

    st.markdown(f"""
    <div class="workflow-shell">
        <div class="workflow-title">{title}</div>
        <div class="step-row">
            {''.join(pills)}
        </div>
    </div>
    """, unsafe_allow_html=True)


def render_sidebar_context(title, items):
    st.sidebar.markdown(f"""
    <div class="sidebar-panel">
        <div class="sidebar-panel-title">{title}</div>
        {''.join([f"<div class='sidebar-kv'><strong>{k}:</strong> {v}</div>" for k, v in items.items()])}
    </div>
    """, unsafe_allow_html=True)