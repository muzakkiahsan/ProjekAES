import streamlit as st
import pandas as pd

from aes_backend import (
    encrypt_aes_std_str,
    decrypt_aes_std_str,
    encrypt_aes_44_str,
    decrypt_aes_44_str,
    avalanche_plaintext,
    key_sensitivity,
)

# =========================
#  CONFIG + THEME
# =========================
st.set_page_config(
    page_title="Crypto S-Box Analyzer",
    page_icon="🔐",
    layout="wide",
)

BG = "#020617"          # page background
CARD_BG = "#020617"     # card background (same, but with border + shadow)
CARD_BORDER = "#1E293B" # slate border
PRIMARY = "#6366F1"     # violet
ACCENT = "#22C55E"      # green
WARN = "#F97316"
DANGER = "#DC2626"
TEXT_MAIN = "#E5E7EB"
TEXT_MUTED = "#9CA3AF"

st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: {BG};
        color: {TEXT_MAIN};
    }}
    .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }}
    h1, h2, h3, h4, h5, h6 {{
        color: {TEXT_MAIN};
    }}
    .card {{
        background: {CARD_BG};
        border-radius: 18px;
        padding: 1.2rem 1.4rem;
        border: 1px solid {CARD_BORDER};
        box-shadow: 0 12px 40px rgba(15,23,42,0.55);
    }}
    .card-soft {{
        background: #020617;
        border-radius: 18px;
        padding: 1.0rem 1.3rem;
        border: 1px solid #111827;
        box-shadow: 0 10px 30px rgba(0,0,0,0.45);
    }}
    .card-title {{
        font-size: 0.8rem;
        color: {TEXT_MUTED};
        text-transform: uppercase;
        letter-spacing: 0.14em;
        margin-bottom: 0.4rem;
    }}
    .card-heading {{
        font-size: 1.0rem;
        font-weight: 600;
        margin-bottom: 0.15rem;
    }}
    .card-sub {{
        font-size: 0.80rem;
        color: {TEXT_MUTED};
    }}
    .pill {{
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0.15rem 0.65rem;
        border-radius: 999px;
        font-size: 0.7rem;
        font-weight: 600;
        border: 1px solid #1F2937;
        background: #020617;
        color: {TEXT_MUTED};
    }}
    .pill-green {{
        border-color: {ACCENT};
        color: {ACCENT};
        background: rgba(34,197,94,0.09);
    }}
    .pill-red {{
        border-color: {DANGER};
        color: {DANGER};
        background: rgba(220,38,38,0.08);
    }}
    .metric-value {{
        font-size: 2.0rem;
        font-weight: 700;
        letter-spacing: 0.04em;
    }}
    .metric-label {{
        font-size: 0.75rem;
        color: {TEXT_MUTED};
    }}
    .metric-tag {{
        font-size: 0.7rem;
        color: {TEXT_MUTED};
    }}
    .section-caption {{
        font-size: 0.8rem;
        color: {TEXT_MUTED};
        margin-top: 0.15rem;
    }}
    .top-nav {{
        display:flex;
        gap:0.75rem;
        align-items:center;
    }}
    .badge-primary {{
        background: rgba(99,102,241,0.18);
        color: {PRIMARY};
        border-radius: 999px;
        padding: 0.2rem 0.8rem;
        font-size: 0.72rem;
        font-weight: 600;
        border: 1px solid rgba(129,140,248,0.7);
    }}
    .alg-label {{
        font-size: 0.78rem;
        color: {TEXT_MUTED};
        margin-bottom: 0.25rem;
    }}
    textarea {{
        font-size: 0.9rem !important;
        background: #020617 !important;
        color: {TEXT_MAIN} !important;
    }}
    .stTextInput>div>div>input {{
        background: #020617;
        color: {TEXT_MAIN};
        border-radius: 999px;
        border: 1px solid #111827;
    }}
    .stTextArea textarea {{
        border-radius: 16px !important;
        border: 1px solid #111827 !important;
    }}
    .stSelectbox>div>div>select {{
        background: #020617;
        color: {TEXT_MAIN};
    }}
    .stRadio>div>label, .stRadio>div>div>label {{
        color: {TEXT_MAIN};
    }}
    .stTabs [data-baseweb="tab-list"] {{
        gap: 0.4rem;
    }}
    .stTabs [data-baseweb="tab"] {{
        background-color: #020617;
        border-radius: 999px;
        padding-top: 0.35rem;
        padding-bottom: 0.35rem;
        padding-left: 0.9rem;
        padding-right: 0.9rem;
        border: 1px solid #111827;
        color: {TEXT_MUTED};
    }}
    .stTabs [aria-selected="true"] {{
        background-color: #111827 !important;
        color: {TEXT_MAIN} !important;
        border-color: {PRIMARY} !important;
    }}
    .stButton>button {{
        border-radius: 999px;
        border: 1px solid #1F2937;
        background: #0B1120;
        color: {TEXT_MAIN};
        padding: 0.4rem 0.9rem;
        font-size: 0.9rem;
        font-weight: 500;
    }}
    .stButton>button:hover {{
        border-color: {PRIMARY};
        background: #111827;
        color: {TEXT_MAIN};
    }}
    .stCode, code {{
        background: #020617 !important;
        color: {TEXT_MAIN} !important;
    }}
    .small-muted {{
        font-size: 0.78rem;
        color: {TEXT_MUTED};
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# =========================
#  SESSION STATE
# =========================
if "last_plaintext" not in st.session_state:
    st.session_state.last_plaintext = ""
if "last_key" not in st.session_state:
    st.session_state.last_key = ""
if "last_algo_name" not in st.session_state:
    st.session_state.last_algo_name = "Custom S-Box 44"

# =========================
#  HEADER
# =========================
header_col1, header_col2 = st.columns([3, 1])

with header_col1:
    st.markdown(
        """
        <div>
            <div style="font-size:0.78rem; letter-spacing:0.16em; text-transform:uppercase; color:#6B7280; margin-bottom:0.2rem;">
                Crypto S-Box Analyzer
            </div>
            <h2 style="margin:0; padding:0;">Scientific comparison: Custom S-Box 44 vs AES Standard</h2>
            <div class="section-caption">
                Playground for AES-128 ECB encryption with paper-based S-Box 44 and baseline AES, including avalanche diagnostics.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

with header_col2:
    st.markdown(
        """
        <div style="display:flex; justify-content:flex-end; align-items:center; height:100%;">
            <span class="badge-primary">Dark Lab Mode</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

st.markdown("")

# =========================
#  TOP-LEVEL TABS: Playground / Analysis
# =========================
tab_playground, tab_analysis = st.tabs(["Playground", "Analysis"])

# ============================================================
#  PLAYGROUND TAB
# ============================================================
with tab_playground:
    left, right = st.columns([1.1, 2.0])

    # -------------------- LEFT: GLOBAL CONFIG --------------------
    with left:
        st.markdown(
            """
            <div class="card">
                <div class="card-title">Global Configuration</div>
                <div class="card-heading">Algorithm & Key</div>
                <div class="card-sub">
                    Choose S-Box variant and set 16-byte secret key. Mode is fixed to AES-128 ECB for comparison.
                </div>
                <div style="margin-top:0.9rem;"></div>
            """,
            unsafe_allow_html=True,
        )

        algo = st.radio(
            "Algorithm",
            ["Custom S-Box 44", "Standard AES"],
            index=0,
            label_visibility="collapsed",
        )

        st.markdown(
            """
            <div class="alg-label">Secret Key (auto-padded to 16 bytes if shorter)</div>
            """,
            unsafe_allow_html=True,
        )

        key_input = st.text_input(
            "Secret key",
            value=st.session_state.last_key or "MySecretKey12345",
            max_chars=32,
            label_visibility="collapsed",
        )

        # info row
        key_len = len(key_input.encode("utf-8"))
        if key_len == 16:
            key_status = f"Perfect ({key_len} bytes)"
            pill_class = "pill-green"
        else:
            key_status = f"{key_len} bytes (backend will reject if ≠16)"
            pill_class = "pill-red"

        st.markdown(
            f"""
            <div style="display:flex; justify-content:space-between; align-items:center; margin-top:0.6rem;">
                <span class="small-muted">Mode: AES-128 ECB</span>
                <span class="{pill_class}">{key_status}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("</div>", unsafe_allow_html=True)  # close card

    # -------------------- RIGHT: ENCRYPT / DECRYPT PANEL --------------------
    with right:
        st.markdown(
            """
            <div class="card-soft">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.6rem;">
                    <div>
                        <div class="card-title" style="margin-bottom:0.25rem;">Playground</div>
                        <div class="card-heading">Encryption Workspace</div>
                    </div>
                    <div class="pill">UTF-8 text → Hex</div>
                </div>
            """,
            unsafe_allow_html=True,
        )

        mode = st.segmented_control(
            "Mode",
            options=["Encryption mode", "Decryption mode"],
            default="Encryption mode",
        )

        st.markdown(
            '<div style="margin-top:0.4rem;"></div>',
            unsafe_allow_html=True,
        )

        # layout for plaintext / ciphertext
        st.markdown(
            """
            <div style="font-size:0.78rem; font-weight:600; margin-bottom:0.2rem;">Plaintext Input</div>
            """,
            unsafe_allow_html=True,
        )

        if mode.startswith("Encryption"):
            default_plain = st.session_state.last_plaintext or "Hello World"
            plaintext = st.text_area(
                "Plaintext",
                value=default_plain,
                placeholder="Type message to encrypt…",
                height=140,
                label_visibility="collapsed",
            )
            ciphertext_hex = ""
        else:
            plaintext = ""
            ciphertext_hex = st.text_area(
                "Ciphertext (hex)",
                value="",
                placeholder="Paste hexadecimal ciphertext to decrypt…",
                height=140,
                label_visibility="collapsed",
            )

        st.markdown(
            '<div style="margin-top:0.4rem;"></div>',
            unsafe_allow_html=True,
        )

        col_btn, col_tag = st.columns([1.1, 1])
        with col_btn:
            run_btn = st.button(
                "Encrypt message" if mode.startswith("Encryption") else "Decrypt message",
                use_container_width=True,
            )
        with col_tag:
            st.markdown(
                """
                <div style="text-align:right;">
                    <span class="pill">Output format: Hex / UTF-8</span>
                </div>
                """,
                unsafe_allow_html=True,
            )

        st.markdown(
            """
            <div style="margin-top:0.8rem; font-size:0.78rem; font-weight:600; margin-bottom:0.2rem;">
                Ciphertext Result
            </div>
            """,
            unsafe_allow_html=True,
        )

        if run_btn:
            if mode.startswith("Encryption"):
                if not plaintext:
                    st.warning("Plaintext kosong.")
                elif len(key_input.encode("utf-8")) != 16:
                    st.error("Key harus tepat 16 byte (karakter UTF-8 sederhana).")
                else:
                    try:
                        if algo == "Custom S-Box 44":
                            cipher_hex = encrypt_aes_44_str(plaintext, key_input)
                        else:
                            cipher_hex = encrypt_aes_std_str(plaintext, key_input)

                        st.session_state.last_plaintext = plaintext
                        st.session_state.last_key = key_input
                        st.session_state.last_algo_name = algo

                        st.code(cipher_hex, language="text")
                    except Exception as ex:
                        st.error(f"Error enkripsi: {ex}")
            else:
                if not ciphertext_hex.strip():
                    st.warning("Ciphertext kosong.")
                elif len(key_input.encode("utf-8")) != 16:
                    st.error("Key harus tepat 16 byte (karakter UTF-8 sederhana).")
                else:
                    try:
                        if algo == "Custom S-Box 44":
                            plain_out = decrypt_aes_44_str(ciphertext_hex.strip(), key_input)
                        else:
                            plain_out = decrypt_aes_std_str(ciphertext_hex.strip(), key_input)

                        st.code(plain_out, language="text")
                    except Exception as ex:
                        st.error(f"Error dekripsi: {ex}")
        else:
            st.markdown(
                '<div style="border-radius:14px; border:1px dashed #1F2937; padding:0.9rem; font-size:0.8rem; color:#6B7280;">Encrypted result will appear here…</div>',
                unsafe_allow_html=True,
            )

        st.markdown("</div>", unsafe_allow_html=True)  # close card-soft

# ============================================================
#  ANALYSIS TAB
# ============================================================
with tab_analysis:
    left, right = st.columns([1.1, 2.0])

    # ---------- LEFT: REAL-TIME STRENGTH VERIFICATION ----------
    with left:
        st.markdown(
            """
            <div class="card">
                <div class="card-title">Real-time Strength Verification</div>
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.6rem;">
                    <div class="card-heading">Paper-based metrics for Custom S-Box 44</div>
                    <div class="pill">Verify math offline</div>
                </div>
            """,
            unsafe_allow_html=True,
        )

        # Non-linearity (theoretical)
        NL_VALUE = 112  # paper value
        st.markdown(
            f"""
            <div style="margin-bottom:0.9rem;">
                <div class="metric-label">Non-Linearity (NL)</div>
                <div style="display:flex; align-items:center; gap:0.6rem; margin-top:0.1rem;">
                    <span class="metric-value" style="font-size:1.7rem; color:{ACCENT};">{NL_VALUE}</span>
                    <span class="pill">Matches AES standard S-Box</span>
                </div>
                <div class="section-caption">Theoretical non-linearity per output bit from the original S-Box 44 paper.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        # SAC (Strict Avalanche Criterion) – paper claim
        SAC_PAPER_SBOX44 = 0.50073
        SAC_PAPER_AES = 0.50488
        dev_44 = abs(SAC_PAPER_SBOX44 - 0.5)
        dev_aes = abs(SAC_PAPER_AES - 0.5)

        st.markdown(
            f"""
            <div style="margin-top:0.3rem;">
                <div class="metric-label">Strict Avalanche (SAC)</div>
                <div style="display:flex; align-items:baseline; gap:0.55rem; margin-top:0.15rem;">
                    <span class="metric-value" style="font-size:1.9rem; color:{ACCENT};">
                        {SAC_PAPER_SBOX44:.5f}
                    </span>
                    <span class="metric-tag">(Paper claim for S-Box 44)</span>
                </div>
                <div class="section-caption">Ideal value is 0.5. Values reported for full AES-round experiment.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown(
            f"""
            <div style="margin-top:0.8rem; border-radius:12px; border:1px solid #111827; padding:0.55rem 0.7rem; background:#020617;">
                <div class="metric-label" style="margin-bottom:0.2rem;">Deviation from ideal (|SAC − 0.5|)</div>
                <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.8rem;">
                    <div>
                        <div>S-Box 44</div>
                        <div class="small-muted">Closer to 0.5 than Standard AES.</div>
                    </div>
                    <div style="text-align:right;">
                        <div style="font-weight:600; color:{ACCENT};">{dev_44:.5f}</div>
                        <div class="small-muted">Standard AES: {dev_aes:.5f}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("</div>", unsafe_allow_html=True)  # close card

    # ---------- RIGHT: AVALANCHE VISUALIZER ----------
    with right:
        st.markdown(
            """
            <div class="card-soft">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.6rem;">
                    <div>
                        <div class="card-title">01 / 10</div>
                        <div class="card-heading">Avalanche Visualizer</div>
                        <div class="card-sub">Uses plaintext and key from the last successful encryption in Playground tab.</div>
                    </div>
                    <div>
            """,
            unsafe_allow_html=True,
        )

        run_av = st.button("Run analysis", key="run_av_all")

        st.markdown(
            """
                    </div>
                </div>
            """,
            unsafe_allow_html=True,
        )

        if not st.session_state.last_plaintext or not st.session_state.last_key:
            st.markdown(
                '<div style="border-radius:16px; border:1px dashed #1F2937; padding:1.3rem; text-align:center; color:#6B7280; font-size:0.85rem;">'
                "Run an encryption first in the Playground tab to populate plaintext and key."
                "</div>",
                unsafe_allow_html=True,
            )
        else:
            if not run_av:
                st.markdown(
                    '<div style="border-radius:16px; border:1px dashed #1F2937; padding:1.3rem; text-align:center; color:#6B7280; font-size:0.85rem;">'
                    "Ready. Press Run analysis to compute avalanche and key-sensitivity for both algorithms."
                    "</div>",
                    unsafe_allow_html=True,
                )
            else:
                pt = st.session_state.last_plaintext
                key_used = st.session_state.last_key

                try:
                    res_av = avalanche_plaintext(pt, key_used)
                    res_ks = key_sensitivity(pt, key_used)

                    # Avalanche table
                    df_av = pd.DataFrame(
                        {
                            "Algorithm": ["Standard AES", "Custom S-Box 44"],
                            "Changed bits": [
                                res_av["std"]["changed_bits"],
                                res_av["sbox44"]["changed_bits"],
                            ],
                            "Total bits": [
                                res_av["std"]["total_bits"],
                                res_av["sbox44"]["total_bits"],
                            ],
                            "Percent": [
                                round(res_av["std"]["percent"], 2),
                                round(res_av["sbox44"]["percent"], 2),
                            ],
                        }
                    )

                    df_ks = pd.DataFrame(
                        {
                            "Algorithm": ["Standard AES", "Custom S-Box 44"],
                            "Changed bits": [
                                res_ks["std"]["changed_bits"],
                                res_ks["sbox44"]["changed_bits"],
                            ],
                            "Total bits": [
                                res_ks["std"]["total_bits"],
                                res_ks["sbox44"]["total_bits"],
                            ],
                            "Percent": [
                                round(res_ks["std"]["percent"], 2),
                                round(res_ks["sbox44"]["percent"], 2),
                            ],
                        }
                    )

                    st.markdown(
                        """
                        <div style="font-size:0.82rem; font-weight:600; margin-top:0.4rem; margin-bottom:0.2rem;">
                            Avalanche on plaintext (flip 1 bit in first byte)
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.dataframe(df_av, use_container_width=True, height=160)

                    st.markdown(
                        """
                        <div style="font-size:0.82rem; font-weight:600; margin-top:0.7rem; margin-bottom:0.2rem;">
                            Key sensitivity (flip 1 bit in first key byte)
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )
                    st.dataframe(df_ks, use_container_width=True, height=160)

                    avg_av = (res_av["std"]["percent"] + res_av["sbox44"]["percent"]) / 2.0
                    avg_ks = (res_ks["std"]["percent"] + res_ks["sbox44"]["percent"]) / 2.0

                    st.markdown(
                        f"""
                        <div style="margin-top:0.9rem; border-radius:12px; border:1px solid #111827; padding:0.6rem 0.75rem;">
                            <div class="small-muted" style="margin-bottom:0.15rem;">Summary (ideal ≈ 50%)</div>
                            <div style="display:flex; justify-content:space-between; font-size:0.83rem;">
                                <div>Avalanche average across algorithms</div>
                                <div style="font-weight:600;">{avg_av:.2f} %</div>
                            </div>
                            <div style="display:flex; justify-content:space-between; font-size:0.83rem; margin-top:0.1rem;">
                                <div>Key-sensitivity average across algorithms</div>
                                <div style="font-weight:600;">{avg_ks:.2f} %</div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                except Exception as ex:
                    st.error(f"Gagal menghitung avalanche: {ex}")

        st.markdown("</div>", unsafe_allow_html=True)  # close card-soft
