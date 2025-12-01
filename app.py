import streamlit as st
from aes_backend import (
    encrypt_aes_std_str,
    decrypt_aes_std_str,
    encrypt_aes_44_str,
    decrypt_aes_44_str,
)

# =========================
#  CONFIG + CUSTOM STYLE
# =========================
st.set_page_config(
    page_title="AES Crypto Dashboard",
    page_icon="🔐",
    layout="wide",
)

# Palet warna baru (lebih hangat)
PRIMARY = "#F97316"  # oranye hangat (utama)
ACCENT = "#16A34A"   # hijau lembut untuk status OK
DANGER = "#DC2626"   # merah untuk error
BG = "#FFF7ED"       # krem hangat sebagai background

st.markdown(
    f"""
    <style>
    html, body, [class*="stApp"] {{
        font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        line-height: 1.5;
    }}

    .stApp {{
        background-color: {BG};
    }}

    .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
        padding-left: 2.2rem;
        padding-right: 2.2rem;
        max-width: 1200px;
        margin: 0 auto;
    }}

    .card {{
        background-color: #FFFFFF;
        border-radius: 14px;
        padding: 1.2rem 1.4rem;
        border: 1px solid #F3E8FF20;
        box-shadow: 0 8px 18px rgba(15,23,42,0.06);
    }}

    .card-title {{
        font-size: 0.9rem;
        color: #6B7280;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 0.4rem;
    }}

    .card-value {{
        font-size: 1.8rem;
        font-weight: 700;
        color: #1F2933;
        margin-bottom: 0.25rem;
    }}

    .badge-primary {{
        background: linear-gradient(135deg, {PRIMARY}, #FDBA74);
        color: white;
        border-radius: 999px;
        padding: 0.25rem 0.8rem;
        font-size: 0.75rem;
        font-weight: 600;
        border: none;
    }}

    .small-label {{
        font-size: 0.82rem;
        color: #6B7280;
    }}

    textarea {{
        font-size: 0.95rem !important;
    }}

    .page-header-title {{
        margin-bottom: 0;
        font-size: 1.7rem;
        font-weight: 700;
        color: #1F2933;
    }}

    .page-header-subtitle {{
        color: #6B7280;
        margin-top: 0.25rem;
        font-size: 0.9rem;
    }}

    .section-label {{
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        color: #9CA3AF;
        margin-bottom: 0.3rem;
    }}

    .stRadio > label, .st-emotion-cache-1x8cf1d > label {{
        font-size: 0.9rem;
        font-weight: 600;
    }}

    .stTextInput, .stTextArea {{
        margin-bottom: 0.5rem;
    }}

    .st-emotion-cache-1y4p8pa, .stTooltipIcon span {{
        font-size: 0.8rem !important;
    }}
    </style>
    """,
    unsafe_allow_html=True,
)

# =========================
#  SESSION STATE (STATISTIK)
# =========================
if "total_encrypt" not in st.session_state:
    st.session_state.total_encrypt = 0
if "total_decrypt" not in st.session_state:
    st.session_state.total_decrypt = 0
if "last_algo" not in st.session_state:
    st.session_state.last_algo = "-"
if "last_mode" not in st.session_state:
    st.session_state.last_mode = "-"
if "last_success" not in st.session_state:
    st.session_state.last_success = False

# =========================
#  SIDEBAR
# =========================
with st.sidebar:
    st.markdown("### 🔐 AES Crypto Tool")
    st.markdown(
        """
        <span class="small-label">
        Demo sederhana enkripsi & dekripsi AES dengan dua varian:
        <br>- AES standar (S-BOX standar)
        <br>- AES SBOX44 (modifikasi)
        </span>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    menu = st.radio(
        "Navigation",
        ["Dashboard", "Encrypt / Decrypt", "Info"],
        index=1,
    )

    st.markdown("---")
    st.caption("Made with Streamlit")

# =========================
#  HEADER ATAS
# =========================
st.markdown(
    f"""
    <div style="
        display:flex;
        justify-content:space-between;
        align-items:center;
        margin-bottom:1.2rem;
        padding-bottom:0.6rem;
        border-bottom:1px solid #E5E7EB;">
        <div>
            <div class="page-header-title">AES Crypto Dashboard</div>
            <p class="page-header-subtitle">
                Simple dashboard untuk mencoba enkripsi & dekripsi AES dengan tampilan yang lebih bersih dan nyaman dibaca.
            </p>
        </div>
        <div>
            <span class="badge-primary">Demo</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

# =========================
#  HALAMAN: DASHBOARD
# =========================
if menu == "Dashboard":
    st.markdown('<div class="section-label">Ringkasan Aktivitas</div>', unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns(4)

    with col1:
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">Total Encryption</div>
                <div class="card-value">{st.session_state.total_encrypt}</div>
                <div class="small-label">Jumlah proses enkripsi yang sukses.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col2:
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">Total Decryption</div>
                <div class="card-value">{st.session_state.total_decrypt}</div>
                <div class="small-label">Jumlah proses dekripsi yang sukses.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">Last Algorithm</div>
                <div class="card-value" style="font-size:1.3rem;">
                    {st.session_state.last_algo}
                </div>
                <div class="small-label">Varian AES terakhir yang dipakai.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        color = ACCENT if st.session_state.last_success else DANGER
        status_text = "Success" if st.session_state.last_success else "Error / None"
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">Last Operation</div>
                <div class="card-value" style="font-size:1.3rem; color:{color};">
                    {status_text}
                </div>
                <div class="small-label">Mode: {st.session_state.last_mode}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### 📊 Ringkasan")
    st.write(
        """
        Halaman ini menampilkan statistik singkat:
        - Berapa kali enkripsi dan dekripsi berhasil dilakukan.
        - Varian AES terakhir yang digunakan.
        - Status operasi terakhir (berhasil atau error).

        Semua angka dihitung di sisi frontend (session state), dan akan reset jika halaman direfresh.
        """
    )

# =========================
#  HALAMAN: ENCRYPT / DECRYPT
# =========================
elif menu == "Encrypt / Decrypt":

    st.markdown('<div class="section-label">Pengaturan & Input</div>', unsafe_allow_html=True)
    top_left, top_right = st.columns([2, 1])

    with top_left:
        st.markdown("### Pengaturan")

        algo = st.selectbox(
            "Pilih Algoritma AES",
            ["AES Standard (S-BOX Std)", "AES SBOX44 (Modifikasi)"],
        )

        # Jika versi Streamlit tidak punya segmented_control, ganti ke radio
        try:
            mode = st.segmented_control(
                "Mode Operasi",
                options=["Enkripsi", "Dekripsi"],
                default="Enkripsi",
            )
        except AttributeError:
            mode = st.radio(
                "Mode Operasi",
                ["Enkripsi", "Dekripsi"],
                index=0,
            )

        key = st.text_input(
            "Key (16 karakter / 128-bit)",
            type="password",
            help="Key harus tepat 16 karakter (AES-128).",
            max_chars=32,
        )

    with top_right:
        st.markdown("### Petunjuk Singkat")
        if mode == "Enkripsi":
            st.markdown(
                """
                - Masukkan **plaintext biasa** (huruf, angka, simbol).
                - Output akan berupa **hex string**.
                - Simpan hex string itu jika ingin didekripsi lagi.
                """
            )
        else:
            st.markdown(
                """
                - Masukkan **ciphertext dalam bentuk hex** (hasil enkripsi sebelumnya).
                - Pastikan tidak ada spasi dan panjangnya valid (kelipatan 32 hex per blok).
                - Hasil dekripsi berupa **plaintext**.
                """
            )

    st.markdown("### Input Data")

    if mode == "Enkripsi":
        text_label = "Plaintext"
        text_placeholder = "Tulis pesan yang ingin dienkripsi..."
    else:
        text_label = "Ciphertext (Hex)"
        text_placeholder = "Tempel ciphertext hex di sini..."

    user_text = st.text_area(
        text_label,
        height=180,
        placeholder=text_placeholder,
    )

    col_btn, col_dummy = st.columns([1, 3])
    with col_btn:
        proses = st.button("🚀 Proses", use_container_width=True)

    st.markdown("### Output")

    if proses:
        if not user_text.strip():
            st.warning("Input masih kosong.")
        elif not key:
            st.warning("Key masih kosong.")
        else:
            try:
                if algo.startswith("AES Standard"):
                    if mode == "Enkripsi":
                        result = encrypt_aes_std_str(user_text, key)
                        st.session_state.total_encrypt += 1
                    else:
                        result = decrypt_aes_std_str(user_text.strip(), key)
                        st.session_state.total_decrypt += 1
                    st.session_state.last_algo = "AES Standard"
                else:
                    if mode == "Enkripsi":
                        result = encrypt_aes_44_str(user_text, key)
                        st.session_state.total_encrypt += 1
                    else:
                        result = decrypt_aes_44_str(user_text.strip(), key)
                        st.session_state.total_decrypt += 1
                    st.session_state.last_algo = "AES SBOX44"

                st.session_state.last_mode = mode
                st.session_state.last_success = True

                if mode == "Enkripsi":
                    st.success("Berhasil melakukan enkripsi.")
                    st.code(result, language="text")
                else:
                    st.success("Berhasil melakukan dekripsi.")
                    st.code(result, language="text")

            except Exception as e:
                st.session_state.last_mode = mode
                st.session_state.last_success = False
                st.error(f"Terjadi error: {e}")

# =========================
#  HALAMAN: INFO
# =========================
else:
    st.markdown('<div class="section-label">Informasi Aplikasi</div>', unsafe_allow_html=True)
    st.markdown("### Tentang Aplikasi")
    st.write(
        """
        Aplikasi ini adalah demo sederhana untuk:
        - Enkripsi dan dekripsi teks menggunakan **AES-128**.
        - Membandingkan implementasi **AES standar** dan **AES SBOX44 (modifikasi)**.

        Backend fungsi AES diambil dari file `aes_backend.py` yang berisi
        implementasi lengkap (S-BOX, key schedule, dan komponen lain).
        """
    )
    st.info(
        "Untuk menambahkan grafik, tabel, atau log detail blok AES, "
        "bisa ditambahkan section baru di halaman ini."
    )
