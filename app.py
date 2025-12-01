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

PRIMARY = "#2F54EB"     # biru utama (mirip dashboard)
ACCENT  = "#10B981"     # hijau (status OK)
DANGER  = "#EF4444"     # merah
BG      = "#F5F7FB"     # background lembut

st.markdown(
    f"""
    <style>
    /* background halaman */
    .stApp {{
        background-color: {BG};
    }}
    /* container utama biar agak mepet kiri-kanan */
    .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }}
    .card {{
        background-color: #FFFFFF;
        border-radius: 14px;
        padding: 1.1rem 1.3rem;
        border: 1px solid #E5E7EB;
        box-shadow: 0 1px 3px rgba(15,23,42,0.08);
    }}
    .card-title {{
        font-size: 0.85rem;
        color: #6B7280;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 0.35rem;
    }}
    .card-value {{
        font-size: 1.6rem;
        font-weight: 700;
        color: #111827;
    }}
    .badge-primary {{
        background-color: {PRIMARY};
        color: white;
        border-radius: 999px;
        padding: 0.15rem 0.6rem;
        font-size: 0.7rem;
        font-weight: 600;
    }}
    .small-label {{
        font-size: 0.8rem;
        color: #6B7280;
    }}
    textarea {{
        font-size: 0.9rem !important;
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
        <br>- AES standar (S-BOX standar)<br>- AES SBOX44 (modifikasi)
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
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1rem;">
        <div>
            <h2 style="margin-bottom:0;">AES Crypto Dashboard</h2>
            <p style="color:#6B7280; margin-top:0.2rem; font-size:0.9rem;">
                Simple dashboard untuk mencoba enkripsi & dekripsi AES.
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
                <div class="card-value" style="font-size:1.2rem;">{st.session_state.last_algo}</div>
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
                <div class="card-value" style="font-size:1.2rem; color:{color};">
                    {status_text}
                </div>
                <div class="small-label">Mode: {st.session_state.last_mode}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### 🔎 Ringkasan")
    st.write(
        """
        Halaman ini hanya menampilkan statistik kecil untuk memantau
        berapa kali kamu melakukan enkripsi/dekripsi dan varian algoritma yang dipakai.
        Semua angka dihitung di sisi frontend (session state).
        """
    )


# =========================
#  HALAMAN: ENCRYPT / DECRYPT
# =========================
elif menu == "Encrypt / Decrypt":

    top_left, top_right = st.columns([2, 1])

    with top_left:
        st.markdown("### 🔧 Pengaturan")

        algo = st.selectbox(
            "Pilih Algoritma AES",
            ["AES Standard (S-BOX Std)", "AES SBOX44 (Modifikasi)"],
        )

        mode = st.segmented_control(
            "Mode Operasi",
            options=["Enkripsi", "Dekripsi"],
            default="Enkripsi",
        )

        key = st.text_input(
            "Key (16 karakter / 128-bit)",
            type="password",
            help="Key harus tepat 16 karakter (AES-128).",
            max_chars=32,  # jaga-jaga, tapi nanti dicek lagi oleh backend
        )

    with top_right:
        st.markdown("### ℹ️ Petunjuk Singkat")
        if mode == "Enkripsi":
            st.markdown(
                """
                - Masukkan **plaintext biasa** (bisa huruf, angka, simbol).\n
                - Output akan berupa **hex string**.\n
                - Simpan hex string itu jika ingin didekripsi lagi.
                """
            )
        else:
            st.markdown(
                """
                - Masukkan **ciphertext dalam bentuk hex** (hasil enkripsi sebelumnya).\n
                - Pastikan tidak ada spasi & panjangnya valid (kelipatan 32 hex per blok).\n
                - Hasil dekripsi berupa **plaintext**.
                """
            )

    st.markdown("### 📝 Input Data")

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

    st.markdown("### 📤 Output")

    if proses:
        if not user_text.strip():
            st.warning("Input masih kosong.")
        elif not key:
            st.warning("Key masih kosong.")
        else:
            try:
                # pilih fungsi backend berdasarkan algoritma & mode
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

                # tampilkan hasil
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
    st.markdown("### ℹ️ Tentang Aplikasi")
    st.write(
        """
        Aplikasi ini adalah demo sederhana untuk:
        - Enkripsi dan dekripsi teks menggunakan **AES-128**.
        - Membandingkan implementasi **AES standar** dan **AES SBOX44 (modifikasi)**.
        
        Backend fungsi AES diambil dari file `aes_backend.py` yang berisi
        implementasi lengkap (S-BOX, key schedule, dll) yang sudah kamu buat.
        """
    )
    st.info("Kalau ingin menambahkan grafik, tabel, atau log detail blok AES, tinggal kita tambah section baru di sini. 😉")
