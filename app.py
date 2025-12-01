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
#  CONFIG + CUSTOM STYLE
# =========================
st.set_page_config(
    page_title="AES Crypto Dashboard",
    page_icon="🔐",
    layout="wide",
)

PRIMARY = "#1F2933"     # dark blue-gray
ACCENT  = "#0EA5E9"     # cyan
DANGER  = "#DC2626"     # red
SUCCESS = "#16A34A"     # green
BG      = "#F5F7FB"     # soft background

st.markdown(
    f"""
    <style>
    .stApp {{
        background-color: {BG};
    }}
    .block-container {{
        padding-top: 1.5rem;
        padding-bottom: 1.5rem;
        padding-left: 2rem;
        padding-right: 2rem;
    }}
    .card {{
        background-color: #FFFFFF;
        border-radius: 12px;
        padding: 1.0rem 1.2rem;
        border: 1px solid #E5E7EB;
        box-shadow: 0 1px 3px rgba(15,23,42,0.06);
    }}
    .card-title {{
        font-size: 0.8rem;
        color: #6B7280;
        text-transform: uppercase;
        letter-spacing: 0.06em;
        margin-bottom: 0.25rem;
    }}
    .card-value {{
        font-size: 1.5rem;
        font-weight: 700;
        color: #111827;
        margin-bottom: 0.1rem;
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
        font-size: 0.78rem;
        color: #6B7280;
    }}
    textarea {{
        font-size: 0.9rem !important;
    }}
    .section-title {{
        font-size: 1.05rem;
        font-weight: 600;
        margin-bottom: 0.2rem;
    }}
    .section-sub {{
        font-size: 0.85rem;
        color: #6B7280;
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
    st.markdown("### AES Crypto Tool")
    st.markdown(
        """
        <span class="small-label">
        Alat sederhana untuk:
        <br>• Enkripsi dan dekripsi AES-128
        <br>• Perbandingan AES standar dan AES SBOX44
        <br>• Analisis avalanche dan key sensitivity
        </span>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")
    menu = st.radio(
        "Menu",
        ["Dashboard", "Encrypt / Decrypt", "Avalanche Analysis", "Info"],
        index=1,
    )

    st.markdown("---")
    st.caption("Backend: aes_backend.py")


# =========================
#  HEADER ATAS
# =========================
st.markdown(
    """
    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:1.0rem;">
        <div>
            <h2 style="margin-bottom:0;">AES Crypto Dashboard</h2>
            <p style="color:#6B7280; margin-top:0.25rem; font-size:0.9rem;">
                Panel sederhana untuk eksperimen AES-128 dan varian SBOX44.
            </p>
        </div>
        <div>
            <span class="badge-primary">Local Demo</span>
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
                <div class="small-label">Jumlah proses enkripsi yang selesai.</div>
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
                <div class="small-label">Jumlah proses dekripsi yang selesai.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col3:
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">Last Algorithm</div>
                <div class="card-value" style="font-size:1.1rem;">{st.session_state.last_algo}</div>
                <div class="small-label">Varian AES terakhir yang digunakan.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col4:
        color = SUCCESS if st.session_state.last_success else DANGER
        status_text = "Success" if st.session_state.last_success else "Error / None"
        st.markdown(
            f"""
            <div class="card">
                <div class="card-title">Last Operation</div>
                <div class="card-value" style="font-size:1.1rem; color:{color};">
                    {status_text}
                </div>
                <div class="small-label">Mode: {st.session_state.last_mode}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown("### Ringkasan")
    st.write(
        """
        Dashboard ini hanya menampilkan statistik ringan di sisi frontend:
        jumlah operasi enkripsi dan dekripsi, algoritma terakhir, dan status operasi terakhir.
        """
    )


# =========================
#  HALAMAN: ENCRYPT / DECRYPT
# =========================
elif menu == "Encrypt / Decrypt":

    top_left, top_right = st.columns([2, 1])

    with top_left:
        st.markdown('<div class="section-title">Pengaturan</div>', unsafe_allow_html=True)

        algo = st.selectbox(
            "Algoritma AES",
            ["AES Standard (S-BOX standar)", "AES SBOX44 (modifikasi)"],
        )

        mode = st.segmented_control(
            "Mode Operasi",
            options=["Enkripsi", "Dekripsi"],
            default="Enkripsi",
        )

        key = st.text_input(
            "Key (16 karakter / 128-bit)",
            type="password",
            help="Key harus tepat 16 karakter untuk AES-128.",
            max_chars=64,
        )

    with top_right:
        st.markdown('<div class="section-title">Petunjuk Singkat</div>', unsafe_allow_html=True)
        if mode == "Enkripsi":
            st.markdown(
                """
                <div class="section-sub">
                • Input berupa plaintext biasa.<br>
                • Output berupa string hex.<br>
                • Simpan ciphertext hex jika ingin didekripsi kembali.
                </div>
                """,
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                """
                <div class="section-sub">
                • Input berupa ciphertext dalam format hex.<br>
                • Tidak boleh ada spasi.<br>
                • Panjang byte ciphertext harus kelipatan 16.
                </div>
                """,
                unsafe_allow_html=True,
            )

    st.markdown('<div class="section-title">Input Data</div>', unsafe_allow_html=True)

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

    col_btn, _ = st.columns([1, 3])
    with col_btn:
        proses = st.button("Proses", use_container_width=True)

    st.markdown('<div class="section-title">Output</div>', unsafe_allow_html=True)

    if proses:
        if not user_text.strip():
            st.warning("Input kosong.")
        elif not key:
            st.warning("Key kosong.")
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
                    st.success("Enkripsi selesai.")
                    st.code(result, language="text")
                else:
                    st.success("Dekripsi selesai.")
                    st.code(result, language="text")

            except Exception as e:
                st.session_state.last_mode = mode
                st.session_state.last_success = False
                st.error(f"Error: {e}")


# =========================
#  HALAMAN: AVALANCHE + KEY SENSITIVITY
# =========================
elif menu == "Avalanche Analysis":
    st.markdown('<div class="section-title">Avalanche dan Key Sensitivity</div>', unsafe_allow_html=True)
    st.markdown(
        """
        <div class="section-sub">
        Analisis ini menggunakan implementasi avalanche dan key sensitivity di <code>aes_backend.py</code>.
        Avalanche: flip 1 bit pada plaintext.<br>
        Key sensitivity: flip 1 bit pada key.<br>
        Ideal: sekitar 50 persen bit ciphertext berubah.
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab1, tab2 = st.tabs(["Avalanche (ubah plaintext)", "Key Sensitivity (ubah key)"])

    # ------------- TAB 1: AVALANCHE -------------
    with tab1:
        col_left, col_right = st.columns([2, 3])

        with col_left:
            st.markdown('<div class="section-title">Parameter</div>', unsafe_allow_html=True)

            plaintext_av = st.text_input(
                "Plaintext",
                placeholder="Contoh: Kriptografi melindungi pesan rahasia",
                key="av_plain",
            )

            key_av = st.text_input(
                "Key (16 karakter)",
                max_chars=64,
                type="password",
                key="av_key",
            )

            st.markdown(
                """
                <div class="section-sub">
                Sistem akan mem-flip 1 bit pada byte pertama plaintext, lalu
                membandingkan ciphertext awal vs ciphertext termodifikasi untuk AES standar dan SBOX44.
                </div>
                """,
                unsafe_allow_html=True,
            )

            run_av = st.button("Hitung Avalanche", use_container_width=True)

        with col_right:
            st.markdown('<div class="section-title">Hasil</div>', unsafe_allow_html=True)

            if run_av:
                if not plaintext_av:
                    st.warning("Plaintext kosong.")
                elif not key_av:
                    st.warning("Key kosong.")
                else:
                    try:
                        res = avalanche_plaintext(plaintext_av, key_av)

                        df_av = pd.DataFrame({
                            "Algoritma": ["AES Standard", "AES SBOX44"],
                            "Changed bits": [
                                res["std"]["changed_bits"],
                                res["sbox44"]["changed_bits"],
                            ],
                            "Total bits": [
                                res["std"]["total_bits"],
                                res["sbox44"]["total_bits"],
                            ],
                            "Persentase (%)": [
                                round(res["std"]["percent"], 2),
                                round(res["sbox44"]["percent"], 2),
                            ],
                        })

                        st.dataframe(df_av, use_container_width=True)

                        avg_pct = (
                            res["std"]["percent"] + res["sbox44"]["percent"]
                        ) / 2.0

                        st.markdown("Rata-rata perubahan dua algoritma: "
                                    f"**{avg_pct:.2f} persen**.")

                        with st.expander("Detail plaintext (hex)"):
                            st.write(f"Plaintext original  : {res['plaintext'].encode('utf-8').hex()}")
                            st.write("Key: digunakan sesuai input; flip dilakukan pada plaintext, bukan key.")

                    except Exception as e:
                        st.error(f"Error perhitungan avalanche: {e}")

    # ------------- TAB 2: KEY SENSITIVITY -------------
    with tab2:
        col_left2, col_right2 = st.columns([2, 3])

        with col_left2:
            st.markdown('<div class="section-title">Parameter</div>', unsafe_allow_html=True)

            plaintext_ks = st.text_input(
                "Plaintext",
                placeholder="Contoh: Kriptografi melindungi pesan rahasia",
                key="ks_plain",
            )

            key_ks = st.text_input(
                "Key (16 karakter)",
                max_chars=64,
                type="password",
                key="ks_key",
            )

            st.markdown(
                """
                <div class="section-sub">
                Sistem akan mem-flip 1 bit pada byte pertama key, lalu
                membandingkan ciphertext awal vs ciphertext dengan key termodifikasi.
                </div>
                """,
                unsafe_allow_html=True,
            )

            run_ks = st.button("Hitung Key Sensitivity", use_container_width=True)

        with col_right2:
            st.markdown('<div class="section-title">Hasil</div>', unsafe_allow_html=True)

            if run_ks:
                if not plaintext_ks:
                    st.warning("Plaintext kosong.")
                elif not key_ks:
                    st.warning("Key kosong.")
                else:
                    try:
                        res = key_sensitivity(plaintext_ks, key_ks)

                        df_ks = pd.DataFrame({
                            "Algoritma": ["AES Standard", "AES SBOX44"],
                            "Changed bits": [
                                res["std"]["changed_bits"],
                                res["sbox44"]["changed_bits"],
                            ],
                            "Total bits": [
                                res["std"]["total_bits"],
                                res["sbox44"]["total_bits"],
                            ],
                            "Persentase (%)": [
                                round(res["std"]["percent"], 2),
                                round(res["sbox44"]["percent"], 2),
                            ],
                        })

                        st.dataframe(df_ks, use_container_width=True)

                        avg_pct = (
                            res["std"]["percent"] + res["sbox44"]["percent"]
                        ) / 2.0

                        st.markdown("Rata-rata perubahan dua algoritma: "
                                    f"**{avg_pct:.2f} persen**.")

                        with st.expander("Detail key (hex)"):
                            st.write(f"Key original : {res['key_original_hex']}")
                            st.write(f"Key modified : {res['key_modified_hex']}")

                    except Exception as e:
                        st.error(f"Error perhitungan key sensitivity: {e}")


# =========================
#  HALAMAN: INFO
# =========================
else:
    st.markdown('<div class="section-title">Tentang Aplikasi</div>', unsafe_allow_html=True)
    st.write(
        """
        Komponen utama:
        • Implementasi AES-128 standar dan AES dengan SBOX44 di file aes_backend.py.
        • Fungsi enkripsi dan dekripsi string untuk dua varian tersebut.
        • Fungsi avalanche_plaintext dan key_sensitivity untuk analisis difusi dan sensitivitas kunci.

        Halaman aplikasi:
        • Dashboard: metrik ringan aktivitas enkripsi/dekripsi.
        • Encrypt / Decrypt: antarmuka utama untuk operasi ECB berbasis string.
        • Avalanche Analysis: analisis perubahan 1 bit pada plaintext dan key untuk kedua algoritma.
        """
    )
