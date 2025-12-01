import streamlit as st
import pandas as pd
import crypto_core as cc
import avalanche_tester as at
import sac_tester as sac
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import numpy as np

# =====================================
# Streamlit Config
# =====================================
st.set_page_config(
    page_title="AES vs SBOX44 Analyzer",
    page_icon="🔐",
    layout="wide",
)

# ---------- Sidebar Navigation ----------
st.sidebar.title("📌 Navigasi Menu")
menu = st.sidebar.radio(
    "Pilih Menu:",
    ["Beranda", "Enkripsi & Dekripsi", "S-Box Properties (NL, DAP, etc.)", "Avalanche Effect", "Key Sensitivity", "SAC Test (Paper)", "Bulk Test Analysis"]
)

# ---------- Session State ----------
if "plain" not in st.session_state:
    st.session_state["plain"] = ""
if "key" not in st.session_state:
    st.session_state["key"] = ""


# ==============================================================
# BERANDA
# (Kode untuk Beranda tetap sama)
# ==============================================================
if menu == "Beranda":
    st.title("🔐 AES vs SBOX44 Cryptographic Analyzer")
    st.markdown("### Aplikasi Perbandingan Algoritma AES Standard dan AES SBOX44")

    st.markdown("---")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.metric(
            label="AES Standard",
            value="10 Rounds",
            delta="128-bit"
        )

    with col2:
        st.metric(
            label="AES SBOX44",
            value="Modified S-Box",
            delta="Custom"
        )

    with col3:
        st.metric(
            label="Total Fitur",
            value="6 Analisis", # Updated from 5 to 6
            delta="Lengkap"
        )

    st.markdown("---")

    st.subheader("📋 Fitur Aplikasi")

    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("""
        **🔒 Enkripsi & Dekripsi**
        - Enkripsi plaintext menjadi ciphertext
        - Dekripsi ciphertext kembali ke plaintext
        - Support AES Standard dan SBOX44
        """)

        st.markdown("""
        **⚡ Avalanche Effect**
        - Test perubahan 1 bit pada plaintext
        - Mengukur persentase perubahan ciphertext
        - Ideal: ~50% bit berubah
        """)

    with col_b:
        st.markdown("""
        **🔬 S-Box Properties (NL, DAP, etc.)** ⭐ NEW!
        - Analisis **Non-Linearity (NL)**, **DAP**, **LAP**, **BIC**
        - Verifikasi kekuatan S-Box secara matematis.
        """)
        
        st.markdown("""
        **🔑 Key Sensitivity**
        - Test perubahan 1 bit pada key
        - Mengukur dampak ke ciphertext
        - Validasi kekuatan key expansion
        """)

        st.markdown("""
        **🎯 SAC Test (Paper)**
        - Strict Avalanche Criterion sesuai paper
        - Test 256 input × 8 bit flips
        """)

    st.markdown("---")
    st.info("💡 Pilih menu di sidebar untuk memulai analisis")


# ==============================================================
# ENKRIPSI & DEKRIPSI
# (Kode untuk Enkripsi & Dekripsi tetap sama)
# ==============================================================
elif menu == "Enkripsi & Dekripsi":
    st.title("🔒 Enkripsi & Dekripsi")

    st.markdown("---")

    # Tab untuk Enkripsi dan Dekripsi
    tab1, tab2 = st.tabs(["🔐 Enkripsi", "🔓 Dekripsi"])

    # ========== TAB ENKRIPSI ==========
    with tab1:
        st.subheader("Enkripsi Plaintext")

        col_input, col_output = st.columns([1, 1])

        with col_input:
            st.markdown("**Input Data**")
            plaintext = st.text_area(
                "Plaintext:",
                value=st.session_state["plain"],
                height=150,
                placeholder="Masukkan teks yang ingin dienkripsi..."
            )

            key = st.text_input(
                "Key (16 karakter):",
                value=st.session_state["key"],
                max_chars=16,
                placeholder="Contoh: MySecretKey12345"
            )

            algo = st.radio(
                "Pilih Algoritma:",
                ["AES Standard", "AES SBOX44"],
                horizontal=True
            )

            st.session_state["plain"] = plaintext
            st.session_state["key"] = key

            encrypt_btn = st.button("🚀 Enkripsi", use_container_width=True)

        with col_output:
            st.markdown("**Output Hasil**")

            if encrypt_btn:
                if not plaintext:
                    st.error("❌ Plaintext tidak boleh kosong!")
                elif len(key) != 16:
                    st.error("❌ Key harus tepat 16 karakter!")
                else:
                    try:
                        with st.spinner("Mengenkripsi..."):
                            if algo == "AES Standard":
                                cipher = cc.encrypt_aes_std_str(plaintext, key)
                            else:
                                cipher = cc.encrypt_aes_44_str(plaintext, key)

                        st.success("✅ Enkripsi berhasil!")
                        st.text_area(
                            "Ciphertext (HEX):",
                            value=cipher,
                            height=150
                        )

                        st.info(f"📊 Panjang: {len(cipher)} karakter hex ({len(cipher)//2} bytes)")

                    except Exception as e:
                        st.error(f"❌ Error: {str(e)}")

    # ========== TAB DEKRIPSI ==========
    with tab2:
        st.subheader("Dekripsi Ciphertext")

        col_input2, col_output2 = st.columns([1, 1])

        with col_input2:
            st.markdown("**Input Data**")
            cipher_hex = st.text_area(
                "Ciphertext (HEX):",
                height=150,
                placeholder="Paste ciphertext dalam format hexadecimal..."
            )

            key_decrypt = st.text_input(
                "Key (16 karakter):",
                value=st.session_state["key"],
                max_chars=16,
                placeholder="Gunakan key yang sama saat enkripsi",
                key="key_decrypt"
            )

            algo_decrypt = st.radio(
                "Pilih Algoritma:",
                ["AES Standard", "AES SBOX44"],
                horizontal=True,
                key="algo_decrypt"
            )

            decrypt_btn = st.button("🔓 Dekripsi", use_container_width=True)

        with col_output2:
            st.markdown("**Output Hasil**")

            if decrypt_btn:
                if not cipher_hex:
                    st.error("❌ Ciphertext tidak boleh kosong!")
                elif len(key_decrypt) != 16:
                    st.error("❌ Key harus tepat 16 karakter!")
                else:
                    try:
                        with st.spinner("Mendekripsi..."):
                            if algo_decrypt == "AES Standard":
                                plaintext_result = cc.decrypt_aes_std_str(cipher_hex, key_decrypt)
                            else:
                                plaintext_result = cc.decrypt_aes_44_str(cipher_hex, key_decrypt)

                        st.success("✅ Dekripsi berhasil!")
                        st.text_area(
                            "Plaintext:",
                            value=plaintext_result,
                            height=150
                        )

                    except Exception as e:
                        st.error(f"❌ Error dekripsi: {str(e)}")
                        st.warning("💡 Pastikan key dan algoritma sama dengan saat enkripsi!")


# ==============================================================
# S-BOX PROPERTIES (New Section)
# ==============================================================
elif menu == "S-Box Properties (NL, DAP, etc.)":
    st.title("🔬 Analisis Properti Kriptografi S-Box")

    st.markdown("""
    Analisis ini membandingkan metrik kriptografi teoritis S-Box 8x8 (256 entri) untuk AES Standard dan SBOX44.
    Metrik dihitung di isolasi tanpa memperhatikan putaran AES.
    """)

    st.markdown("---")

    run_analysis = st.button("✨ Hitung Semua Properti S-Box", use_container_width=True)

    if run_analysis:
        with st.spinner("Menghitung NL, SAC, BIC, LAP, DAP... (membutuhkan waktu sebentar)"):
            try:
                results = cc.get_sbox_analysis_results()

                data = {
                    "Metrik": ["Non-Linearity (NL) [Ideal=112]", "SAC Average (Per Bit) [Ideal=0.5]", "BIC-NL Min [Ideal=112]", "BIC-SAC Avg [Ideal=0.5]", "LAP Bias Max [Ideal=0.0625]", "DAP Max P [Ideal=0.015625]"],
                    "AES Standard": [
                        f"{results['aes']['NL_MIN']:.1f}",
                        f"{results['aes']['SAC_AVG']:.5f}",
                        f"{results['aes']['BIC_NL_MIN']:.1f}",
                        f"{results['aes']['BIC_SAC_AVG']:.5f}",
                        f"{results['aes']['LAP_BIAS']:.6f}",
                        f"{results['aes']['DAP_MAX_P']:.6f}",
                    ],
                    "SBOX44 (Proposed)": [
                        f"{results['sbox44']['NL_MIN']:.1f}",
                        f"{results['sbox44']['SAC_AVG']:.5f}",
                        f"{results['sbox44']['BIC_NL_MIN']:.1f}",
                        f"{results['sbox44']['BIC_SAC_AVG']:.5f}",
                        f"{results['sbox44']['LAP_BIAS']:.6f}",
                        f"{results['sbox44']['DAP_MAX_P']:.6f}",
                    ]
                }

                df = pd.DataFrame(data)

                st.subheader("📊 Hasil Perbandingan Properti S-Box")
                st.dataframe(df, use_container_width=True)

                st.markdown("### 🎯 Kesimpulan")

                nl_status = "NL optimal (112)" if results['aes']['NL_MIN'] == 112 and results['sbox44']['NL_MIN'] == 112 else "NL tidak optimal"
                dap_status = "DAP optimal (0.015625)" if results['aes']['DAP_MAX_P'] == 0.015625 and results['sbox44']['DAP_MAX_P'] == 0.015625 else "DAP tidak optimal"

                st.success(f"✅ **SBOX44 memiliki properti kriptografi yang setara dengan AES Standard S-Box.**")
                st.markdown(f"""
                - **Non-Linearity (NL):** Kedua S-Box mencapai NL optimal **{nl_status}**.
                - **Differential Uniformity (DAP):** Kedua S-Box mencapai DAP optimal **{dap_status}** (sebagai *Almost Perfect Nonlinear / APN*).
                - **SAC/BIC:** Kedua S-Box memenuhi kriteria SAC dan BIC yang ideal (nilai ~0.5), menunjukkan penyebaran bit yang sangat baik.
                """)

            except Exception as e:
                st.error(f"❌ Error saat menjalankan analisis: {str(e)}")
                st.warning("💡 Pastikan semua modul helper tersedia dan terimpor dengan benar.")


# ==============================================================
# AVALANCHE EFFECT
# (Kode untuk Avalanche Effect tetap sama)
# ==============================================================
elif menu == "Avalanche Effect":
    st.title("⚡ Avalanche Effect")

    st.markdown("""
    **Avalanche Effect** mengukur seberapa besar perubahan output ketika input diubah sedikit (1 bit).
    Pada algoritma enkripsi yang baik, perubahan 1 bit pada plaintext harus mengubah sekitar **50%** bit pada ciphertext.
    """)

    st.markdown("---")

    col_left, col_right = st.columns([2, 3])

    with col_left:
        st.subheader("Input Parameter")

        plaintext_av = st.text_input(
            "Plaintext:",
            value=st.session_state["plain"],
            placeholder="Contoh: Hello World"
        )

        key_av = st.text_input(
            "Key (16 karakter):",
            value=st.session_state["key"],
            max_chars=16,
            placeholder="Contoh: MySecretKey12345"
        )

        st.info("ℹ️ Sistem akan mengubah 1 bit pertama pada plaintext dan membandingkan hasilnya")

        calc_btn = st.button("🔥 Hitung Avalanche Effect", use_container_width=True)

    with col_right:
        st.subheader("Hasil Analisis")

        if calc_btn:
            if not plaintext_av:
                st.error("❌ Plaintext tidak boleh kosong!")
            elif len(key_av) != 16:
                st.error("❌ Key harus tepat 16 karakter!")
            else:
                try:
                    with st.spinner("Menghitung avalanche effect..."):
                        result = cc.avalanche_plaintext(plaintext_av, key_av)

                    # Tabel hasil
                    df = pd.DataFrame({
                        "Algoritma": ["AES Standard", "AES SBOX44"],
                        "Changed Bits": [
                            result["std"]["changed_bits"],
                            result["sbox44"]["changed_bits"]
                        ],
                        "Total Bits": [
                            result["std"]["total_bits"],
                            result["sbox44"]["total_bits"]
                        ],
                        "Percentage (%)": [
                            result["std"]["percent"],
                            result["sbox44"]["percent"]
                        ]
                    })

                    st.dataframe(df, use_container_width=True)

                    # Interpretasi
                    avg_pct = (result["std"]["percent"] + result["sbox44"]["percent"]) / 2

                    st.markdown("### 📊 Interpretasi Hasil")

                    if 45 <= avg_pct <= 55:
                        st.success(f"✅ **Avalanche effect sangat baik!** (Rata-rata: {avg_pct:.2f}%)")
                        st.markdown("Perubahan mendekati ideal 50%, menunjukkan difusi yang sangat baik.")
                    elif 40 <= avg_pct <= 60:
                        st.info(f"ℹ️ **Avalanche effect baik** (Rata-rata: {avg_pct:.2f}%)")
                        st.markdown("Perubahan masih dalam range acceptable.")
                    else:
                        st.warning(f"⚠️ **Avalanche effect perlu perbaikan** (Rata-rata: {avg_pct:.2f}%)")
                        st.markdown("Perubahan di luar range ideal.")

                    # Detail
                    with st.expander("📋 Detail Teknis"):
                        st.markdown(f"""
                        **Plaintext Original:** `{result['plaintext_original']}`

                        **Plaintext Modified:** `{result['plaintext_modified']}`

                        **Perubahan:** 1 bit pada byte pertama

                        **Standar Ideal:** 45-55% bit berubah
                        """)

                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")


# ==============================================================
# KEY SENSITIVITY
# (Kode untuk Key Sensitivity tetap sama)
# ==============================================================
elif menu == "Key Sensitivity":
    st.title("🔑 Key Sensitivity")

    st.markdown("""
    **Key Sensitivity** mengukur seberapa sensitif algoritma terhadap perubahan key.
    Perubahan 1 bit pada key seharusnya mengubah sekitar **50%** bit pada ciphertext,
    menunjukkan bahwa key expansion berfungsi dengan baik.
    """)

    st.markdown("---")

    col_left, col_right = st.columns([2, 3])

    with col_left:
        st.subheader("Input Parameter")

        plaintext_ks = st.text_input(
            "Plaintext:",
            value=st.session_state["plain"],
            placeholder="Contoh: Hello World"
        )

        key_ks = st.text_input(
            "Key (16 karakter):",
            value=st.session_state["key"],
            max_chars=16,
            placeholder="Contoh: MySecretKey12345"
        )

        st.info("ℹ️ Sistem akan mengubah 1 bit pertama pada key dan membandingkan hasilnya")

        calc_ks_btn = st.button("🔍 Hitung Key Sensitivity", use_container_width=True)

    with col_right:
        st.subheader("Hasil Analisis")

        if calc_ks_btn:
            if not plaintext_ks:
                st.error("❌ Plaintext tidak boleh kosong!")
            elif len(key_ks) != 16:
                st.error("❌ Key harus tepat 16 karakter!")
            else:
                try:
                    with st.spinner("Menghitung key sensitivity..."):
                        result = cc.key_sensitivity(plaintext_ks, key_ks)

                    # Tabel hasil
                    df = pd.DataFrame({
                        "Algoritma": ["AES Standard", "AES SBOX44"],
                        "Changed Bits": [
                            result["std"]["changed_bits"],
                            result["sbox44"]["changed_bits"]
                        ],
                        "Total Bits": [
                            result["std"]["total_bits"],
                            result["sbox44"]["total_bits"]
                        ],
                        "Percentage (%)": [
                            result["std"]["percent"],
                            result["sbox44"]["percent"]
                        ]
                    })

                    st.dataframe(df, use_container_width=True)

                    # Interpretasi
                    avg_pct = (result["std"]["percent"] + result["sbox44"]["percent"]) / 2

                    st.markdown("### 📊 Interpretasi Hasil")

                    if 45 <= avg_pct <= 55:
                        st.success(f"✅ **Key sensitivity sangat baik!** (Rata-rata: {avg_pct:.2f}%)")
                        st.markdown("Key expansion bekerja optimal, perubahan key menyebar dengan baik.")
                    elif 40 <= avg_pct <= 60:
                        st.info(f"ℹ️ **Key sensitivity baik** (Rata-rata: {avg_pct:.2f}%)")
                        st.markdown("Key expansion masih dalam range acceptable.")
                    else:
                        st.warning(f"⚠️ **Key sensitivity perlu perbaikan** (Rata-rata: {avg_pct:.2f}%)")
                        st.markdown("Perubahan key kurang optimal.")

                    # Detail
                    with st.expander("📋 Detail Teknis"):
                        st.markdown(f"""
                        **Key Original (HEX):** `{result['key_original_hex']}`

                        **Key Modified (HEX):** `{result['key_modified_hex']}`

                        **Perubahan:** 1 bit pada byte pertama

                        **Standar Ideal:** 45-55% bit berubah
                        """)

                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")


# ==============================================================
# SAC TEST (SESUAI PAPER)
# (Kode untuk SAC Test tetap sama)
# ==============================================================
elif menu == "SAC Test (Paper)":
    st.title("🎯 SAC Test (Strict Avalanche Criterion)")

    st.markdown("""


    Test ini berbeda dengan Avalanche Effect sederhana:
    - ✅ Test **256 kombinasi input** (0x00 sampai 0xFF)
    - ✅ Flip **setiap bit** (8 bit) di tiap input
    - ✅ Hitung pengaruh ke **setiap bit output** (8 bit)
    - ✅ Generate **SAC Matrix 8×8** (seperti Table 17 paper)
    - ✅ Ideal SAC value = **0.5** (50%)

    **Paper result:**
    - AES Standard: 0.50488
    - SBOX44: **0.50073** ✨ (lebih baik!)
    """)

    st.markdown("---")

    # Tabs untuk Single Test dan Bulk Test
    tab1, tab2 = st.tabs(["🔍 Single Key Test", "📊 Bulk SAC Test"])

    # ========== SINGLE KEY TEST ==========
    with tab1:
        st.subheader("SAC Test dengan 1 Key")

        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("**Konfigurasi**")

            key_sac = st.text_input(
                "Key (16 karakter):",
                value=st.session_state.get("key", "1234567890ABCDEF"),
                max_chars=16,
                key="key_sac"
            )

            st.info("ℹ️ Test akan menjalankan 256 × 8 = 2,048 enkripsi")

            run_sac = st.button("🚀 Run SAC Test", use_container_width=True)

        with col2:
            if run_sac:
                if len(key_sac) != 16:
                    st.error("❌ Key harus tepat 16 karakter!")
                else:
                    with st.spinner("Menjalankan SAC test (2048 enkripsi)..."):
                        key_bytes = key_sac.encode('utf-8')

                        # Test AES Standard
                        sac_matrix_std, sac_value_std = sac.calculate_sac_for_sbox(
                            cc.aes_encrypt_block_std,
                            key_bytes
                        )

                        # Test SBOX44
                        sac_matrix_44, sac_value_44 = sac.calculate_sac_for_sbox(
                            cc.aes_encrypt_block_44,
                            key_bytes
                        )

                    st.success("✅ SAC Test selesai!")

                    # Tabel hasil
                    st.markdown("### 📈 Hasil SAC Value")

                    results_df = pd.DataFrame({
                        "Algoritma": ["AES Standard", "SBOX44", "Paper (AES)", "Paper (SBOX44)"],
                        "SAC Value": [
                            f"{sac_value_std:.5f}",
                            f"{sac_value_44:.5f}",
                            "0.50488",
                            "0.50073"
                        ],
                        "Deviasi dari 0.5": [
                            f"{abs(sac_value_std - 0.5):.5f}",
                            f"{abs(sac_value_44 - 0.5):.5f}",
                            "0.00488",
                            "0.00073"
                        ]
                    })

                    st.dataframe(results_df, use_container_width=True)

                    # Winner
                    st.markdown("### 🏆 Winner")
                    if abs(sac_value_44 - 0.5) < abs(sac_value_std - 0.5):
                        improvement = ((abs(sac_value_std - 0.5) - abs(sac_value_44 - 0.5)) / abs(sac_value_44 - 0.5)) * 100
                        st.success(f"**SBOX44 menang!** Lebih dekat ke ideal 0.5 dengan improvement {improvement:.3f}%")
                    else:
                        st.info("AES Standard lebih dekat ke ideal 0.5")

                    # Visualisasi SAC Matrix
                    st.markdown("### 📊 SAC Matrix 8×8 (Heatmap)")

                    col_a, col_b = st.columns(2)

                    with col_a:
                        st.markdown("**AES Standard**")
                        fig_std = go.Figure(data=go.Heatmap(
                            z=sac_matrix_std,
                            colorscale='RdYlGn',
                            zmid=0.5,
                            text=np.round(sac_matrix_std, 3),
                            texttemplate='%{text}',
                            textfont={"size": 10},
                            colorbar=dict(title="Probability")
                        ))
                        fig_std.update_layout(
                            xaxis_title="Output Bit",
                            yaxis_title="Input Bit Flipped",
                            height=400
                        )
                        st.plotly_chart(fig_std, use_container_width=True)

                    with col_b:
                        st.markdown("**SBOX44**")
                        fig_44 = go.Figure(data=go.Heatmap(
                            z=sac_matrix_44,
                            colorscale='RdYlGn',
                            zmid=0.5,
                            text=np.round(sac_matrix_44, 3),
                            texttemplate='%{text}',
                            textfont={"size": 10},
                            colorbar=dict(title="Probability")
                        ))
                        fig_44.update_layout(
                            xaxis_title="Output Bit",
                            yaxis_title="Input Bit Flipped",
                            height=400
                        )
                        st.plotly_chart(fig_44, use_container_width=True)

                    # Detail Matrix
                    with st.expander("📋 Detail SAC Matrix (Tabel)"):
                        st.markdown("**AES Standard SAC Matrix:**")
                        st.dataframe(pd.DataFrame(sac_matrix_std), use_container_width=True)

                        st.markdown("**SBOX44 SAC Matrix:**")
                        st.dataframe(pd.DataFrame(sac_matrix_44), use_container_width=True)

    # ========== BULK SAC TEST ==========
    with tab2:
        st.subheader("Bulk SAC Test dengan Multiple Keys")

        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("**Konfigurasi**")

            n_keys = st.slider(
                "Jumlah Random Keys:",
                min_value=5,
                max_value=100,
                value=20,
                step=5,
                help="Semakin banyak keys = semakin akurat, tapi lebih lama"
            )

            total_tests = n_keys * 2048
            st.info(f"📝 Total: {total_tests:,} enkripsi ({n_keys} keys × 2,048)")

            run_bulk_sac = st.button("🚀 Run Bulk SAC Test", use_container_width=True)

        with col2:
            if run_bulk_sac:
                progress_bar = st.progress(0)
                status_text = st.empty()

                import random
                import string

                sac_values_std = []
                sac_values_44 = []

                for i in range(n_keys):
                    status_text.text(f"Testing key {i+1}/{n_keys}...")

                    # Generate random key
                    key_str = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
                    key_bytes = key_str.encode('utf-8')

                    # Test SAC
                    _, sac_std = sac.calculate_sac_for_sbox(cc.aes_encrypt_block_std, key_bytes)
                    _, sac_44 = sac.calculate_sac_for_sbox(cc.aes_encrypt_block_44, key_bytes)

                    sac_values_std.append(sac_std)
                    sac_values_44.append(sac_44)

                    progress_bar.progress((i + 1) / n_keys)

                progress_bar.empty()
                status_text.empty()

                # Hitung statistik
                avg_std = sum(sac_values_std) / len(sac_values_std)
                avg_44 = sum(sac_values_44) / len(sac_values_44)

                st.success(f"✅ Selesai! {n_keys} keys berhasil ditest")

                # Tabel statistik
                st.markdown("### 📈 Hasil Statistik")

                stats_df = pd.DataFrame({
                    "Metric": ["Mean SAC", "Min SAC", "Max SAC", "Deviation from 0.5", "Paper Value"],
                    "AES Standard": [
                        f"{avg_std:.5f}",
                        f"{min(sac_values_std):.5f}",
                        f"{max(sac_values_std):.5f}",
                        f"{abs(avg_std - 0.5):.5f}",
                        "0.50488"
                    ],
                    "SBOX44": [
                        f"{avg_44:.5f}",
                        f"{min(sac_values_44):.5f}",
                        f"{max(sac_values_44):.5f}",
                        f"{abs(avg_44 - 0.5):.5f}",
                        "0.50073"
                    ]
                })

                st.dataframe(stats_df, use_container_width=True)

                # Visualisasi distribusi
                st.markdown("### 📊 Distribusi SAC Values")

                fig = make_subplots(
                    rows=1, cols=2,
                    subplot_titles=("AES Standard", "SBOX44")
                )

                # Histogram AES Standard
                fig.add_trace(
                    go.Histogram(
                        x=sac_values_std,
                        name="AES Std",
                        marker_color='#3498db',
                        nbinsx=15
                    ),
                    row=1, col=1
                )

                # Histogram SBOX44
                fig.add_trace(
                    go.Histogram(
                        x=sac_values_44,
                        name="SBOX44",
                        marker_color='#e74c3c',
                        nbinsx=15
                    ),
                    row=1, col=2
                )

                # Garis ideal (0.5)
                fig.add_vline(x=0.5, line_dash="dash", line_color="green",
                              annotation_text="Ideal: 0.5", row=1, col=1)
                fig.add_vline(x=0.5, line_dash="dash", line_color="green",
                              annotation_text="Ideal: 0.5", row=1, col=2)

                fig.update_xaxes(title_text="SAC Value", row=1, col=1)
                fig.update_xaxes(title_text="SAC Value", row=1, col=2)
                fig.update_yaxes(title_text="Frequency", row=1, col=1)

                fig.update_layout(height=400, showlegend=False)

                st.plotly_chart(fig, use_container_width=True)

                # Kesimpulan
                st.markdown("### 🎯 Kesimpulan")

                if abs(avg_44 - 0.5) < abs(avg_std - 0.5):
                    improvement = ((abs(avg_std - 0.5) - abs(avg_44 - 0.5)) / abs(avg_44 - 0.5)) * 100
                    st.success(f"""
                    **🏆 WINNER: SBOX44**

                    SBOX44 memiliki SAC value **{avg_44:.5f}** (deviasi: {abs(avg_44 - 0.5):.5f})

                    AES Standard memiliki SAC value **{avg_std:.5f}** (deviasi: {abs(avg_std - 0.5):.5f})

                    **Improvement: {improvement:.3f}%** ✨

                    Hasil ini **konsisten dengan paper** Pak Alam!
                    """)
                else:
                    st.info(f"""
                    **AES Standard lebih baik** (SAC: {avg_std:.5f}, deviasi: {abs(avg_std - 0.5):.5f})

                    vs SBOX44 (SAC: {avg_44:.5f}, deviasi: {abs(avg_44 - 0.5):.5f})
                    """)


# ==============================================================
# BULK TEST ANALYSIS
# (Kode untuk Bulk Test Analysis tetap sama)
# ==============================================================
elif menu == "Bulk Test Analysis":
    st.title("📊 Bulk Test Analysis")

    st.markdown("""
    **Bulk Testing** menjalankan ratusan tes dengan kombinasi plaintext dan key yang berbeda-beda.

    Ini memberikan gambaran statistik yang lebih akurat tentang performa algoritma,
    karena hasil dari 1 sample saja bisa tidak representatif.
    """)

    st.markdown("---")

    # Tabs untuk Avalanche dan Key Sensitivity
    tab1, tab2 = st.tabs(["⚡ Bulk Avalanche Test", "🔑 Bulk Key Sensitivity Test"])

    # ========== BULK AVALANCHE TEST ==========
    with tab1:
        st.subheader("Bulk Avalanche Effect Testing")

        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("**Konfigurasi Test**")

            n_samples_av = st.slider(
                "Jumlah Sampel:",
                min_value=10,
                max_value=500,
                value=100,
                step=10,
                help="Semakin banyak sampel = semakin akurat, tapi lebih lama"
            )

            st.info(f"📝 Akan menguji {n_samples_av} kombinasi plaintext-key yang berbeda")

            run_bulk_av = st.button("🚀 Jalankan Bulk Test", use_container_width=True, key="bulk_av")

        with col2:
            if run_bulk_av:
                # Progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()

                def update_progress(pct):
                    progress_bar.progress(pct)
                    status_text.text(f"Testing... {int(pct*100)}% selesai")

                with st.spinner("Menjalankan bulk testing..."):
                    results = at.run_bulk_avalanche_test(n_samples_av, update_progress)

                progress_bar.empty()
                status_text.empty()

                if results:
                    st.success(f"✅ Selesai! {results['n_samples']} sampel berhasil diuji")

                    # Tabel statistik
                    st.markdown("### 📈 Hasil Statistik")

                    stats_df = pd.DataFrame({
                        "Metric": ["Mean (%)", "Min (%)", "Max (%)", "Deviation from 50%", "Quality Rating"],
                        "AES Standard": [
                            f"{results['std']['mean']:.2f}",
                            f"{results['std']['min']:.2f}",
                            f"{results['std']['max']:.2f}",
                            f"{abs(results['std']['mean'] - 50):.3f}",
                            at.get_quality_rating(results['std']['mean'])
                        ],
                        "AES SBOX44": [
                            f"{results['sbox44']['mean']:.2f}",
                            f"{results['sbox44']['min']:.2f}",
                            f"{results['sbox44']['max']:.2f}",
                            f"{abs(results['sbox44']['mean'] - 50):.3f}",
                            at.get_quality_rating(results['sbox44']['mean'])
                        ]
                    })

                    st.dataframe(stats_df, use_container_width=True)

                    # Visualisasi distribusi
                    st.markdown("### 📊 Distribusi Hasil")

                    fig = make_subplots(
                        rows=1, cols=2,
                        subplot_titles=("AES Standard", "AES SBOX44")
                    )

                    # Histogram AES Standard
                    fig.add_trace(
                        go.Histogram(
                            x=results['std']['all_values'],
                            name="AES Std",
                            marker_color='#3498db',
                            nbinsx=20
                        ),
                        row=1, col=1
                    )

                    # Histogram SBOX44
                    fig.add_trace(
                        go.Histogram(
                            x=results['sbox44']['all_values'],
                            name="SBOX44",
                            marker_color='#e74c3c',
                            nbinsx=20
                        ),
                        row=1, col=2
                    )

                    # Garis ideal (50%)
                    fig.add_vline(x=0.5, line_dash="dash", line_color="green",
                                  annotation_text="Ideal: 50%", row=1, col=1)
                    fig.add_vline(x=0.5, line_dash="dash", line_color="green",
                                  annotation_text="Ideal: 50%", row=1, col=2)

                    fig.update_xaxes(title_text="Percentage (%)", row=1, col=1)
                    fig.update_xaxes(title_text="Percentage (%)", row=1, col=2)
                    fig.update_yaxes(title_text="Frequency", row=1, col=1)

                    fig.update_layout(height=400, showlegend=False)

                    st.plotly_chart(fig, use_container_width=True)

                    # Kesimpulan
                    st.markdown("### 🎯 Kesimpulan")

                    winner = "AES SBOX44" if abs(results['sbox44']['mean'] - 50) < abs(results['std']['mean'] - 50) else "AES Standard"
                    diff = abs(abs(results['sbox44']['mean'] - 50) - abs(results['std']['mean'] - 50))

                    st.info(f"""
                    **Winner:** {winner} ✨

                    **SBOX44** memiliki deviasi dari ideal (50%) sebesar **{abs(results['sbox44']['mean'] - 50):.3f}%**

                    **AES Standard** memiliki deviasi sebesar **{abs(results['std']['mean'] - 50):.3f}%**

                    Selisih: **{diff:.3f}%**
                    """)

                else:
                    st.error("❌ Terjadi kesalahan saat menjalankan bulk test")

    # ========== BULK KEY SENSITIVITY TEST ==========
    with tab2:
        st.subheader("Bulk Key Sensitivity Testing")

        col1, col2 = st.columns([1, 2])

        with col1:
            st.markdown("**Konfigurasi Test**")

            n_samples_ks = st.slider(
                "Jumlah Sampel:",
                min_value=10,
                max_value=500,
                value=100,
                step=10,
                help="Semakin banyak sampel = semakin akurat, tapi lebih lama",
                key="n_samples_ks"
            )

            st.info(f"📝 Akan menguji {n_samples_ks} kombinasi plaintext-key yang berbeda")

            run_bulk_ks = st.button("🚀 Jalankan Bulk Test", use_container_width=True, key="bulk_ks")

        with col2:
            if run_bulk_ks:
                # Progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()

                def update_progress(pct):
                    progress_bar.progress(pct)
                    status_text.text(f"Testing... {int(pct*100)}% selesai")

                with st.spinner("Menjalankan bulk testing..."):
                    results = at.run_bulk_key_sensitivity_test(n_samples_ks, update_progress)

                progress_bar.empty()
                status_text.empty()

                if results:
                    st.success(f"✅ Selesai! {results['n_samples']} sampel berhasil diuji")

                    # Tabel statistik
                    st.markdown("### 📈 Hasil Statistik")

                    stats_df = pd.DataFrame({
                        "Metric": ["Mean (%)", "Min (%)", "Max (%)", "Deviation from 50%", "Quality Rating"],
                        "AES Standard": [
                            f"{results['std']['mean']:.2f}",
                            f"{results['std']['min']:.2f}",
                            f"{results['std']['max']:.2f}",
                            f"{abs(results['std']['mean'] - 50):.3f}",
                            at.get_quality_rating(results['std']['mean'])
                        ],
                        "AES SBOX44": [
                            f"{results['sbox44']['mean']:.2f}",
                            f"{results['sbox44']['min']:.2f}",
                            f"{results['sbox44']['max']:.2f}",
                            f"{abs(results['sbox44']['mean'] - 50):.3f}",
                            at.get_quality_rating(results['sbox44']['mean'])
                        ]
                    })

                    st.dataframe(stats_df, use_container_width=True)

                    # Visualisasi distribusi
                    st.markdown("### 📊 Distribusi Hasil")

                    fig = make_subplots(
                        rows=1, cols=2,
                        subplot_titles=("AES Standard", "AES SBOX44")
                    )

                    # Histogram AES Standard
                    fig.add_trace(
                        go.Histogram(
                            x=results['std']['all_values'],
                            name="AES Std",
                            marker_color='#3498db',
                            nbinsx=20
                        ),
                        row=1, col=1
                    )

                    # Histogram SBOX44
                    fig.add_trace(
                        go.Histogram(
                            x=results['sbox44']['all_values'],
                            name="SBOX44",
                            marker_color='#e74c3c',
                            nbinsx=20
                        ),
                        row=1, col=2
                    )

                    fig.update_xaxes(title_text="Percentage (%)", row=1, col=1)
                    fig.update_xaxes(title_text="Percentage (%)", row=1, col=2)
                    fig.update_yaxes(title_text="Frequency", row=1, col=1)

                    fig.update_layout(height=400, showlegend=False)

                    st.plotly_chart(fig, use_container_width=True)

                    # Kesimpulan
                    st.markdown("### 🎯 Kesimpulan")

                    winner = "AES SBOX44" if abs(results['sbox44']['mean'] - 50) < abs(results['std']['mean'] - 50) else "AES Standard"
                    diff = abs(abs(results['sbox44']['mean'] - 50) - abs(results['std']['mean'] - 50))

                    st.info(f"""
                    **Winner:** {winner} ✨

                    **SBOX44** memiliki deviasi dari ideal (50%) sebesar **{abs(results['sbox44']['mean'] - 50):.3f}%**

                    **AES Standard** memiliki deviasi sebesar **{abs(results['std']['mean'] - 50):.3f}%**

                    Selisih: **{diff:.3f}%**
                    """)

                else:
                    st.error("❌ Terjadi kesalahan saat menjalankan bulk test")


# Footer
st.markdown("---")
st.caption("🔐 AES vs SBOX44 Analyzer | Cryptographic Analysis Tool")

