# app.py
import streamlit as st
import textwrap

import kelompok_idub_projek_kripto as kripto  # impor file kamu

# =========================
# Styling dasar + "card"
# =========================
CARD_CSS = """
<style>
    .main {
        background-color: #f5f7fb;
    }
    .card {
        background-color: #ffffff;
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        box-shadow: 0 2px 10px rgba(15, 23, 42, 0.06);
        border: 1px solid rgba(148, 163, 184, 0.3);
        margin-bottom: 1.5rem;
    }
    .card-title {
        font-size: 1.05rem;
        font-weight: 600;
        margin-bottom: 0.35rem;
    }
    .card-subtitle {
        font-size: 0.85rem;
        color: #6b7280;
        margin-bottom: 0.8rem;
    }
    .pill {
        display: inline-flex;
        align-items: center;
        padding: 0.10rem 0.55rem;
        border-radius: 999px;
        font-size: 0.70rem;
        font-weight: 500;
        background: #eef2ff;
        color: #3730a3;
        margin-right: 0.35rem;
    }
    .metric-row {
        display: flex;
        gap: 0.75rem;
        flex-wrap: wrap;
        margin-top: 0.75rem;
    }
    .metric-pill {
        flex: 1 1 140px;
        border-radius: 999px;
        padding: 0.35rem 0.75rem;
        background: #f3f4f6;
        font-size: 0.8rem;
        display: flex;
        justify-content: space-between;
        align-items: center;
    }
    .metric-label {
        color: #6b7280;
    }
    .metric-value {
        font-weight: 600;
        color: #111827;
    }
</style>
"""

st.set_page_config(
    page_title="AES vs SBOX44 Crypto Demo",
    page_icon="🔐",
    layout="wide",
)

st.markdown(CARD_CSS, unsafe_allow_html=True)

# =========================
# Header
# =========================
st.markdown(
    """
    <div style="margin-bottom: 1rem;">
        <h2 style="margin-bottom: 0.25rem;">AES & SBOX44 Demo</h2>
        <p style="color:#6b7280; font-size:0.9rem; margin-bottom:0.5rem;">
            UI untuk eksperimen enkripsi, avalanche effect, dan key sensitivity dari AES standar dan varian SBOX44.
        </p>
    </div>
    """,
    unsafe_allow_html=True,
)

tab_enkripsi, tab_avalanche = st.tabs(["🔑 Enkripsi / Dekripsi", "🌊 Avalanche & Key Sensitivity"])

# ======================================================
# TAB 1 — ENKRIPSI / DEKRIPSI
# ======================================================
with tab_enkripsi:
    col1, col2 = st.columns(2)

    # ------------- Kartu input plaintext / key -------------
    with col1:
        st.markdown('<div class="card">', unsafe_allow_html=True)

        st.markdown('<div class="card-title">Input Pesan & Kunci</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="card-subtitle">Gunakan key 16 karakter (128-bit). Mode ECB, hanya untuk demo / riset.</div>',
            unsafe_allow_html=True,
        )

        default_plain = "Kriptografi melindungi pesan rahasia"
        plaintext = st.text_area(
            "Plaintext",
            value=default_plain,
            height=120,
            key="enc_plaintext",
        )

        key_str = st.text_input(
            "Key (16 karakter)",
            value="1234567890ABCDEF",
            max_chars=16,
            key="enc_key",
        )

        col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])

        with col_btn1:
            enc_std = st.button("Encrypt AES Std", key="btn_enc_std")
        with col_btn2:
            enc_44 = st.button("Encrypt SBOX44", key="btn_enc_44")
        with col_btn3:
            dec_btn = st.button("Decrypt (teks di bawah)", key="btn_dec")

        st.markdown("</div>", unsafe_allow_html=True)

    # ------------- Kartu hasil cipher -------------
    with col2:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Ciphertext & Hasil Dekripsi</div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="card-subtitle">Teks dienkripsi menjadi hex string. Dekripsi akan mengembalikan plaintext.</div>',
            unsafe_allow_html=True,
        )

        cipher_std = st.text_area(
            "Cipher AES Standar (hex)",
            value="",
            height=120,
            key="cipher_std",
        )
        cipher_44 = st.text_area(
            "Cipher AES SBOX44 (hex)",
            value="",
            height=120,
            key="cipher_44",
        )

        decrypted_output = st.text_area(
            "Plaintext dari dekripsi",
            value="",
            height=120,
            key="dec_plaintext_out",
        )

        st.markdown("</div>", unsafe_allow_html=True)

    # ------------- Logika proses enkripsi/dekripsi -------------
    # simpan di session_state supaya tombol bisa update isi field
    if "cipher_std_val" not in st.session_state:
        st.session_state["cipher_std_val"] = ""
    if "cipher_44_val" not in st.session_state:
        st.session_state["cipher_44_val"] = ""
    if "dec_plain_val" not in st.session_state:
        st.session_state["dec_plain_val"] = ""

    # validasi key
    def _validate_key(k: str):
        if len(k.encode("utf-8")) != 16:
            st.error("Key harus tepat 16 byte (16 karakter sederhana).")
            return False
        return True

    # ENCRYPT AES STD
    if enc_std:
        if _validate_key(key_str):
            try:
                ct = kripto.encrypt_aes_std_str(plaintext, key_str)
                st.session_state["cipher_std_val"] = ct
                st.session_state["cipher_44_val"] = st.session_state.get("cipher_44_val", "")
                st.session_state["dec_plain_val"] = ""
            except Exception as e:
                st.error(f"Enkripsi AES Std gagal: {e}")

    # ENCRYPT SBOX44
    if enc_44:
        if _validate_key(key_str):
            try:
                ct = kripto.encrypt_aes_44_str(plaintext, key_str)
                st.session_state["cipher_44_val"] = ct
                st.session_state["cipher_std_val"] = st.session_state.get("cipher_std_val", "")
                st.session_state["dec_plain_val"] = ""
            except Exception as e:
                st.error(f"Enkripsi SBOX44 gagal: {e}")

    # DECRYPT (prioritas: jika isian cipher_std ada → pakai AES Std, kalau tidak → pakai SBOX44)
    if dec_btn:
        if _validate_key(key_str):
            try:
                src_std = st.session_state.get("cipher_std_val") or cipher_std.strip()
                src_44 = st.session_state.get("cipher_44_val") or cipher_44.strip()

                if src_std:
                    plain = kripto.decrypt_aes_std_str(src_std, key_str)
                    st.session_state["dec_plain_val"] = plain
                elif src_44:
                    plain = kripto.decrypt_aes_44_str(src_44, key_str)
                    st.session_state["dec_plain_val"] = plain
                else:
                    st.warning("Isi salah satu ciphertext (AES Std atau SBOX44) sebelum dekripsi.")
            except Exception as e:
                st.error(f"Dekripsi gagal: {e}")

    # Sinkronisasi dengan widget teks
    st.session_state["cipher_std"] = st.session_state.get("cipher_std_val", "")
    st.session_state["cipher_44"] = st.session_state.get("cipher_44_val", "")
    st.session_state["dec_plaintext_out"] = st.session_state.get("dec_plain_val", "")


# ======================================================
# TAB 2 — AVALANCHE & KEY SENSITIVITY
# ======================================================
with tab_avalanche:
    col_left, col_right = st.columns(2)

    # ---------- Avalanche Plaintext Card ----------
    with col_left:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Avalanche Effect (flip 1 bit plaintext)</div>', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="card-subtitle">
            Satu bit pada plaintext di-flip, lalu dihitung seberapa banyak bit ciphertext berubah
            pada AES standar vs SBOX44.
            </div>
            """,
            unsafe_allow_html=True,
        )

        plain_av = st.text_area(
            "Plaintext (untuk uji avalanche)",
            value="Kriptografi melindungi pesan rahasia",
            height=120,
            key="av_plain",
        )
        key_av = st.text_input(
            "Key (16 karakter, avalanche)",
            value="1234567890ABCDEF",
            max_chars=16,
            key="av_key",
        )

        btn_run_av = st.button("Hitung Avalanche Effect", key="btn_run_av")

        if btn_run_av:
            if len(key_av.encode("utf-8")) != 16:
                st.error("Key avalanche harus 16 byte.")
            elif len(plain_av.encode("utf-8")) == 0:
                st.error("Plaintext tidak boleh kosong.")
            else:
                try:
                    res_av = kripto.avalanche_plaintext(plain_av, key_av)
                    std_p = res_av["std"]["percent"]
                    std_chg = res_av["std"]["changed_bits"]
                    std_tot = res_av["std"]["total_bits"]

                    s44_p = res_av["sbox44"]["percent"]
                    s44_chg = res_av["sbox44"]["changed_bits"]
                    s44_tot = res_av["sbox44"]["total_bits"]

                    st.markdown(
                        f"""
                        <div class="metric-row">
                            <div class="metric-pill">
                                <span class="metric-label">AES Std</span>
                                <span class="metric-value">{std_p:.2f}%  ({std_chg}/{std_tot} bit)</span>
                            </div>
                            <div class="metric-pill">
                                <span class="metric-label">SBOX44</span>
                                <span class="metric-value">{s44_p:.2f}%  ({s44_chg}/{s44_tot} bit)</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    with st.expander("Detail ciphertext (block pertama)", expanded=False):
                        st.code(
                            textwrap.dedent(
                                f"""
                                AES Std:
                                  CT1: {res_av["std"]["ct1"]}
                                  CT2: {res_av["std"]["ct2"]}

                                SBOX44:
                                  CT1: {res_av["sbox44"]["ct1"]}
                                  CT2: {res_av["sbox44"]["ct2"]}
                                """
                            ).strip(),
                            language="text",
                        )
                except Exception as e:
                    st.error(f"Perhitungan avalanche gagal: {e}")

        st.markdown("</div>", unsafe_allow_html=True)

    # ---------- Key Sensitivity Card ----------
    with col_right:
        st.markdown('<div class="card">', unsafe_allow_html=True)
        st.markdown('<div class="card-title">Key Sensitivity (flip 1 bit key)</div>', unsafe_allow_html=True)
        st.markdown(
            """
            <div class="card-subtitle">
            Satu bit pada key di-flip, lalu dihitung perubahan bit ciphertext untuk AES standar dan SBOX44.
            </div>
            """,
            unsafe_allow_html=True,
        )

        plain_key = st.text_area(
            "Plaintext (untuk uji key sensitivity)",
            value="Kriptografi melindungi pesan rahasia",
            height=120,
            key="ks_plain",
        )
        key_ks = st.text_input(
            "Key (16 karakter, sebelum flip)",
            value="1234567890ABCDEF",
            max_chars=16,
            key="ks_key",
        )

        btn_run_ks = st.button("Hitung Key Sensitivity", key="btn_run_ks")

        if btn_run_ks:
            if len(key_ks.encode("utf-8")) != 16:
                st.error("Key harus 16 byte.")
            elif len(plain_key.encode("utf-8")) == 0:
                st.error("Plaintext tidak boleh kosong.")
            else:
                try:
                    res_ks = kripto.key_sensitivity(plain_key, key_ks)

                    std_p = res_ks["std"]["percent"]
                    std_chg = res_ks["std"]["changed_bits"]
                    std_tot = res_ks["std"]["total_bits"]

                    s44_p = res_ks["sbox44"]["percent"]
                    s44_chg = res_ks["sbox44"]["changed_bits"]
                    s44_tot = res_ks["sbox44"]["total_bits"]

                    st.markdown(
                        """
                        <div class="pill">Key di-flip 1 bit pada byte pertama</div>
                        """,
                        unsafe_allow_html=True,
                    )

                    st.markdown(
                        f"""
                        <div class="metric-row">
                            <div class="metric-pill">
                                <span class="metric-label">AES Std</span>
                                <span class="metric-value">{std_p:.2f}%  ({std_chg}/{std_tot} bit)</span>
                            </div>
                            <div class="metric-pill">
                                <span class="metric-label">SBOX44</span>
                                <span class="metric-value">{s44_p:.2f}%  ({s44_chg}/{s44_tot} bit)</span>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    with st.expander("Detail key & ciphertext", expanded=False):
                        st.code(
                            textwrap.dedent(
                                f"""
                                Key:
                                  Original: {res_ks["key_original_hex"]}
                                  Modified: {res_ks["key_modified_hex"]}

                                AES Std:
                                  CT1: {res_ks["std"]["ct1"]}
                                  CT2: {res_ks["std"]["ct2"]}

                                SBOX44:
                                  CT1: {res_ks["sbox44"]["ct1"]}
                                  CT2: {res_ks["sbox44"]["ct2"]}
                                """
                            ).strip(),
                            language="text",
                        )
                except Exception as e:
                    st.error(f"Perhitungan key sensitivity gagal: {e}")

        st.markdown("</div>", unsafe_allow_html=True)
