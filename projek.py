import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# --- Vigenère Cipher ---
def vigenere_encrypt(plaintext, key):
    encrypted = []
    key = key.upper()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            encrypted.append(encrypted_char)
            key_index += 1
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    decrypted = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            decrypted.append(decrypted_char)
            key_index += 1
        else:
            decrypted.append(char)
    return ''.join(decrypted)

# --- AES ---
def get_aes_key(key):
    return hashlib.sha256(key.encode()).digest()

def aes_encrypt(text, key):
    cipher = AES.new(get_aes_key(key), AES.MODE_ECB)
    encrypted = cipher.encrypt(pad(text.encode(), AES.block_size))
    return base64.b64encode(encrypted).decode()

def aes_decrypt(base64_text, key):
    cipher = AES.new(get_aes_key(key), AES.MODE_ECB)
    decrypted = cipher.decrypt(base64.b64decode(base64_text))
    return unpad(decrypted, AES.block_size).decode()

# --- Caesar Cipher ---
def caesar_encrypt(text, key):
    shift = len(key)
    result = ""
    for char in text:
        result += chr((ord(char) + shift) % 256)
    return result

def caesar_decrypt(text, key):
    shift = len(key)
    result = ""
    for char in text:
        result += chr((ord(char) - shift) % 256)
    return result

# --- Streamlit UI ---
st.set_page_config(
    page_title="🔐 Enkripsi 3 Lapisan",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Custom CSS untuk tampilan dinamis dan tidak monoton
st.markdown("""
    <style>
    .main {
        background: linear-gradient(135deg, #e0f7fa 0%, #f0f2f6 100%);
        padding: 30px;
        border-radius: 15px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
    }
    .stButton>button {
        background: linear-gradient(45deg, #4CAF50, #66BB6A);
        color: white;
        border-radius: 10px;
        padding: 12px 24px;
        font-weight: bold;
        transition: transform 0.2s ease-in-out;
    }
    .stButton>button:hover {
        background: linear-gradient(45deg, #45a049, #5cb860);
        transform: scale(1.05);
    }
    .stTextInput>div>div>input {
        border: 2px solid #26A69A;
        border-radius: 10px;
        padding: 10px;
        background-color: #ffffff;
    }
    .stFileUploader>div>div>input {
        border: 2px solid #26A69A;
        border-radius: 10px;
        padding: 10px;
    }
    .stRadio>div {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 10px;
        border: 2px solid #26A69A;
        box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }
    .stTextArea textarea {
        border: 2px solid #26A69A;
        border-radius: 10px;
        background-color: #ffffff;
        font-family: 'Courier New', Courier, monospace;
    }
    .title {
        font-size: 2.8em;
        color: #00695C;
        text-align: center;
        margin-bottom: 20px;
        font-weight: bold;
        text-shadow: 1px 1px 2px rgba(0, 0, 0, 0.1);
    }
    .subtitle {
        font-size: 1.3em;
        color: #37474F;
        text-align: center;
        margin-bottom: 30px;
        font-style: italic;
    }
    .success-box {
        background: linear-gradient(45deg, #e8f5e9, #c8e6c9);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #4CAF50;
        color: #2e7d32;
        font-weight: bold;
        animation: fadeIn 0.5s;
    }
    .error-box {
        background: linear-gradient(45deg, #ffebee, #ffcdd2);
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #d32f2f;
        color: #b71c1c;
        font-weight: bold;
        animation: fadeIn 0.5s;
    }
    @keyframes fadeIn {
        0% { opacity: 0; transform: translateY(-10px); }
        100% { opacity: 1; transform: translateY(0); }
    }
    .section-divider {
        border-top: 2px dashed #26A69A;
        margin: 20px 0;
    }
    </style>
""", unsafe_allow_html=True)

# Judul dan Deskripsi
st.markdown('<div class="title">🔐 Enkripsi & Dekripsi 3 Lapisan</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Lindungi Data Anda dengan Vigenère → AES → Caesar Cipher</div>', unsafe_allow_html=True)

# Pemisah visual
st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)

# Form untuk input pengguna
with st.container():
    st.markdown("### 📥 Masukkan Data Anda")
    with st.form(key="crypto_form"):
        uploaded_file = st.file_uploader(
            "📂 Upload File Teks (.txt)",
            type=["txt"],
            help="Pilih file teks yang ingin dienkripsi atau didekripsi"
        )
        key = st.text_input(
            "🔑 Masukkan Kunci",
            type="password",
            help="Kunci digunakan untuk semua lapisan enkripsi. Pastikan kunci aman!"
        )
        mode = st.radio(
            "Pilih Mode:",
            ["Enkripsi", "Dekripsi"],
            help="Pilih apakah akan mengenkripsi atau mendekripsi file",
            horizontal=True
        )
        submit_button = st.form_submit_button("🚀 Proses Sekarang")

# Logika pemrosesan
if uploaded_file and key and submit_button:
    content = uploaded_file.read().decode('utf-8')
    
    with st.spinner("🔄 Sedang Memproses Data..."):
        try:
            if mode == "Enkripsi":
                step1 = vigenere_encrypt(content, key)
                step2 = aes_encrypt(step1, key)
                result = caesar_encrypt(step2, key)
                st.markdown('<div class="success-box">✅ Enkripsi Berhasil! Data Anda telah diamankan.</div>', unsafe_allow_html=True)
            else:
                step1 = caesar_decrypt(content, key)
                step2 = aes_decrypt(step1, key)
                result = vigenere_decrypt(step2, key)
                st.markdown('<div class="success-box">✅ Dekripsi Berhasil! Data Anda telah dipulihkan.</div>', unsafe_allow_html=True)

            st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
            st.markdown("### 📄 Hasil Pemrosesan")
            st.text_area(
                "Hasil:",
                result,
                height=250,
                help="Hasil enkripsi atau dekripsi ditampilkan di sini"
            )
            st.download_button(
                label="⬇️ Download Hasil",
                data=result,
                file_name="output.txt",
                mime="text/plain",
                help="Unduh hasil sebagai file teks",
                key="download_button"
            )
        except Exception as e:
            st.markdown(f'<div class="error-box">❌ Terjadi kesalahan: {e}</div>', unsafe_allow_html=True)