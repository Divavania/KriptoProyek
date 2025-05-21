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
    initial_sidebar_state="expanded"
)

# Custom CSS untuk mempercantik tampilan
st.markdown("""
    <style>
    .main {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border-radius: 8px;
        padding: 10px 20px;
        font-weight: bold;
    }
    .stButton>button:hover {
        background-color: #45a049;
    }
    .stTextInput>div>div>input {
        border: 2px solid #4CAF50;
        border-radius: 8px;
    }
    .stFileUploader>div>div>input {
        border: 2px solid #4CAF50;
        border-radius: 8px;
    }
    .stRadio>div {
        background-color: #ffffff;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #4CAF50;
    }
    .stTextArea textarea {
        border: 2px solid #4CAF50;
        border-radius: 8px;
        background-color: #ffffff;
    }
    .title {
        font-size: 2.5em;
        color: #2e7d32;
        text-align: center;
        margin-bottom: 20px;
    }
    .subtitle {
        font-size: 1.2em;
        color: #555555;
        text-align: center;
        margin-bottom: 30px;
    }
    .success-box {
        background-color: #e8f5e9;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #4CAF50;
    }
    .error-box {
        background-color: #ffebee;
        padding: 10px;
        border-radius: 8px;
        border: 1px solid #d32f2f;
    }
    </style>
""", unsafe_allow_html=True)

# Judul dan Deskripsi
st.markdown('<div class="title">🔐 Aplikasi Enkripsi & Dekripsi 3 Lapisan</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Amankan data Anda dengan Vigenère → AES → Caesar Cipher</div>', unsafe_allow_html=True)

# Sidebar untuk informasi tambahan
with st.sidebar:
    st.header("ℹ️ Tentang Aplikasi")
    st.write("""
        Aplikasi ini mengenkripsi atau mendekripsi file teks menggunakan tiga lapisan keamanan:
        1. **Vigenère Cipher**: Enkripsi berbasis kunci huruf.
        2. **AES**: Algoritma enkripsi simetris modern.
        3. **Caesar Cipher**: Pergeseran karakter berbasis panjang kunci.
        Masukkan kunci yang sama untuk enkripsi dan dekripsi.
    """)
    st.markdown("---")
    st.write("**Catatan Keamanan**: Gunakan kunci yang kuat dan simpan dengan aman!")

# Form untuk input pengguna
with st.form(key="crypto_form"):
    uploaded_file = st.file_uploader("📂 Upload File Teks (.txt)", type=["txt"], help="Pilih file teks yang ingin dienkripsi atau didekripsi")
    key = st.text_input("🔑 Masukkan Kunci", type="password", help="Kunci digunakan untuk semua lapisan enkripsi")
    mode = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"], help="Pilih apakah akan mengenkripsi atau mendekripsi file")
    submit_button = st.form_submit_button("🚀 Proses Sekarang")

# Logika pemrosesan
if uploaded_file and key and submit_button:
    content = uploaded_file.read().decode('utf-8')
    
    with st.spinner("🔄 Memproses..."):
        try:
            if mode == "Enkripsi":
                step1 = vigenere_encrypt(content, key)
                step2 = aes_encrypt(step1, key)
                result = caesar_encrypt(step2, key)
                st.markdown('<div class="success-box">✅ Enkripsi Berhasil!</div>', unsafe_allow_html=True)
            else:
                step1 = caesar_decrypt(content, key)
                step2 = aes_decrypt(step1, key)
                result = vigenere_decrypt(step2, key)
                st.markdown('<div class="success-box">✅ Dekripsi Berhasil!</div>', unsafe_allow_html=True)

            st.subheader("📄 Hasil")
            st.text_area("Hasil Pemrosesan:", result, height=200)
            st.download_button(
                label="⬇️ Download Hasil",
                data=result,
                file_name="output.txt",
                mime="text/plain",
                help="Unduh hasil sebagai file teks"
            )
        except Exception as e:
            st.markdown(f'<div class="error-box">❌ Terjadi kesalahan: {e}</div>', unsafe_allow_html=True)