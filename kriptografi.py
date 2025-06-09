import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# --- Vigenère Cipher ---
def vigenere_encrypt(plaintext, key):
    key = key.upper()
    encrypted = []
    key_length = len(key)
    
    for i, char in enumerate(plaintext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            encrypted.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            encrypted.append(char)
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    decrypted = []
    key_length = len(key)
    
    for i, char in enumerate(ciphertext):
        if char.isalpha():
            shift = ord(key[i % key_length]) - ord('A')
            base = ord('A') if char.isupper() else ord('a')
            decrypted.append(chr((ord(char) - base - shift) % 26 + base))
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
st.title("🔐 Aplikasi Enkripsi & Dekripsi 3 Lapisan (Vigenère → AES → Caesar)")

uploaded_file = st.file_uploader("📂 Upload file (.txt)", type=["txt"])
key = st.text_input("🔑 Masukkan Kunci (Digunakan untuk semua lapisan)")
mode = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"])

if uploaded_file and key:
    content = uploaded_file.read().decode('utf-8')

    if st.button("🚀 Proses Sekarang"):
        try:
            if mode == "Enkripsi":
                # Step 1: Vigenère
                step1 = vigenere_encrypt(content, key)
                st.text_area("🔐 Hasil Enkripsi Vigenère:", step1, height=150)

                # Step 2: AES
                step2 = aes_encrypt(step1, key)
                st.text_area("🔐 Hasil Enkripsi AES (Base64):", step2, height=150)

                # Step 3: Caesar
                result = caesar_encrypt(step2, key)
                st.text_area("🔐 Hasil Enkripsi Caesar (Final):", result, height=150)

                st.text_area("📄 Hasil Akhir (Gabungan 3 Lapisan):", result, height=200)

                st.success("✅ Enkripsi Berhasil!")

            else:  # Dekripsi
                # Step 1: Caesar
                step1 = caesar_decrypt(content, key)
                st.text_area("🔓 Hasil Dekripsi Caesar:", step1, height=150)

                # Step 2: AES
                step2 = aes_decrypt(step1, key)
                st.text_area("🔓 Hasil Dekripsi AES:", step2, height=150)

                # Step 3: Vigenère
                result = vigenere_decrypt(step2, key)
                st.text_area("🔓 Hasil Dekripsi Vigenère (Final):", result, height=150)

                st.text_area("📄 Hasil Akhir (Gabungan 3 Lapisan):", result, height=200)

                st.success("✅ Dekripsi Berhasil!")

            # Tombol download untuk hasil AKHIR
            st.download_button("⬇ Download Hasil Akhir", data=result, file_name="output.txt", mime="text/plain")

        except Exception as e:
            st.error(f"❌ Terjadi kesalahan: {e}")