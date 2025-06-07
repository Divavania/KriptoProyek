import streamlit as st
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

# --- Vigenère Cipher ---
def vigenere_encrypt(plaintext, key):
    # Buat daftar kosong encrypted untuk simpan hasil enkripsi.
    encrypted = []
    # Ubah kunci ke huruf kapital untuk konsistensi.
    key = key.upper()
    # Inisialisasi key_index untuk lacak posisi karakter kunci.
    key_index = 0

    # Iterasi setiap karakter di plaintext.
    for char in plaintext:
        # Periksa apakah karakter adalah huruf alfabet.
        if char.isalpha():
            # Hitung geseran: nilai ASCII karakter kunci dikurangi ASCII 'A'.
            shift = ord(key[key_index % len(key)]) - ord('A')
            # Tentukan base: ASCII 'A' (kapital) atau 'a' (kecil).
            base = ord('A') if char.isupper() else ord('a')
            # Enkripsi: geser karakter, modulo 26, ubah kembali ke karakter.
            encrypted_char = chr((ord(char) - base + shift) % 26 + base)
            # Tambah karakter terenkripsi ke encrypted.
            encrypted.append(encrypted_char)
            # Tambah key_index untuk karakter kunci berikutnya.
            key_index += 1
        # Jika bukan alfabet:
        else:
            # Tambah karakter langsung ke encrypted tanpa perubahan.
            encrypted.append(char)
    # Gabungkan encrypted jadi string hasil enkripsi.
    return ''.join(encrypted)

def vigenere_decrypt(ciphertext, key):
    # Buat daftar kosong decrypted untuk simpan hasil dekripsi.
    decrypted = []
    # Ubah kunci ke huruf kapital.
    key = key.upper()
    # Inisialisasi key_index untuk lacak posisi kunci.
    key_index = 0

    # Iterasi setiap karakter di ciphertext.
    for char in ciphertext:
        # Periksa apakah karakter adalah alfabet.
        if char.isalpha():
            # Hitung geseran dari kunci, sama seperti enkripsi.
            shift = ord(key[key_index % len(key)]) - ord('A')
            # Tentukan base: ASCII 'A' (kapital) atau 'a' (kecil).
            base = ord('A') if char.isupper() else ord('a')
            # Dekripsi: balikkan geseran, modulo 26, ubah ke karakter.
            decrypted_char = chr((ord(char) - base - shift) % 26 + base)
            # Tambah karakter didekripsi ke decrypted.
            decrypted.append(decrypted_char)
            # Tambah key_index untuk karakter kunci berikutnya.
            key_index += 1
        # Jika bukan alfabet:
        else:
            # Tambah karakter langsung ke decrypted tanpa perubahan.
            decrypted.append(char)
    # Gabungkan decrypted jadi string hasil dekripsi.
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

# Memeriksa apakah file telah diunggah dan kunci telah dimasukkan.
if uploaded_file and key:
    # Membaca isi file yang diunggah dan mengubahnya dari bytes ke string dengan encoding UTF-8.
    content = uploaded_file.read().decode('utf-8')

    if st.button("🚀 Proses Sekarang"):
        try:
            if mode == "Enkripsi":
                # Step 1: Vigenère
                # Langkah 1: Enkripsi teks menggunakan fungsi vigenere_encrypt dengan content dan key.
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
                # Langkah 3: Dekripsi hasil AES (step2) menggunakan fungsi vigenere_decrypt.
                result = vigenere_decrypt(step2, key)
                st.text_area("🔓 Hasil Dekripsi Vigenère (Final):", result, height=150)

                st.text_area("📄 Hasil Akhir (Gabungan 3 Lapisan):", result, height=200)

                st.success("✅ Dekripsi Berhasil!")

            # Tombol download untuk hasil AKHIR
            st.download_button("⬇ Download Hasil Akhir", data=result, file_name="output.txt", mime="text/plain")

        except Exception as e:
            st.error(f"❌ Terjadi kesalahan: {e}")