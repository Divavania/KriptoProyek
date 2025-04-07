import streamlit as st

# Fungsi Enkripsi Vigenere
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

# Fungsi Dekripsi Vigenere
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

# Streamlit UI
st.title("🔐 Vigenère Cipher Web App")

# Input file dan kunci
uploaded_file = st.file_uploader("📂 Upload file (.txt)", type=["txt"])
key = st.text_input("🔑 Masukkan Kunci")

# Pilihan mode
mode = st.radio("Pilih Mode:", ["Enkripsi", "Dekripsi"])

if uploaded_file and key:
    content = uploaded_file.read().decode('utf-8')

    if st.button("🚀 Proses Sekarang"):
        if mode == "Enkripsi":
            result = vigenere_encrypt(content, key)
            st.success("✅ Enkripsi berhasil!")
        else:
            result = vigenere_decrypt(content, key)
            st.success("✅ Dekripsi berhasil!")

        st.text_area("📄 Hasil:", result, height=200)

        # Tombol download
        st.download_button(
            label="⬇️ Download Hasil",
            data=result,
            file_name="output.txt",
            mime="text/plain"
        )