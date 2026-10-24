import streamlit as st
st.markdown("""
<div style="text-align: center; padding: 20px 10px;">

    <h1>SecureFileLab</h1>

    <p>Secure File Encryption, Decryption &amp; Hashing</p>

    <hr>

    <h3>Developed by</h3>
    <h2>Rutuja Sudesh Kadam</h2>

    <p>Department of Forensic Science</p>

    <h4>Yashavantrao Chavan Institute of Science, Satara</h4>
    <p>Maharashtra, India</p>

    <hr>

    <h3>Under the Guidance of</h3>
    <p>Mr. Smitesh Nalage</p>
    <p>Mr. Aadesh Vatane</p>

    <hr>

    <p><b>Research Project:</b> MITM Attack Prevention</p>

</div>
""", unsafe_allow_html=True)
import hashlib
import io
from cryptography.fernet import Fernet, InvalidToken

st.set_page_config(
    page_title="SecureFile Lab",
    page_icon="🔐",
    layout="centered"
)

st.title("🔐 SecureFile Lab")
st.subheader("Data Integrity & Confidentiality Research Prototype")

st.info(
    "Research prototype: SHA-256 checks file integrity. "
    "Encryption protects confidentiality. These alone do not "
    "prove or prevent a live MITM attack."
)

st.header("1. Two-File Hash Comparison")

files = st.file_uploader(
    "Select original and modified files",
    type=["txt", "pdf", "docx", "pptx"],
    accept_multiple_files=True,
    key="compare"
)

if files:
    if len(files) != 2:
        st.warning("Please select exactly two files to compare.")
    else:
        data1 = files[0].getvalue()
        data2 = files[1].getvalue()

        hash1 = hashlib.sha256(data1).hexdigest()
        hash2 = hashlib.sha256(data2).hexdigest()

        st.write("**File 1:**", files[0].name)
        st.code(hash1)

        st.write("**File 2:**", files[1].name)
        st.code(hash2)

        if hash1 == hash2:
            st.success("MATCH: Both files have identical contents.")
        else:
            st.error("MISMATCH: File contents are different.")

        report = (
            f"File 1: {files[0].name}\nSHA-256: {hash1}\n\n"
            f"File 2: {files[1].name}\nSHA-256: {hash2}\n\n"
            f"Result: {'MATCH' if hash1 == hash2 else 'MISMATCH'}\n"
        )

        st.download_button(
            "Download comparison report",
            data=report,
            file_name="hash_comparison.txt",
            mime="text/plain"
        )

st.divider()
st.header("2. Encrypt a File")

source = st.file_uploader(
    "Choose a file to encrypt",
    type=["txt", "pdf", "docx", "pptx"],
    key="encrypt"
)

password = st.text_input(
    "Create an encryption password",
    type="password",
    key="encrypt_password"
)

confirm_password = st.text_input(
    "Confirm password",
    type="password",
    key="confirm_password"
)

if st.button("Encrypt File"):
    if source is None:
        st.error("Please select a file.")
    elif len(password) < 12:
        st.error("Use a password of at least 12 characters.")
    elif password != confirm_password:
        st.error("Passwords do not match.")
    else:
        import base64
        import os
        import hashlib as hl

        salt = os.urandom(16)
        key = hl.pbkdf2_hmac(
            "sha256", password.encode(), salt, 600000, dklen=32
        )
        fernet_key = base64.urlsafe_b64encode(key)
        encrypted = Fernet(fernet_key).encrypt(source.getvalue())
        package = b"SFL1" + salt + encrypted

        st.download_button(
            "Download encrypted file",
            data=package,
            file_name=source.name + ".sfl",
            mime="application/octet-stream"
        )
        st.success("Encryption complete. Save the password securely.")

st.divider()
st.header("3. Decrypt a File")

encrypted_file = st.file_uploader(
    "Choose an encrypted .sfl file",
    type=["sfl"],
    key="decrypt"
)

decrypt_password = st.text_input(
    "Enter the original encryption password",
    type="password",
    key="decrypt_password"
)

if st.button("Decrypt File"):
    if encrypted_file is None or not decrypt_password:
        st.error("Select an encrypted file and enter its password.")
    else:
        import base64
        import hashlib as hl

        package = encrypted_file.getvalue()

        try:
            if not package.startswith(b"SFL1") or len(package) < 21:
                raise ValueError("Invalid encrypted file format.")

            salt = package[4:20]
            key = hl.pbkdf2_hmac(
                "sha256", decrypt_password.encode(), salt,
                600000, dklen=32
            )
            fernet_key = base64.urlsafe_b64encode(key)
            decrypted = Fernet(fernet_key).decrypt(package[20:])

            original_name = encrypted_file.name[:-4]
            st.success("Decryption successful!")
            st.write("**Decrypted file SHA-256:**")
            st.code(hashlib.sha256(decrypted).hexdigest())

            st.download_button(
                "Download decrypted file",
                data=decrypted,
                file_name=original_name,
                mime="application/octet-stream"
            )

        except (InvalidToken, ValueError):
            st.error("Decryption failed. Check the password and file.")

st.caption(
    "Prototype notice: Uploaded files are handled in application memory. "
    "Public hosting requires additional security and privacy testing."
)
