import streamlit as st
import requests
import base64
import hashlib

# Your VirusTotal Key
VT_API_KEY = "YOUR_API_KEY_HERE"

st.set_page_config(page_title="CyberShield Web", page_icon="🛡️")
st.title("🛡️ CyberShield Web Security")

tab1, tab2 = st.tabs(["URL Scanner", "File Scanner"])

# --- URL SCANNER ---
with tab1:
    url = st.text_input("Enter URL to scan:")
    if st.button("Analyze Link"):
        if url:
            # VirusTotal API Check
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
            res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", 
                               headers={"x-apikey": VT_API_KEY})
            if res.status_code == 200:
                stats = res.json()['data']['attributes']['last_analysis_stats']
                st.write(f"🚩 Malicious: {stats['malicious']}")
                if stats['malicious'] > 0:
                    st.error("DANGER: This link is flagged!")
                else:
                    st.success("This link appears safe.")

# --- FILE SCANNER ---
with tab2:
    uploaded_file = st.file_uploader("Choose a file to scan")
    if uploaded_file is not None:
        # Calculate Hash
        file_bytes = uploaded_file.read()
        file_hash = hashlib.sha256(file_bytes).hexdigest()
        st.info(f"File Fingerprint: {file_hash}")
        
        # Check VirusTotal
        res = requests.get(f"https://www.virustotal.com/api/v3/files/{file_hash}", 
                           headers={"x-apikey": VT_API_KEY})
        if res.status_code == 200:
            st.warning("Found in malware database!")
        else:
            st.success("File fingerprint not flagged as malicious.")