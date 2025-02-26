import streamlit as st
import pandas as pd
import plotly.express as px
from utils.apk_analyzer import APKAnalyzer
from utils.virustotal import VirusTotalScanner
from utils.privacy_analyzer import PrivacyAnalyzer
from utils.risk_calculator import calculate_risk_score
import tempfile
import os

st.set_page_config(
    page_title="App Security & Privacy Analyzer",
    page_icon="🔒",
    layout="wide"
)

def initialize_session_state():
    if 'analysis_complete' not in st.session_state:
        st.session_state.analysis_complete = False
    if 'permissions' not in st.session_state:
        st.session_state.permissions = None
    if 'malware_results' not in st.session_state:
        st.session_state.malware_results = None
    if 'privacy_summary' not in st.session_state:
        st.session_state.privacy_summary = None
    if 'risk_score' not in st.session_state:
        st.session_state.risk_score = None

initialize_session_state()

st.title("📱 App Security & Privacy Analyzer")
st.markdown("""
This tool analyzes Android applications for security risks and privacy concerns.
Upload an APK file to get started!
""")

# File upload section
uploaded_file = st.file_uploader("Upload APK file", type=['apk'])

if uploaded_file:
    with st.spinner("Analyzing APK file..."):
        # Save uploaded file temporarily
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as tmp_file:
            tmp_file.write(uploaded_file.getvalue())
            temp_path = tmp_file.name

        # Initialize analyzers
        apk_analyzer = APKAnalyzer(temp_path)
        vt_scanner = VirusTotalScanner()
        privacy_analyzer = PrivacyAnalyzer()

        # Perform analysis
        permissions = apk_analyzer.get_permissions()
        malware_scan = vt_scanner.scan_file(temp_path)
        privacy_policy = apk_analyzer.get_privacy_policy()
        privacy_summary = privacy_analyzer.analyze_policy(privacy_policy)
        
        # Calculate risk score
        risk_score = calculate_risk_score(permissions, malware_scan, privacy_summary)

        # Store results in session state
        st.session_state.permissions = permissions
        st.session_state.malware_results = malware_scan
        st.session_state.privacy_summary = privacy_summary
        st.session_state.risk_score = risk_score
        st.session_state.analysis_complete = True

        # Clean up temp file
        os.unlink(temp_path)

if st.session_state.analysis_complete:
    # Display results in tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Risk Score", "Permissions", "Malware Scan", "Privacy Analysis"])
    
    with tab1:
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("Overall Risk Score", f"{st.session_state.risk_score}/10")
        with col2:
            risk_gauge = px.gauge(
                value=st.session_state.risk_score,
                range_color=[0, 10],
                title="Risk Level",
                color_continuous_scale=["green", "yellow", "red"]
            )
            st.plotly_chart(risk_gauge)

    with tab2:
        st.subheader("App Permissions")
        perm_df = pd.DataFrame(
            st.session_state.permissions.items(),
            columns=["Permission", "Risk Level"]
        )
        st.dataframe(perm_df, use_container_width=True)
        
        # Permission distribution chart
        perm_counts = perm_df["Risk Level"].value_counts()
        fig = px.pie(values=perm_counts.values, names=perm_counts.index,
                    title="Permission Risk Distribution")
        st.plotly_chart(fig)

    with tab3:
        st.subheader("Malware Scan Results")
        if st.session_state.malware_results['detected']:
            st.error("⚠️ Malware detected!")
        else:
            st.success("✅ No malware detected")
        st.json(st.session_state.malware_results['details'])

    with tab4:
        st.subheader("Privacy Policy Analysis")
        st.write("Key findings from privacy policy:")
        for finding in st.session_state.privacy_summary:
            st.write(f"• {finding}")

