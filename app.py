import streamlit as st
import pandas as pd
import plotly.express as px
from utils.apk_analyzer import APKAnalyzer
from utils.virustotal import VirusTotalScanner
from utils.privacy_analyzer import PrivacyAnalyzer
from utils.risk_calculator import calculate_risk_score
import tempfile
import os
import re

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
    if 'analysis_type' not in st.session_state:
        st.session_state.analysis_type = 'apk'

initialize_session_state()

st.title("📱 App Security & Privacy Analyzer")
st.markdown("""
This tool analyzes Android applications for security risks and privacy concerns.
Choose your preferred method of analysis below!
""")

# Analysis type selection
analysis_type = st.radio(
    "Choose analysis method:",
    ('Upload APK file', 'Enter Play Store link'),
    key='analysis_type_radio'
)

def validate_play_store_url(url):
    """Validate if the URL is a valid Google Play Store link"""
    play_store_pattern = r'https?://play\.google\.com/store/apps/details\?id=[\w\.]+'
    return bool(re.match(play_store_pattern, url))

def extract_package_name(url):
    """Extract package name from Play Store URL"""
    match = re.search(r'id=([\w\.]+)', url)
    return match.group(1) if match else None

if analysis_type == 'Upload APK file':
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

else:
    play_store_url = st.text_input(
        "Enter Google Play Store URL",
        placeholder="https://play.google.com/store/apps/details?id=com.example.app"
    )

    if play_store_url:
        if not validate_play_store_url(play_store_url):
            st.error("Please enter a valid Google Play Store URL")
        else:
            with st.spinner("Analyzing app from Play Store..."):
                package_name = extract_package_name(play_store_url)

                # For demo purposes, using sample data
                # In a real implementation, this would fetch data from Play Store
                permissions = {
                    "INTERNET": "Low",
                    "ACCESS_NETWORK_STATE": "Low",
                    "READ_EXTERNAL_STORAGE": "Medium",
                    "CAMERA": "High"
                }

                malware_scan = {
                    "detected": False,
                    "details": {
                        "total_scanners": 70,
                        "positive_detections": 0,
                        "scan_results": {
                            "scanner1": "clean",
                            "scanner2": "clean"
                        }
                    }
                }

                privacy_summary = [
                    "Data Collection: App collects device information",
                    "Data Usage: App uses data for analytics",
                    "Data Sharing: Limited sharing with third parties"
                ]

                risk_score = calculate_risk_score(permissions, malware_scan, privacy_summary)

                # Store results in session state
                st.session_state.permissions = permissions
                st.session_state.malware_results = malware_scan
                st.session_state.privacy_summary = privacy_summary
                st.session_state.risk_score = risk_score
                st.session_state.analysis_complete = True

if st.session_state.analysis_complete:
    # Display results in tabs
    tab1, tab2, tab3, tab4 = st.tabs(["Risk Score", "Permissions", "Malware Scan", "Privacy Analysis"])

    with tab1:
        col1, col2 = st.columns([1, 2])
        with col1:
            st.metric("Overall Risk Score", f"{st.session_state.risk_score}/10")
        with col2:
            # Create a horizontal bar chart for risk visualization
            risk_df = pd.DataFrame({
                'Score': [st.session_state.risk_score],
                'Max': [10 - st.session_state.risk_score]  # Remaining part of the bar
            })

            fig = px.bar(risk_df, 
                        x=['Score', 'Max'], 
                        orientation='h',
                        height=100,
                        title="Risk Level",
                        color_discrete_sequence=['#FF4B4B', '#E0E0E0'])

            # Customize the layout
            fig.update_layout(
                showlegend=False,
                xaxis_range=[0, 10],
                xaxis_title=None,
                yaxis_title=None,
                yaxis_showticklabels=False,
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=20, r=20, t=30, b=20)
            )

            st.plotly_chart(fig, use_container_width=True)

            # Add risk level text
            risk_level = "Low" if st.session_state.risk_score <= 3 else "Medium" if st.session_state.risk_score <= 7 else "High"
            st.markdown(f"<h3 style='text-align: center; color: {'green' if risk_level == 'Low' else 'orange' if risk_level == 'Medium' else 'red'};'>{risk_level} Risk</h3>", unsafe_allow_html=True)

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