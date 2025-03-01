# App Security & Privacy Analyzer

A Streamlit-based application that analyzes Android APK files and Play Store apps for security risks and privacy concerns. The tool provides detailed insights about app permissions, potential malware threats, and privacy policy analysis.

## Features

- APK file analysis
- Google Play Store app analysis
- Permission risk assessment
- Malware detection
- Privacy policy analysis
- Risk score calculation
- Interactive visualizations

## Prerequisites

- Python 3.11 or higher
- pip (Python package manager)

## Installation

1. Clone the repository:
```bash
git clone <your-repository-url>
cd app-security-analyzer
```

2. Create a virtual environment (recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

3. Install the required packages:
```bash
pip install -r requirements.txt
```

## Required Packages

- streamlit
- pandas
- plotly
- nltk
- androguard
- trafilatura

## Project Structure

```
├── .streamlit/
│   └── config.toml
├── assets/
│   └── app_security.svg
├── utils/
│   ├── __init__.py
│   ├── apk_analyzer.py
│   ├── privacy_analyzer.py
│   ├── risk_calculator.py
│   └── virustotal.py
└── app.py
```

## Configuration

1. Create a `.streamlit/config.toml` file with the following content:
```toml
[server]
headless = true
address = "0.0.0.0"
port = 5000

[theme]
primaryColor = "#FF4B4B"
backgroundColor = "#FFFFFF"
secondaryBackgroundColor = "#F0F2F6"
textColor = "#262730"
```

## Running the Application

1. Start the Streamlit server:
```bash
streamlit run app.py
```

2. Open your web browser and navigate to:
```
http://localhost:5000
```

## Usage

1. Choose your analysis method:
   - Upload an APK file
   - Enter a Google Play Store link

2. View the analysis results in four categories:
   - Risk Score
   - Permissions
   - Malware Scan
   - Privacy Analysis

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

