import nltk
from nltk.tokenize import sent_tokenize
import re

class PrivacyAnalyzer:
    def __init__(self):
        try:
            nltk.data.find('tokenizers/punkt')
        except LookupError:
            nltk.download('punkt')

    def analyze_policy(self, policy_text):
        """Analyze privacy policy text and extract key points"""
        sentences = sent_tokenize(policy_text)
        
        # Keywords to look for
        data_collection = r"collect|gather|obtain|track"
        data_sharing = r"share|transfer|disclose|provide to"
        data_storage = r"store|save|retain|keep"
        
        findings = []
        
        for sentence in sentences:
            if re.search(data_collection, sentence, re.I):
                findings.append("Data Collection: " + sentence.strip())
            if re.search(data_sharing, sentence, re.I):
                findings.append("Data Sharing: " + sentence.strip())
            if re.search(data_storage, sentence, re.I):
                findings.append("Data Storage: " + sentence.strip())
                
        return findings
