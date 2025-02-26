def calculate_risk_score(permissions, malware_results, privacy_findings):
    """Calculate overall risk score based on various factors"""
    score = 5.0  # Start with neutral score
    
    # Permission risk factors
    permission_risk = {
        "High": 2.0,
        "Medium": 1.0,
        "Low": 0.2
    }
    
    # Calculate permission score
    perm_count = {risk: 0 for risk in permission_risk.keys()}
    for risk_level in permissions.values():
        perm_count[risk_level] += 1
    
    permission_score = sum(perm_count[risk] * permission_risk[risk] 
                         for risk in permission_risk.keys())
    
    # Normalize permission score (max 3 points)
    permission_score = min(permission_score, 3.0)
    
    # Malware detection score (max 4 points)
    malware_score = 4.0 if malware_results['detected'] else 0.0
    
    # Privacy policy score (max 3 points)
    privacy_score = min(len(privacy_findings) * 0.5, 3.0)
    
    # Calculate final score
    final_score = score + permission_score + malware_score + privacy_score
    
    # Normalize to 0-10 scale
    final_score = min(max(final_score, 0.0), 10.0)
    
    return round(final_score, 1)
