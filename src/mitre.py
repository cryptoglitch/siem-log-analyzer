MITRE_ATTACK = {
    "Brute Force Detected": {
        "id": "T1110",
        "name": "Brute Force",
        "recommendation": (
            "Investigate authentication logs, verify MFA, and consider blocking the source IP."
        )
    },

    "Successful Login After Failed Logins": {
        "id": "T1110",
        "name": "Brute Force",
        "recommendation": (
            "Verify the login was legitimate. Review recent account activity for suspicious behavior."
        )
    },

    "PowerShell Execution": {
        "id": "T1059.001",
        "name": "PowerShell",
        "recommendation": (
            "Review the executed PowerShell command and determine whether it was expected."
        )
    }
}


def enrich_alert(alert):
    if alert["title"] in MITRE_ATTACK:
        mitre = MITRE_ATTACK[alert["title"]]

        alert["mitre_id"] = mitre["id"]
        alert["mitre_name"] = mitre["name"]
        alert["recommendation"] = mitre["recommendation"]

    return alert
