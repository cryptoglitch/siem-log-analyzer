# 🛡️ SIEM Log Analyzer

A Python-based Security Information and Event Management (SIEM) project that analyzes Windows Security Event Logs and detects suspicious activity using custom detection rules mapped to the MITRE ATT&CK framework.

---

## Features

- 🔍 Parses Windows Security Event Logs
- 🚨 Detects Brute Force attacks
- 🔄 Correlates successful logins after repeated failures
- ⚡ Detects PowerShell execution
- 🛡️ Maps detections to MITRE ATT&CK techniques
- 💡 Provides analyst recommendations
- 🖥️ Displays professional terminal alerts using Rich

---

## Technologies

- Python
- Rich
- MITRE ATT&CK
- Windows Security Event Logs

---

## Detection Rules

| Detection | MITRE Technique |
|-----------|-----------------|
| Brute Force | T1110 |
| Successful Login After Failed Logins | T1110 |
| PowerShell Execution | T1059.001 |

---

## 📁 Project Structure


siem-log-analyzer/
│
├── logs/
│   └── security_log.csv
│
├── screenshots/
│   ├── security-log-events.png
│   ├── brute-force-alert.png
│   └── powershell-alert.png
│
├── src/
│   ├── parser.py
│   ├── detections.py
│   ├── alert_builder.py
│   ├── alerts.py
│   ├── mitre.py
│   └── main.py
│
├── README.md
├── requirements.txt
└── .gitignore
```

---

---

## Future Improvements

- Windows Defender Disabled detection
- USB Device monitoring
- Account creation detection
- HTML reports
- Interactive web dashboard
- EVTX support
- Threat scoring dashboard

---

## Author

**Paloma Galindo**

Aspiring Cybersecurity Engineer passionate about detection engineering, threat hunting, and security automation.
