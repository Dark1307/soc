## 🛡️ Integrated SOC Intelligence Suite

A comprehensive **Security Operations Center (SOC)** simulation platform built.

The suite combines **7 cybersecurity modules** into a single dark-themed web application powered by Python Flask:

| Module | Description |
|--------|-------------|
| 🖥️ Dashboard | Live threat level, risk score & scrolling alert feed |
| 🔍 Port Scanner | Multi-threaded TCP scanner with banner grabbing & risk flags |
| 🤖 Log Analyzer | ML-based detection (Random Forest + TF-IDF) for 5 attack types |
| 📡 Network Monitor | Real-time packet capture using Scapy + Npcap |
| 💣 Payload Lab | Safe SQL/XSS/DoS/CMDi/PathTrav reference with encoder/decoder |
| #️⃣ Hash Tools | 10 algorithms (MD5 → BLAKE2) + HMAC + verifier |
| 📄 Reports | Auto-generated PDF reports using ReportLab |

---

### 🚀 Tech Stack
`Python 3.10+` · `Flask` · `Scikit-learn` · `Scapy` · `Npcap` · `ReportLab` · `HTML5/CSS3/JS`


### ▶️ Run
```bash
cd soc_suite
pip install requriment 
python app.py
# Open: http://127.0.0.1:5000
# Note: Run as Administrator for Network Monitor
```
