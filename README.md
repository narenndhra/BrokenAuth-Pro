# 🔒 BrokenAuth Pro – Professional Broken Authentication Testing Extension for Burp Suite

**BrokenAuth Pro** is a **Burp Suite Jython extension** designed to detect **Broken Authentication and Session Management** issues automatically.  
It allows penetration testers to **analyze session header protection**, test for **authorization enforcement**, and detect authentication bypasses in real-time.

---

## 🚀 Overview

Manual testing of authentication headers (like `Cookie`, `Authorization`, or `X-Auth-Token`) can be repetitive and error-prone.  
**BrokenAuth Pro** automates this process with two intelligent testing modes — **Remove All** and **Strip All** — to simulate different authentication bypass scenarios.

---

## ✨ Key Features

- **Dual-Mode Authentication Testing**
  - **Remove All Mode** – Removes all session headers and replays the request.  
  - **Strip All Mode** – Retains header names but clears their values to test partial bypasses.

- **Auto and Manual Testing**
  - Automatically tests Proxy and Repeater traffic when **Auto-Scan** is enabled.  
  - Supports **manual testing** via right-click context menu → “Send to BrokenAuth Pro”.

- **Smart Header Management**
  - Easily manage which headers to test (`Cookie`, `Authorization`, etc.).  
  - Add **custom authentication headers** to include in scans.

- **Scope and Filtering Options**
  - Optionally exclude static resources (`.js`, `.css`, `.png`, etc.).  
  - Whitelist URLs using **regular expressions**.  
  - Include/exclude `GET` requests as needed.

- **Real-Time Dashboard**
  - View all test results instantly in a dynamic **Live Dashboard**.  
  - Displays verdicts (`VULNERABLE`, `SAFE`, `SUSPICIOUS`), HTTP status, and calculated **risk scores**.

- **Color-Coded Verdicts**
  - Intuitive color rendering for verdicts and risk severity.  
  - Easily identify critical vulnerabilities at a glance.

- **Quick Export Options**
  - Export results as **CSV** or **JSON** for offline analysis or reporting.  
  - Includes essential metadata like verdicts, risk scores, and endpoints.

---

## 🧠 How It Works

1. **Configuration Tab**
   - Select which headers to test (`Cookie`, `Authorization`, `X-Auth-Token`, etc.).  
   - Add custom session headers.  
   - Define URL filters and scope rules.  
   - Toggle auto-scan for Proxy and Repeater.

2. **Live Dashboard Tab**
   - Displays all test results in real-time.  
   - Provides summary cards for total, vulnerable, safe, and unknown endpoints.  
   - Supports searching, filtering, and sorting.  
   - Integrated **Request/Response Viewer** to inspect HTTP messages.  
   - Export options available directly from this tab.

---

## 📊 Verdicts Explained

| Verdict | Description |
|----------|--------------|
| **VULNERABLE** | Endpoint accessible without authentication headers. |
| **SAFE / AUTH_ENFORCED** | Proper authentication required (401/403). |
| **SUSPICIOUS** | Unexpected behavior or redirect detected. |
| **INPUT_ERROR / ROUTING_ERROR** | Minor client errors, may indicate weak auth checks. |
| **SERVER_ERROR** | Unexpected 5xx responses. |

---

## ⚙️ Installation

1. **Install Jython**
   - Download `jython-standalone-2.7.x.jar`.
   - In Burp → `Extender → Options → Python Environment` → Select the JAR.

2. **Load the Extension**
   - Save this script as `BrokenAuthPro.py`.
   - In Burp → `Extender → Extensions → Add`:
     - Extension type: **Python**
     - Extension file: `BrokenAuthPro.py`

3. **Verify Installation**
   - A new tab **“BrokenAuth Pro”** will appear inside Burp Suite.

---

## 🧩 Exporting Results

- **CSV Export**
  - Exports endpoint, method, mode, status, verdict, risk score, and details.
  - Saved as `brokenauth_results.csv` under the user home directory.

- **JSON Export**
  - Includes all test results, summary stats, and metadata.
  - Useful for CI/CD pipelines or post-processing in tools.

---

## 🧪 Use Cases

- Test authentication header enforcement across APIs and web apps.  
- Identify weak or missing authentication mechanisms.  
- Validate if removing or emptying tokens still grants access.  
- Quickly find potential bypasses due to missing backend validation.  

---

## 🪪 Requirements

- **Burp Suite (Community or Professional)**  
- **Jython 2.7.x**  
- **No additional dependencies required**  

---

## 👤 Author

**Narendra Reddy (Entersoft Security)**  
