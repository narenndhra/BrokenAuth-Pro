# 🔒 BrokenAuth Pro – Professional Broken Authentication Testing Extension for Burp Suite

**BrokenAuth Pro** is a **Burp Suite Jython extension** designed to detect **Broken Authentication and Session Management** vulnerabilities automatically.  
It enables penetration testers to analyze **session header protection**, validate **authorization enforcement**, and detect **authentication bypasses** efficiently.

---

## 🚀 Overview

Authentication and session testing can be time-consuming when performed manually.  
BrokenAuth Pro automates this process by intelligently manipulating authentication headers to simulate various bypass conditions.

It offers two main testing modes — **Remove All** and **Strip All** — to detect whether authentication checks are properly enforced.

---

## ✨ Key Features

- **Dual-Mode Authentication Testing**
  - **Remove All Mode:** Removes all session headers and replays the request.  
  - **Strip All Mode:** Keeps header names but clears their values to test partial bypasses.

- **Manual and Auto Testing**
  - Auto-scan traffic from **Proxy** and **Repeater** when enabled.  
  - Manually test any request via context menu → “Send to BrokenAuth Pro”.

- **Session Header Management**
  - Built-in list of common headers (`Cookie`, `Authorization`, `X-Auth-Token`, etc.).  
  - Add custom authentication headers directly from the UI.

- **Scope and Filtering Options**
  - Exclude static resources like `.js`, `.css`, `.png`, etc.  
  - Option to test only endpoints containing authentication headers.

- **Real-Time Dashboard**
  - Displays live scan results in a responsive dashboard.  
  - Color-coded verdicts and risk scores with live counters.  
  - Integrated **Request/Response viewer** for traffic inspection.

- **Verdict Visualization**
  - Intuitive, color-based severity visualization.  
  - Clear status and risk representation for each tested endpoint.

- **Result Export**
  - Export complete results to **CSV** for offline review or reporting.  
  - Each record includes endpoint, method, mode, status, verdict, and risk score.

---

## 🧠 How It Works

### 1. Configuration Tab
- Choose which headers to test for authentication enforcement.  
- Add custom session headers.  
- Enable or disable automatic scanning of Proxy and Repeater traffic.  
- Apply filters to exclude static files or irrelevant endpoints.

### 2. Live Dashboard
- Displays all tested endpoints and verdicts.  
- Search and filter by HTTP method or verdict.  
- View and analyze raw HTTP request and response messages.  
- Export collected data instantly with one click.

---

## 📊 Verdict Reference

| Verdict | Meaning |
|----------|----------|
| **VULNERABLE** | Endpoint accessible without valid authentication headers. |
| **SAFE / AUTH_ENFORCED** | Authentication properly required (401/403). |
| **SUSPICIOUS** | Unusual redirect or unexpected response detected. |
| **INPUT_ERROR / ROUTING_ERROR** | Minor client-side issues possibly related to weak auth checks. |
| **SERVER_ERROR** | Backend error encountered during testing. |

---

## 🧩 Exporting Results

**CSV Export**
- Saves output as `brokenauth_results.csv` in the user’s home directory.  
- Contains the following columns:

| Column | Description |
|---------|--------------|
| Endpoint | Full URL tested |
| Method | HTTP method used |
| Mode | Remove All / Strip All |
| Status | Response status code |
| Verdict | Auth test result |
| Risk | Computed risk score (0–100) |
| Details | Summary of test findings |

---

## ⚙️ Installation

1. **Install Jython**
   - Download `jython-standalone-2.7.x.jar`.
   - In Burp: `Extender → Options → Python Environment → Select File`.

2. **Load the Extension**
   - Save this script as `BrokenAuthPro.py`.
   - In Burp: `Extender → Extensions → Add`  
     - Type: **Python**  
     - File: `BrokenAuthPro.py`

3. **Verify Installation**
   - A new tab **“BrokenAuth Pro”** will appear in Burp Suite.

---

## 🧪 Use Cases

- Identify missing authentication checks on APIs or web endpoints.  
- Detect endpoints that allow access after token removal.  
- Validate session control implementation in large web applications.  
- Support CI/CD validation of auth logic consistency.

---

## 🪪 Requirements

- **Burp Suite (Community or Professional)**  
- **Jython 2.7.x**  
- **No additional dependencies required**  

---

## 👤 Author

**Narendra Reddy (Entersoft Security)**  
