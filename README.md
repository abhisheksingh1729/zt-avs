# IIIT Dharwad — Zero-Trust Attendance Verification System (ZT-AVS)

A production-grade, zero-trust student attendance and identity verification platform built for **IIIT Dharwad** (`@iiitdwd.ac.in`) using **Python, Streamlit, OpenCV, and SQLite (WAL mode)**.

Designed to eliminate proxy attendance through multi-layered zero-trust verification: **15-second dynamic rolling projector OTPs**, **OpenCV facial biometric recognition**, **salted SHA-256 passkey attestation**, **campus network subnet validation (`10.12.*.*`)**, and **browser-level tab-switch anti-proxy guards (`visibilitychange` API)**.

---

## 🏛️ System Architecture & Zero-Trust Principles

```
+-----------------------------------------------------------------------------------+
|                        IIIT Dharwad Campus Perimeter (10.12.*.*)                  |
+-----------------------------------------------------------------------------------+
       │                                                              │
       ▼                                                              ▼
[ Professor Portal ]                                         [ Student Portal ]
  • Course Management (6-char Join Codes)                      • Auto-Identity Pre-fill (Read-only)
  • 15s Rolling Dynamic Projector OTP (5-char)                 • 15s Dynamic Rolling OTP Validation
  • Real-Time Interactive Roster                              • OpenCV Facial Biometric Verification
  • st.data_editor Overrides & .xlsx Export                   • Anti-Proxy Tab-Switch Guard
       │                                                              │
       └─────────────────────────┬────────────────────────────────────┘
                                 ▼
                     [ SQLite Database Layer ]
         • users (RBAC, 256-D Facial Vectors & SHA-256 Hashes)
         • email_otps (Cryptographic OTPs with TTL)
         • courses & enrollments (Classroom Model)
         • attendance_sessions (Rolling OTP Expiries)
         • attendance_records & tamper_logs
```

### Zero-Trust Verification Pipeline
1. **Implicit Trust Elimination:** Merely authenticating into the portal does not grant attendance.
2. **Auto-Identity Pre-Fill:** Session email locks name and roll number (e.g. `25bcs053@iiitdwd.ac.in` $\rightarrow$ `25BCS053`).
3. **15-Second Ephemeral Projector Code:** Dynamic 5-character OTP rotating every 15s (`st.fragment(run_every=1)`). Relayed screenshots expire before they can be exploited.
4. **OpenCV Facial Biometrics:** Built-in Haar Cascade face detector extracts a 256-dimensional normalized facial feature vector from a live webcam capture, verifying cosine similarity ($\ge 65\%$) against the enrolled facial biometric template.
5. **Anti-Proxy Visibility Guard:** Browser `visibilitychange` & `window.blur` API detects if student switches tabs or minimizes the window to message codes. If detected, the session is terminated and logged.
6. **Network & Spatial Attestation:** Confirms connection to the campus academic subnet (`10.12.4.x`) and spatial classroom boundary.
7. **Adaptive Theme Engine:** Clean, high-contrast **Light Theme** by default with an instant **Dark Mode** toggle.

---

## 🚀 Quickstart & Local Setup

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.10 – 3.15)
- Git & Webcam (for facial biometric verification)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/abhisheksingh1729/zt-avs.git
cd zt-avs

# Optional: Create and activate a virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\activate
# Linux/macOS:
source .venv/bin/activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Run the Application
```bash
python -m streamlit run app.py
# or
streamlit run app.py
```
Open [http://localhost:8501](http://localhost:8501) in your browser.

---

## 🧪 Multi-Role Testing Walkthrough (Simultaneous Multi-Tab)

Open **two separate browser windows** (e.g., standard browser window + Incognito window, or Chrome + Edge):

### Portal Access Guide
| Portal | Email Address | Authentication |
| :--- | :--- | :--- |
| **Professor Portal** | `prof.os@iiitdwd.ac.in` | Real-time OTP dispatched via Institute Gateway |
| **Student Portal** | `25bcs053@iiitdwd.ac.in` | Real-time OTP dispatched via Institute Gateway |
| **Admin Portal** | `admin@iiitdwd.ac.in` | Real-time OTP dispatched via Institute Gateway |

### Step-by-Step Demonstration Flow
1. **Window A (Professor Window):**
   - Click **"👨‍🏫 Professor Account"** (or enter `prof.os@iiitdwd.ac.in`).
   - Click **Request Security OTP**. Copy the generated 6-digit verification code from the gateway display and authenticate.
   - Open **"CS301 — Operating Systems"**.
   - Click **"🚀 Initialize Attendance"**.
   - The screen projects a large 5-character OTP that dynamically refreshes with a 15-second countdown progress bar.
2. **Window B (Student Window - Incognito):**
   - Click **"🎓 Student Account"** (or enter `25bcs053@iiitdwd.ac.in`).
   - Request and enter the 6-digit OTP to authenticate.
   - Observe the live banner: `⚠️ Attendance is initialized for CS301 — Operating Systems!`.
   - Click **"Mark Attendance"**.
   - Note the auto-prefilled Name and Roll Number (`25BCS053`).
   - Enter the current 5-character OTP from Window A.
   - Complete facial verification via webcam (`st.camera_input`) or enter the passkey (`bio_key_053`).
   - Click **"Submit Zero-Trust Attendance"** $\rightarrow$ verified and marked Present!
3. **Anti-Proxy Tamper Demonstration:**
   - On the student attendance screen, switch to another browser tab or minimize the window.
   - Return: observe the immediate red **ZERO-TRUST SECURITY BREACH: SESSION TERMINATED** warning and logged event.
4. **Attendance Review & Excel Export (Professor Window):**
   - In Window A, review the real-time attendance roster with Face Match % and Verification Mode.
   - Use `st.data_editor` to manually toggle any student status (1/0). Click **"Save Manual Overrides"**.
   - Click **"📥 Download Session Report (.xlsx)"** to export the official session attendance list.

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
