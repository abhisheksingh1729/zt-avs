# IIIT Dharwad — Zero-Trust Attendance Verification System (ZT-AVS)

A production-grade, zero-trust student attendance platform built for **IIIT Dharwad** (`@iiitdwd.ac.in`) using **Python, Streamlit, and SQLite**. Designed to eliminate proxy attendance through multi-layered zero-trust verification: rolling dynamic projector OTPs, enrolled biometric confirmation, real-time campus network attestation, and client-side browser tab-visibility tamper guards.

---

## 🏛️ System Architecture & Zero-Trust Principles

```
+-----------------------------------------------------------------------------------+
|                           IIIT Dharwad Network Perimeter                          |
+-----------------------------------------------------------------------------------+
       │                                                              │
       ▼                                                              ▼
[ Professor Portal ]                                         [ Student Portal ]
  • Course Management (Classroom Join Codes)                   • Auto-Identity Pre-fill
  • 15s Rolling Dynamic Projector OTP (5-char)                 • 15s Rolling Code Validation
  • Real-Time Interactive Roster                              • Biometric Fingerprint Passkey
  • st.data_editor Overrides & .xlsx Export                   • Anti-Proxy Tab-Switch Guard
       │                                                              │
       └─────────────────────────┬────────────────────────────────────┘
                                 ▼
                     [ SQLite Database Layer ]
         • users (RBAC & SHA-256 Fingerprint Hashes)
         • courses & enrollments (Classroom Model)
         • attendance_sessions (Rolling OTP Expiries)
         • attendance_records & tamper_logs
```

### Zero-Trust Verification Pipeline
1. **Implicit Trust Elimination:** Merely logging into the portal does not grant attendance.
2. **Auto-Identity Pre-Fill:** Session email locks name and roll number (e.g. `25bcs053@iiitdwd.ac.in` → `25BCS053`).
3. **15-Second Ephemeral Projector Code:** Dynamic 5-character OTP rotating every 15s (`st.fragment(run_every=1)`). Screenshots and relayed codes expire before they can be exploited.
4. **Enrolled Biometric Confirmation:** SHA-256 passkey confirmed against enrollment record.
5. **Anti-Proxy Visibility Guard:** Browser `visibilitychange` & `window.blur` API detects if student switches tabs or minimizes the window to share OTP codes on messaging apps. If detected, the session is terminated and logged.
6. **Network & Spatial Attestation:** Confirms connection to the campus academic subnet (`10.12.*.*`) and spatial bounds.

---

## 🚀 Quickstart & Local Setup

### 1. Prerequisites
- Python 3.10+ (Tested on Python 3.10 – 3.15)
- Git

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

### 3. Run the Streamlit Application
```bash
python -m streamlit run app.py
# or
streamlit run app.py
```
The app will launch at `http://localhost:8501`. SQLite database (`attendance.db`) will auto-initialize on first run with seeded demo personas and courses.

---

## 🧪 Multi-Role Testing Walkthrough (Simultaneous Multi-Tab)

To test the zero-trust workflow live during an evaluation or presentation, open **two separate browser contexts** (e.g., standard browser window + Incognito window, or Chrome + Firefox):

### Persona Credentials (Mock Login OTP: `1234`)
| Role | Email Address | Mapped Portal |
| :--- | :--- | :--- |
| **Professor** | `prof.os@iiitdwd.ac.in` | **Professor Management Portal** |
| **Student** | `25bcs053@iiitdwd.ac.in` | **Student Attendance Portal** (Roll: `25BCS053`) |
| **Admin** | `admin@iiitdwd.ac.in` | **Institute Admin Oversight Portal** |

### Step-by-Step Demonstration Flow
1. **Window A (Professor Window):**
   - Click **"👨‍🏫 Professor Demo"** or enter `prof.os@iiitdwd.ac.in`.
   - Enter mock OTP `1234`.
   - Open **"CS301 — Operating Systems"**.
   - Click **"🚀 Initialize Attendance"**.
   - The screen projects a large 5-character OTP that dynamically refreshes with a 15-second countdown progress bar.
2. **Window B (Student Window - Incognito):**
   - Click **"🎓 Student Demo"** or enter `25bcs053@iiitdwd.ac.in`.
   - Enter mock OTP `1234`.
   - Observe the immediate live banner: `⚠️ Attendance is initialized for CS301 — Operating Systems!`.
   - Click **"Mark Attendance"**.
   - Note the auto-prefilled Name and Roll Number (`25BCS053`).
   - Enter the current 5-character OTP from Window A.
   - Enter the student biometric token (demo default: `bio_key_053`).
   - Click **"Submit Zero-Trust Attendance"**.
   - Visual celebration (balloons) and confirmed Present mark!
3. **Anti-Proxy Tamper Demonstration:**
   - In Student portal, click Mark Attendance on another session.
   - Switch to another browser tab or minimize window (triggering `visibilitychange`).
   - Return to the tab: observe the immediate red **ZERO-TRUST SECURITY BREACH: SESSION TERMINATED** warning and logged event.
4. **Attendance Review & Excel Export (Professor Window):**
   - In Window A, review the real-time attendance roster.
   - Use `st.data_editor` to manually toggle any student status (1/0). Click **"Save Manual Overrides"**.
   - Click **"📥 Download Session Report (.xlsx)"** to export the official clean session attendance list.

---

## 📊 Database Schema (SQLite)

- **`users`**: `email` (PK), `name`, `role`, `roll_number`, `fingerprint_hash`, `created_at`
- **`courses`**: `course_id` (PK), `course_name`, `professor_email`, `join_code`, `created_at`
- **`enrollments`**: `course_id`, `student_email`, `joined_at`
- **`attendance_sessions`**: `session_id` (PK), `course_id`, `date`, `is_active`, `current_otp`, `otp_expires_at`, `network_ssid`, `created_at`
- **`attendance_records`**: `session_id`, `student_email`, `status` (1/0), `marked_at`, `device_info`
- **`tamper_logs`**: `log_id` (PK), `session_id`, `student_email`, `reason`, `detected_at`

---

## 📄 License
This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
