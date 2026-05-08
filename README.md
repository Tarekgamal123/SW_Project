```markdown
# SIEM - Security Information and Event Management System

A modern **Log Analysis and Threat Detection** web application built with Python and Flask.

---

## 🌟 Features

- Upload and parse log files (`.log`, `.txt`, `.csv`)
- Manual log entry
- Intelligent Threat Detection Rules
- Real-time-ish alerts generation
- Beautiful Arabic/RTL responsive interface
- Device tracking and activity monitoring
- Advanced search & filtering (IP, Status, Date Range)
- Auto-refresh dashboard
- User authentication system

---

## 🛠️ Technologies Used

- **Backend**: Python + Flask
- **Database**: SQLite + SQLAlchemy (ORM)
- **Frontend**: HTML5, CSS3, Jinja2
- **Forms**: Flask-WTF
- **Authentication**: Flask-Login
- **Styling**: Modern Glassmorphism Design + Cairo Font

---

## 🚀 Quick Start

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

### 2. Run the Application

```bash
python run.py
```

Or

```bash
python app.py
```

### 3. Access the System

- **URL**: `http://127.0.0.1:5000`
- **Default Login**:
  - **Username**: `admin`
  - **Password**: `admin123`

---

## 📋 Available Pages

| Page                    | Description |
|------------------------|-----------|
| **Dashboard**          | Overview, statistics, recent alerts & top attackers |
| **Upload Logs**        | Upload and analyze log files |
| **Submit Log**         | Add logs manually |
| **Logs**               | View all logs with advanced filters |
| **Alerts**             | View generated security alerts |
| **Devices**            | Monitor all detected devices/IPs |

---

## 🔍 Detection Rules

- **Brute Force Detection** (5+ failed attempts in 60 seconds)
- **Blacklisted IP** detection
- **Successful Login After Failures**
- **Web Probing / Scanning** (`/wp-login`, `/.env`, `/admin`, etc.)

---

## 📁 Project Structure

```
SIEM-Project/
├── app.py
├── run.py
├── config.py
├── models.py
├── forms.py
├── rules.py
├── utils.py
├── auth.py
├── threat_intel.py
├── requirements.txt
├── siem.db
├── uploads/
├── templates/
│   ├── index.html
│   ├── logs.html
│   ├── alerts.html
│   └── ...
└── README.md
```

---

## 🛠️ Future Improvements

- Support for PostgreSQL / MySQL
- Real-time log ingestion (Syslog, Filebeat, etc.)
- Machine Learning based anomaly detection
- PDF/CSV report export
- Advanced user roles and permissions
- Redis caching for rate limiting

---

## 👨‍💻 Developer

**Developed by**: [SW_Team]  
**Purpose**: Educational & Practical SIEM System

---

**⭐ If you like this project, don't forget to star it on GitHub!**

```

---

**Ready to use!**
