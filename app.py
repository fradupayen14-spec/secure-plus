from flask import (
    Flask, request, redirect, url_for,
    session, render_template_string, Response
)
from urllib.parse import urlparse
from ipaddress import ip_address
from datetime import datetime
from functools import wraps
import re
import os
import csv
import io
from functools import wraps
import re
import os

app = Flask(__name__)
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY", "change-this-demo-secret"
)

# Demo credentials. Change before real deployment.
DEMO_USER = "admin"
DEMO_PASSWORD = "Admin@123"

scans = []
alerts = []

CSV_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "scan_history.csv"
)

def save_scan_to_csv(scan):
    needs_header = (
        not os.path.isfile(CSV_FILE)
        or os.path.getsize(CSV_FILE) == 0
    )

    with open(CSV_FILE, "a", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)

        if needs_header:
            writer.writerow([
                "Target", "Type", "Risk",
                "Score", "Reasons", "Scanned At"
            ])

        writer.writerow([
            scan.get("target", ""),
            scan.get("type", ""),
            scan.get("risk", ""),
            scan.get("score", ""),
            "; ".join(scan.get("reasons", [])),
            scan.get("time", "")
        ])

PAGE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SecurePulse | Cyber Risk Protection</title>
<style>
:root {
  --bg:#071225; --panel:#0d1b33; --panel2:#10213d; --border:#203858;
  --text:#e8f0ff; --muted:#8da4c7; --blue:#1687ff; --cyan:#39c8ff;
  --green:#29d6a0; --yellow:#ffc857; --red:#ff647c;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(ellipse at 75% 0%,#102b50 0%,var(--bg) 42%);color:var(--text);font-family:Inter,Segoe UI,Arial,sans-serif;line-height:1.5}
a{color:#62c8ff;text-decoration:none}
a:hover{color:#fff}
.layout{
    display: flex;
    min-height: 100vh;
    width: 100%;
}
.sidebar{position:fixed;inset:0 auto 0 0;width:240px;padding:26px 16px;background:#08162b;border-right:1px solid var(--border);display:flex;flex-direction:column;gap:26px;z-index:5}
.brand{display:flex;align-items:center;gap:10px;padding:0 10px 18px;border-bottom:1px solid #1a2d49}
.brand-mark{width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,#167cff,#22d3ee);display:grid;place-items:center;font-size:20px;font-weight:800;color:white;box-shadow:0 8px 28px #087cff35}
.brand-name{font-size:20px;font-weight:800;letter-spacing:-.5px}.brand-name span{color:var(--cyan)}
.brand-sub{font-size:11px;color:var(--muted);letter-spacing:.4px}
.nav-label{font-size:10px;text-transform:uppercase;letter-spacing:1.6px;color:#647da4;padding:0 12px;margin-bottom:-14px}
nav{display:flex;flex-direction:column;gap:7px}
nav a{display:flex;align-items:center;gap:12px;padding:12px 13px;border-radius:10px;color:#a8bbd9;font-size:14px;font-weight:600;transition:.18s}
nav a:hover,nav a.active{background:linear-gradient(90deg,#0e4ea5,#103568);color:#fff}
.nav-icon{width:22px;text-align:center;font-size:17px}
.sidebar-foot{margin-top:auto;border:1px solid var(--border);background:#0c203a;border-radius:12px;padding:14px;font-size:12px;color:var(--muted)}
.sidebar-foot strong{display:block;color:#dceaff;font-size:13px;margin-bottom:4px}
.workspace{margin-left:240px;min-width:0}
.topbar{height:82px;display:flex;align-items:center;justify-content:space-between;gap:18px;padding:18px 34px;border-bottom:1px solid #1a2d49;background:#07152bd9}
.top-title{font-size:18px;font-weight:700}.top-sub{font-size:12px;color:var(--muted)}
.user-pill{border:1px solid var(--border);border-radius:999px;padding:8px 13px;color:#c8d8f0;font-size:12px;white-space:nowrap}
main{max-width:1500px;margin:0 auto;padding:30px 34px 40px}
h1{font-size:28px;letter-spacing:-.7px;margin:0 0 5px;color:#f2f7ff}
h2{font-size:19px;margin:0 0 16px}h3{font-size:14px;margin:0 0 10px}
.muted{color:var(--muted);font-size:13px}
.card{background:linear-gradient(145deg,#10213b,#0b1a31);padding:23px;margin:18px 0;border-radius:15px;border:1px solid var(--border);box-shadow:0 12px 35px #00000012}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:15px}
.metric{position:relative;overflow:hidden;min-height:135px;padding:19px;background:linear-gradient(145deg,#112541,#0b1a31);border:1px solid var(--border);border-radius:14px}
.metric:after{content:"";position:absolute;width:100px;height:100px;right:-40px;top:-45px;border-radius:50%;background:#1687ff12}
.metric-label{font-size:12px;color:#9bb0ce}.metric-value{font-size:31px;font-weight:750;letter-spacing:-1px;margin-top:9px}.metric-icon{width:34px;height:34px;border-radius:10px;display:grid;place-items:center;background:#1687ff20;color:var(--cyan);font-size:17px;margin-bottom:12px}
.metric.green .metric-icon{background:#29d6a01c;color:var(--green)}.metric.yellow .metric-icon{background:#ffc8571c;color:var(--yellow)}.metric.red .metric-icon{background:#ff647c1c;color:var(--red)}
.dashboard-grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(260px,1fr);gap:18px;align-items:start}
.scan-hero{padding:26px;background:linear-gradient(120deg,#102c53,#0d1d39 70%);border:1px solid #1b4b7e;border-radius:16px;margin:20px 0}
.eyebrow{color:var(--cyan);font-size:11px;font-weight:800;letter-spacing:1.7px;text-transform:uppercase;margin-bottom:10px}
.scan-form{display:flex;gap:10px;margin-top:20px}.scan-form input{flex:1;min-width:0}
input{width:100%;padding:13px 14px;margin:6px 0;border-radius:9px;border:1px solid #294363;background:#07152b;color:white;font-size:14px;outline:none}
input:focus{border-color:var(--blue);box-shadow:0 0 0 3px #1687ff20}
button,.btn{display:inline-flex;align-items:center;justify-content:center;padding:12px 17px;border:0;border-radius:9px;background:linear-gradient(135deg,#1687ff,#0866db);color:white;font-size:13px;font-weight:700;cursor:pointer;white-space:nowrap}
button:hover,.btn:hover{filter:brightness(1.1);color:#fff}
table{width:100%;border-collapse:collapse;font-size:12px}th{text-align:left;color:#7f9bc0;font-size:10px;text-transform:uppercase;letter-spacing:.8px;background:#0a1830;padding:13px 11px}td{padding:14px 11px;border-bottom:1px solid #1c304d;color:#d5e2f6}tr:last-child td{border-bottom:0}.target{max-width:280px;overflow-wrap:anywhere;color:#b8d8ff}
.badge{display:inline-block;border-radius:999px;padding:4px 9px;font-size:10px;font-weight:800}.badge.safe{color:var(--green);background:#29d6a018}.badge.medium{color:var(--yellow);background:#ffc8571c}.badge.high{color:var(--red);background:#ff647c1c}.badge.info{color:var(--cyan);background:#39c8ff18}
.safe{color:var(--green)}.risk{color:var(--red)}.section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:14px}.section-head h2{margin:0}
.quick-action{display:flex;gap:12px;align-items:center;padding:13px;margin-top:10px;border:1px solid var(--border);border-radius:11px;background:#0a1a32;color:#dce9ff}.quick-action:hover{border-color:#247bd2;background:#102747}.qa-icon{width:35px;height:35px;display:grid;place-items:center;border-radius:10px;background:#1687ff20;color:var(--cyan);font-size:17px}.quick-action small{display:block;color:var(--muted);font-size:11px;margin-top:2px}
form label{display:block;font-size:13px;color:#b9cbe5;margin-top:12px}
ul{padding-left:21px}li{margin:7px 0;color:#c5d5ec}
footer{border-top:1px solid #1a2d49;padding:18px 34px;color:#637b9f;font-size:11px}
@media(max-width:1050px){.sidebar{width:205px}.workspace{margin-left:205px}main{padding:24px 20px}.topbar{padding:16px 20px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.dashboard-grid{grid-template-columns:1fr}}
@media(max-width:700px){.sidebar{position:static;width:auto;padding:14px;gap:14px}.brand{padding-bottom:12px}.nav-label,.sidebar-foot{display:none}nav{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:5px}nav a{justify-content:center;padding:10px 5px;font-size:11px;gap:5px;flex-direction:column}.workspace{margin-left:0}.topbar{height:auto;padding:14px 18px}main{padding:20px 14px}.grid{grid-template-columns:repeat(2,minmax(0,1fr))}.card{padding:17px}.scan-form{flex-direction:column}.scan-form button{width:100%}.table-wrap{overflow-x:auto}table{min-width:650px}h1{font-size:24px}}
@media(max-width:390px){.grid{grid-template-columns:1fr}}
/* Force SecurePulse sidebar into vertical layout */
.layout > aside.sidebar {
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    bottom: 0 !important;
    width: 240px !important;
    display: flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
    box-sizing: border-box !important;
    z-index: 100 !important;
}

.layout > aside.sidebar > nav {
    display: flex !important;
    flex-direction: column !important;
    align-items: stretch !important;
    width: 100% !important;
}

.layout > aside.sidebar > nav > a {
    width: 100% !important;
    flex-direction: row !important;
    box-sizing: border-box !important;
}

.risk-distribution {
  margin-bottom: 22px;
}

.risk-circles {
  display: flex;
  justify-content: space-around;
  align-items: center;
  gap: 24px;
  flex-wrap: wrap;
  padding: 24px 8px 12px;
}

.risk-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 12px;
}

.risk-donut {
  --ring-color: #29d6a0;
  width: 132px;
  height: 132px;
  border-radius: 50%;
  display: grid;
  place-items: center;
  background: conic-gradient(
    var(--ring-color) var(--percent),
    #203858 0
  );
}

.low-donut { --ring-color: #29d6a0; }
.medium-donut { --ring-color: #ffc857; }
.high-donut { --ring-color: #ff647c; }

.donut-center {
  width: 96px;
  height: 96px;
  border-radius: 50%;
  background: #0d1b33;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
}

.donut-center strong {
  color: #e8f0ff;
  font-size: 26px;
}

.donut-center small {
  color: #8da4c7;
  font-size: 12px;
}

.risk-label {
  font-size: 14px;
  font-weight: 600;
}

.low-label { color: #29d6a0; }
.medium-label { color: #ffc857; }
.high-label { color: #ff647c; }
</style>
</head>
<body>
<div class="layout">
<aside class="sidebar">
  <div class="brand">
    <div class="brand-mark">
      <svg xmlns="http://www.w3.org/2000/svg"
           width="30" height="30" viewBox="0 0 24 24"
           fill="none" stroke="currentColor"
           stroke-width="2" stroke-linecap="round"
           stroke-linejoin="round" aria-hidden="true">
        <path d="M12 22s8-4 8-11V5l-8-3-8 3v6c0 7 8 11 8 11z"/>
        <path d="m9 12 2 2 4-4"/>
      </svg>
    </div>
    <div>
      <div class="brand-name">Secure<span>Pulse</span></div>
      <div class="brand-sub">SCAN · DETECT · STAY SAFE</div>
    </div>
  </div>
  <div class="nav-label">Workspace</div>
  <nav>
    <a href="{{ url_for('dashboard') }}" class="{{ 'active' if request.endpoint == 'dashboard' else '' }}"><span class="nav-icon">▦</span>Dashboard</a>
    <a href="{{ url_for('url_scan') }}" class="{{ 'active' if request.endpoint == 'url_scan' else '' }}"><span class="nav-icon">↗</span>Scan URL</a>
    <a href="{{ url_for('history') }}" class="{{ 'active' if request.endpoint == 'history' else '' }}"><span class="nav-icon">◷</span>Scan History</a>
    <a href="{{ url_for('ip_scan') }}" class="{{ 'active' if request.endpoint == 'ip_scan' else '' }}"><span class="nav-icon">⌘</span>IP Analysis</a>
    <a href="{{ url_for('threats') }}" class="{{ 'active' if request.endpoint == 'threats' else '' }}"><span class="nav-icon">⚑</span>Threat Alerts</a>
    <a href="{{ url_for('export_csv') }}"><span class="nav-icon">⇩</span>Export CSV</a>
    <a href="{{ url_for('logout') }}"><span class="nav-icon">↪</span>Logout</a>
  </nav>
  <div class="sidebar-foot"><strong>◈ Digital Risk Protection</strong>Safer links. Smarter decisions.</div>
</aside>
<div class="workspace">
<header class="topbar"><div><div class="top-title">Security Operations</div><div class="top-sub">Website risk monitoring and analysis</div></div><div class="user-pill">● &nbsp; SecurePulse Workspace</div></header>
<main>{{ content|safe }}</main>
<footer>SecurePulse · Cyber Risk Protection · Educational prototype</footer>
</div>
</div>
</body>
</html>
"""

def login_required(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


def page(content, **context):
    return render_template_string(
        PAGE, content=render_template_string(
            content, **context
        )
    )

@app.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == DEMO_USER and password == DEMO_PASSWORD:
            session.clear()
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        message = "Invalid username or password"

    return page("""
    <div class="card">
      <h1>Digital Risk Protection</h1>
      <h2>Login</h2>
      <p class="risk">{{ message }}</p>
      <form method="post">
        <label>Username</label>
        <input name="username" required>
        <label>Password</label>
        <input name="password" type="password" required>
        <button type="submit">Login</button>
      </form>
      <p class="muted">Demo username: admin</p>
      <p class="muted">Demo password: Admin@123</p>
    </div>
    """, message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    safe = sum(s.get("risk") in ["Safe", "Low"] for s in scans)
    medium = sum(s.get("risk") in ["Medium", "Moderate"] for s in scans)
    high = sum(s.get("risk") == "High" for s in scans)
    recent = scans[:5]

    return page("""
    <div class="section-head">
      <div>
        <div class="eyebrow">SECURITY OVERVIEW</div>
        <h1>Good to see you again</h1>
        <p class="muted">Review scan activity, identify risk indicators, and protect your digital presence.</p>
      </div>
      <a class="btn" href="{{ url_for('url_scan') }}">＋ New URL Scan</a>
    </div>

    <section class="scan-hero">
      <div class="eyebrow">SECUREPULSE URL INTELLIGENCE</div>
      <h2 style="font-size:25px;margin-bottom:8px">Detect. Analyse. Stay protected.</h2>
      <p class="muted">Check a website URL for suspicious patterns and common phishing indicators.</p>
      <form class="scan-form" method="post" action="{{ url_for('url_scan') }}">
        <input name="url" type="url" placeholder="https://example.com" aria-label="Website URL" required>
        <button type="submit">Scan URL &nbsp; →</button>
      </form>
      <p class="muted" style="margin-bottom:0">Tip: enter a full URL or a domain you want to inspect.</p>
    </section>

    <div class="grid">
      <div class="metric"><div class="metric-icon">↗</div><div class="metric-label">Total Scans</div><div class="metric-value">{{ total }}</div></div>
      <div class="metric green"><div class="metric-icon">✓</div><div class="metric-label">Low / Safe Risk</div><div class="metric-value">{{ safe }}</div></div>
      <div class="metric yellow"><div class="metric-icon">⚠</div><div class="metric-label">Medium Risk</div><div class="metric-value">{{ medium }}</div></div>
      <div class="metric red"><div class="metric-icon">!</div><div class="metric-label">High Risk</div><div class="metric-value">{{ high }}</div></div>
    </div>

<section class="card risk-distribution">
  <h2>Risk Distribution</h2>

  <div class="risk-circles">
    <div class="risk-item">
      <div class="risk-donut low-donut"
           style="--percent: {{ (safe * 100 / (safe + medium + high)) if (safe + medium + high) else 0 }}%">
        <div class="donut-center">
          <strong>{{ safe }}</strong>
          <small>Scans</small>
        </div>
      </div>
      <span class="risk-label low-label">Low Risk</span>
    </div>

    <div class="risk-item">
      <div class="risk-donut medium-donut"
           style="--percent: {{ (medium * 100 / (safe + medium + high)) if (safe + medium + high) else 0 }}%">
        <div class="donut-center">
          <strong>{{ medium }}</strong>
          <small>Scans</small>
        </div>
      </div>
      <span class="risk-label medium-label">Medium Risk</span>
    </div>

    <div class="risk-item">
      <div class="risk-donut high-donut"
           style="--percent: {{ (high * 100 / (safe + medium + high)) if (safe + medium + high) else 0 }}%">
        <div class="donut-center">
          <strong>{{ high }}</strong>
          <small>Scans</small>
        </div>
      </div>
      <span class="risk-label high-label">High Risk</span>
    </div>
  </div>
</section>
<div class="dashboard-grid">
      <section class="card">
        <div class="section-head"><h2>Recent Scan History</h2><a href="{{ url_for('history') }}">View all →</a></div>
        {% if recent %}
        <div class="table-wrap"><table>
          <thead><tr><th>Target</th><th>Type</th><th>Risk level</th><th>Score</th><th>Scanned at</th></tr></thead>
          <tbody>
          {% for item in recent %}
          <tr>
            <td class="target">{{ item.target }}</td>
            <td>{{ item.type or 'URL' }}</td>
            <td><span class="badge {{ 'high' if item.risk == 'High' else 'medium' if item.risk in ['Medium','Moderate'] else 'safe' if item.risk in ['Safe','Low'] else 'info' }}">{{ item.risk }}</span></td>
            <td>{{ item.score if item.score is defined else '—' }}</td>
            <td>{{ item.time or '—' }}</td>
          </tr>
          {% endfor %}
          </tbody>
        </table></div>
        {% else %}
        <p class="muted">No scans yet. Run your first URL scan to populate this table.</p>
        {% endif %}
      </section>
      <aside>
        <section class="card">
          <h2>Quick Actions</h2>
          <a class="quick-action" href="{{ url_for('url_scan') }}"><span class="qa-icon">↗</span><span>Scan Website URL<small>Check suspicious URL patterns</small></span></a>
          <a class="quick-action" href="{{ url_for('ip_scan') }}"><span class="qa-icon">⌘</span><span>Analyse IP Address<small>Validate IPv4 or IPv6 format</small></span></a>
          <a class="quick-action" href="{{ url_for('threats') }}"><span class="qa-icon">⚑</span><span>Threat Alerts<small>Review high-risk scan findings</small></span></a>
        </section>
        <section class="card">
          <h2>Risk Level Guide</h2>
          <p><span class="badge high">HIGH</span> &nbsp; <span class="muted">Multiple configured risk indicators</span></p>
          <p><span class="badge medium">MEDIUM</span> &nbsp; <span class="muted">One or more indicators detected</span></p>
          <p><span class="badge safe">LOW</span> &nbsp; <span class="muted">No configured indicators found</span></p>
          <p class="muted">A low score does not guarantee a website is safe. Results are heuristic only.</p>
        </section>
      </aside>
    </div>
    """,
    total=len(scans),
    safe=safe,
    medium=medium,
    high=high,
    recent=recent)

def analyse_url(value):
    value = value.strip()

    parsed = urlparse(
        value if "://" in value else "https://" + value
    )

    host = parsed.hostname

    if (
        not host
        or "." not in host
        or any(c.isspace() for c in value)
        or parsed.scheme not in ("http", "https")
    ):
        return None

    host = host.lower().rstrip(".")
    score = 0
    reasons = []

    # Identify popular social platforms
    platforms = {
        "instagram.com": "Instagram",
        "facebook.com": "Facebook",
        "fb.com": "Facebook",
        "fb.watch": "Facebook Watch",
        "youtube.com": "YouTube",
        "youtu.be": "YouTube",
        "tiktok.com": "TikTok",
        "linkedin.com": "LinkedIn",
        "x.com": "X (Twitter)",
        "twitter.com": "X (Twitter)",
        "reddit.com": "Reddit",
        "pinterest.com": "Pinterest",
        "snapchat.com": "Snapchat",
        "threads.net": "Threads",
        "twitch.tv": "Twitch",
        "t.me": "Telegram",
        "telegram.me": "Telegram",
        "whatsapp.com": "WhatsApp",
        "discord.com": "Discord",
        "github.com": "GitHub",
    }

    platform = "Other Website"

    for domain, name in platforms.items():
        if host == domain or host.endswith("." + domain):
            platform = name
            break

    # Detect possible lookalike domains
    brand_domains = {
        "instagram": "Instagram",
        "facebook": "Facebook",
        "youtube": "YouTube",
        "tiktok": "TikTok",
        "linkedin": "LinkedIn",
        "twitter": "X (Twitter)",
        "pinterest": "Pinterest",
        "snapchat": "Snapchat",
        "reddit": "Reddit",
    }

    if platform == "Other Website":
        labels = host.split(".")

        for brand, name in brand_domains.items():
            if any(brand in label for label in labels):
                score += 2
                reasons.append(
                    f"Possible {name} lookalike domain"
                )
                break

    # URL-based risk indicators
    if parsed.scheme != "https":
        score += 1
        reasons.append("HTTPS is not used")

    if "@" in parsed.netloc:
        score += 2
        reasons.append("URL contains an @ symbol")

    if len(value) > 100:
        score += 1
        reasons.append("Unusually long URL")

    if host.count("-") >= 3:
        score += 1
        reasons.append("Multiple hyphens in hostname")

    if re.search(
        r"(login|verify|secure|account|update|password)",
        value,
        re.I,
    ):
        score += 1
        reasons.append(
            "Contains a sensitive-action keyword"
        )

    if re.fullmatch(
        r"\d{1,3}(?:\.\d{1,3}){3}",
        host,
    ):
        score += 2
        reasons.append(
            "Uses an IP address as the website host"
        )

    level = (
        "High" if score >= 3
        else "Medium" if score >= 1
        else "Low"
    )

    if not reasons:
        reasons.append(
            "No configured suspicious URL patterns found"
        )

    return {
        "target": value,
        "platform": platform,
        "risk": level,
        "score": score,
        "reasons": reasons,
    }

@app.route("/scan", methods=["GET", "POST"])
@login_required
def url_scan():
    result = None
    error = ""
    if request.method == "POST":
        value = request.form.get("url", "")
        result = analyse_url(value)
        if result is None:
            error = "Enter a valid domain or website URL."
        else:
            result["type"] = "URL"
            result["time"] = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            scans.insert(0, result)
            save_scan_to_csv(result)
            if result["risk"] == "High":
                alerts.insert(0, result.copy())

    return page("""
    <h1>Website Risk Scanner</h1>
    <div class="card">
      <form method="post">
        <label>Website URL</label>
        <input name="url" placeholder="https://example.com" required>
        <button type="submit">Analyse URL</button>
      </form>
      <p class="risk">{{ error }}</p>
    </div>
    {% if result %}
    <div class="card">
      <h2>Risk: <span class="{{ 'risk' if result.risk == 'High'
        else 'safe' }}">{{ result.risk }}</span></h2>
      <p>Risk score: {{ result.score }}</p>
      <p><strong>Platform:</strong> {{ result.platform }}</p>
      <h3>Indicators</h3>
      <ul>{% for reason in result.reasons %}
        <li>{{ reason }}</li>
      {% endfor %}</ul>
      <p class="muted">Heuristic result only; not a confirmed
      phishing verdict.</p>
    </div>
    {% endif %}
    """, result=result, error=error)


@app.route("/ip", methods=["GET", "POST"])
@login_required
def ip_scan():
    result = None
    error = ""
    if request.method == "POST":
        value = request.form.get("ip", "").strip()
        try:
            addr = ip_address(value)
            result = {
                "target": str(addr),
                "version": addr.version,
                "scope": "Private" if addr.is_private else "Public",
                "valid": True
            }
            item = {
                "target": str(addr), "type": "IP",
                "risk": "Informational",
                "time": datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                "reasons": ["IP format validated; reputation not checked"]
            }
            scans.insert(0, item)
        except ValueError:
            error = "Invalid IP address. Try 8.8.8.8"

    return page("""
    <h1>IP Address Analysis</h1>
    <div class="card">
      <form method="post">
        <label>IPv4 or IPv6 address</label>
        <input name="ip" placeholder="8.8.8.8" required>
        <button type="submit">Analyse IP</button>
      </form>
      <p class="risk">{{ error }}</p>
    </div>
    {% if result %}
    <div class="card">
      <h2>IP: {{ result.target }}</h2>
      <p>IP version: IPv{{ result.version }}</p>
      <p>Address classification: {{ result.scope }}</p>
      <p class="muted">This is not a malicious-IP reputation check.</p>
    </div>
    {% endif %}
    """, result=result, error=error)


@app.route("/alerts")
@login_required
def threats():
    return page("""
    <h1>Threat Alerts</h1>
    {% if items %}
      {% for item in items %}
      <div class="card">
        <h3 class="risk">{{ item.risk }} risk</h3>
        <p>Target: {{ item.target }}</p>
        <p>Time: {{ item.time }}</p>
        <ul>{% for reason in item.reasons %}
          <li>{{ reason }}</li>
        {% endfor %}</ul>
      </div>
      {% endfor %}
    {% else %}
      <div class="card">No high-risk URL indicators recorded yet.</div>
    {% endif %}
    """, items=alerts)

@app.route("/history")
@login_required
def history():
    return page("""
    <h1>Scan History</h1>
<a href="{{ url_for('export_csv') }}" class="btn">Export CSV</a>
    {% if items %}
      {% for item in items %}
      <div class="card">
        <b>{{ item.type }}</b>: {{ item.target }}
        <p>Result: {{ item.risk }} | Time: {{ item.time }}</p>
      </div>
      {% endfor %}
    {% else %}
      <div class="card">No scans yet. Try the website scanner.</div>
    {% endif %}
    """, items=scans)
@app.route("/export.csv")
@login_required
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Target", "Type", "Risk",
        "Score", "Reasons", "Scanned At"
    ])

    for scan in scans:
        writer.writerow([
            scan.get("target", ""),
            scan.get("type", ""),
            scan.get("risk", ""),
            scan.get("score", ""),
            "; ".join(scan.get("reasons", [])),
            scan.get("time", "")
        ])

    response = Response(
        "\ufeff" + output.getvalue(),
        mimetype="text/csv"
    )
    response.headers["Content-Disposition"] = (
        "attachment; filename=scan_history.csv"
    )
    return response
if __name__ == "__main__":
    print("Starting Flask app...")
    app.run(debug=True)