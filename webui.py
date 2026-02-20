#!/usr/bin/env python3
"""
Schulungs-Benutzerverwaltung - Web-UI
=======================================
Flask-basierte Web-Oberfläche für die Schulungs-Provisionierung.
Importiert die Klassen aus UserScript.py und bietet:
  - Dashboard mit Übersicht aller User
  - User erstellen (mit Live-Fortschritt via SSE)
  - User löschen (mit Live-Fortschritt via SSE)

Starten:
  /opt/gns3-venv/bin/python /root/gns3-upgrade-docs/webui.py

Oder als Systemd-Service:
  systemctl start gns3-webui
"""

import io
import json
import os
import queue
import sys
import threading
import time
import uuid

# Ensure UserScript.py is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, Response, redirect, render_template_string, request, session, url_for
from UserScript import (
    GNS3,
    GNS3_MASTER_PROJECTS,
    Guacamole,
    Keycloak,
    Proxmox,
    DEFAULT_PASSWORD,
)

# =============================================================================
# KONFIGURATION
# =============================================================================

WEBUI_PASSWORD = "admin123"
WEBUI_PORT = 9443
SECRET_KEY = os.urandom(24).hex()

# =============================================================================
# APP
# =============================================================================

app = Flask(__name__)
app.secret_key = SECRET_KEY

# Task storage: task_id -> {"queue": Queue, "done": bool, "result": str}
tasks = {}


# =============================================================================
# AUTH
# =============================================================================

@app.before_request
def require_login():
    if request.endpoint in ("login", "static"):
        return
    if not session.get("authenticated"):
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        if request.form.get("password") == WEBUI_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("dashboard"))
        error = "Falsches Passwort."
    return render_template_string(LOGIN_HTML, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# =============================================================================
# DASHBOARD
# =============================================================================

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_HTML, projects=list(GNS3_MASTER_PROJECTS.keys()))


@app.route("/api/users")
def api_users():
    """JSON endpoint: list all provisioned users."""
    try:
        pve = Proxmox()
        kc = Keycloak()
        gns3 = GNS3()
        guac = Guacamole()

        kc.authenticate()
        gns3.authenticate()
        guac.authenticate()

        containers = pve.get_all_containers()
        training_cts = {
            c.get("name", "").replace("training-", ""): c
            for c in containers if c.get("name", "").startswith("training-")
        }

        kc_users = {u["username"] for u in kc.get_all_users()}
        gns3_users = {u["username"] for u in gns3.get_all_users() if not u.get("is_superadmin")}

        guac_conns = guac.get_all_connections()
        guac_names = set()
        if isinstance(guac_conns, dict):
            for c in guac_conns.values():
                name = c.get("name", "")
                if name.startswith("Training-"):
                    # Extract username from "Training-<user> (CT xxx)"
                    uname = name.split("Training-", 1)[1].split(" (")[0]
                    guac_names.add(uname)

        all_usernames = set(training_cts.keys()) | gns3_users
        rows = []
        for username in sorted(all_usernames):
            ct = training_cts.get(username)
            rows.append({
                "username": username,
                "proxmox_id": ct["vmid"] if ct else None,
                "proxmox_status": ct.get("status", "?") if ct else None,
                "keycloak": username in kc_users,
                "gns3": username in gns3_users,
                "guacamole": username in guac_names,
            })
        return json.dumps(rows), 200, {"Content-Type": "application/json"}
    except Exception as e:
        return json.dumps({"error": str(e)}), 500, {"Content-Type": "application/json"}


# =============================================================================
# CREATE USERS
# =============================================================================

@app.route("/api/create", methods=["POST"])
def api_create():
    """Start user creation as background task, return task_id."""
    data = request.get_json()
    mode = data.get("mode", "count")  # "count" or "single"
    prefix = data.get("prefix", "user")
    count = int(data.get("count", 1))
    single_name = data.get("name", "")
    password = data.get("password", "") or DEFAULT_PASSWORD
    selected_projects = data.get("projects") or list(GNS3_MASTER_PROJECTS.keys())

    if mode == "single" and single_name:
        usernames = [single_name]
    else:
        usernames = [f"{prefix}{i}" for i in range(1, count + 1)]

    project_map = {k: v for k, v in GNS3_MASTER_PROJECTS.items() if k in selected_projects}

    task_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    tasks[task_id] = {"queue": q, "done": False, "result": ""}

    def run():
        try:
            _run_create(q, usernames, password, project_map)
        except Exception as e:
            q.put(f"\nFEHLER: {e}\n")
        finally:
            tasks[task_id]["done"] = True
            q.put(None)  # sentinel

    threading.Thread(target=run, daemon=True).start()
    return json.dumps({"task_id": task_id}), 200, {"Content-Type": "application/json"}


def _run_create(q, usernames, password, project_map):
    """Run the full provisioning, sending output lines to the queue."""
    def out(msg=""):
        q.put(msg)

    out(f"Starte Provisionierung für {len(usernames)} User...")
    out()

    # Authenticate all services
    out("[0/5] Authentifizierung bei allen Diensten...")
    pve = Proxmox()
    kc = Keycloak()
    gns3 = GNS3()
    guac = Guacamole()

    if not kc.authenticate():
        out("FEHLER: Keycloak-Authentifizierung fehlgeschlagen!")
        return
    out("  Keycloak OK")

    if not gns3.authenticate():
        out("FEHLER: GNS3-Authentifizierung fehlgeschlagen!")
        return
    out("  GNS3 OK")

    if not guac.authenticate():
        out("FEHLER: Guacamole-Authentifizierung fehlgeschlagen!")
        return
    out("  Guacamole OK")
    out("  Proxmox OK (Token-Auth)")

    results = []

    for idx, username in enumerate(usernames, 1):
        out()
        out(f"{'='*50}")
        out(f"  Provisioniere: {username} ({idx}/{len(usernames)})")
        out(f"{'='*50}")

        # 1. Proxmox
        out(f"\n[1/5] Proxmox - Container erstellen...")
        vmid = pve.get_next_vmid()
        hostname = f"training-{username}"
        out(f"    Klone Template -> CT {vmid} ({hostname})...")
        upid = pve.clone_container(vmid, hostname)
        if not upid:
            out(f"    FEHLER beim Klonen! Überspringe {username}.")
            continue

        out(f"    Warte auf Abschluss des Klonvorgangs...")
        if not pve.wait_for_task(upid, timeout=900):
            out(f"    FEHLER: Klonvorgang nicht abgeschlossen!")
            pve.unlock_container(vmid)
            pve.delete_container(vmid)
            continue
        out(f"    Klon abgeschlossen")

        from UserScript import PROXMOX_NODE
        pve._api("PUT", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/config", data={"protection": 0})
        pve.start_container(vmid)
        out(f"    Container {vmid} gestartet")

        # Wait for IP
        out(f"    Warte auf IP-Adresse...")
        container_ip = pve.get_container_ip(vmid)
        if not container_ip:
            out(f"    WARNUNG: Keine IP erhalten!")
            container_ip = f"UNKNOWN-CT{vmid}"
        else:
            out(f"    IP: {container_ip}")

        # 2. Keycloak
        out(f"\n[2/5] Keycloak - User anlegen...")
        kc.authenticate()
        kc_user = kc.create_user(username, password)
        if kc_user:
            out(f"    Keycloak-User '{username}' erstellt")
        else:
            out(f"    WARNUNG: Keycloak-User konnte nicht erstellt werden")

        # 3. GNS3
        out(f"\n[3/5] GNS3 - User und Projekte anlegen...")
        gns3.authenticate()
        gns3_user = gns3.create_user(username, password)
        if gns3_user:
            out(f"    GNS3-User '{username}' erstellt")
            gns3_projects = gns3.setup_user_projects(gns3_user["user_id"], username, project_map)
            out(f"    {len(gns3_projects)} Projekte dupliziert und berechtigt")
        else:
            out(f"    WARNUNG: GNS3-User konnte nicht erstellt werden")
            gns3_projects = []

        # 4. Guacamole
        out(f"\n[4/5] Guacamole - RDP-Verbindung erstellen...")
        guac.authenticate()
        conn_name = f"Training-{username} (CT {vmid})"
        connection = guac.create_connection(conn_name, container_ip)
        if connection and "identifier" in connection:
            conn_id = connection["identifier"]
            out(f"    Verbindung '{conn_name}' erstellt")
            guac.create_user(username)
            guac.assign_connection_to_user(username, conn_id)
            out(f"    User '{username}' berechtigt")
        else:
            out(f"    WARNUNG: Guacamole-Verbindung konnte nicht erstellt werden")

        # 5. Done
        out(f"\n[5/5] {username} fertig provisioniert!")
        results.append({
            "username": username,
            "password": password,
            "vmid": vmid,
            "ip": container_ip,
        })

    # Summary
    if results:
        out()
        out(f"{'='*50}")
        out("ZUSAMMENFASSUNG")
        out(f"{'='*50}")
        for r in results:
            out(f"  {r['username']}  CT {r['vmid']}  IP {r['ip']}  PW {r['password']}")
        out(f"\n{len(results)} User erfolgreich provisioniert.")
    else:
        out("\nKeine User provisioniert.")


# =============================================================================
# DELETE USERS
# =============================================================================

@app.route("/api/delete", methods=["POST"])
def api_delete():
    """Start user deletion as background task."""
    data = request.get_json()
    usernames = data.get("usernames", [])
    if not usernames:
        return json.dumps({"error": "Keine User angegeben"}), 400, {"Content-Type": "application/json"}

    task_id = str(uuid.uuid4())[:8]
    q = queue.Queue()
    tasks[task_id] = {"queue": q, "done": False, "result": ""}

    def run():
        try:
            _run_delete(q, usernames)
        except Exception as e:
            q.put(f"\nFEHLER: {e}\n")
        finally:
            tasks[task_id]["done"] = True
            q.put(None)

    threading.Thread(target=run, daemon=True).start()
    return json.dumps({"task_id": task_id}), 200, {"Content-Type": "application/json"}


def _run_delete(q, usernames):
    """Run deletion for given usernames."""
    def out(msg=""):
        q.put(msg)

    out(f"Lösche {len(usernames)} User...")
    out()

    pve = Proxmox()
    kc = Keycloak()
    gns3 = GNS3()
    guac = Guacamole()

    out("Authentifizierung...")
    kc.authenticate()
    gns3.authenticate()
    guac.authenticate()
    out("OK")

    containers = pve.get_all_containers()
    guac_conns = guac.get_all_connections()
    gns3_acl = gns3.get_all_acl()
    gns3_projects = gns3.get_all_projects()
    gns3_users = gns3.get_all_users()
    master_pids = set(GNS3_MASTER_PROJECTS.values())

    for username in usernames:
        out(f"\n--- Lösche {username} ---")

        # 1. Proxmox
        ct = next((c for c in containers if c.get("name") == f"training-{username}"), None)
        if ct:
            out(f"  Proxmox: Lösche CT {ct['vmid']}...")
            pve.delete_container(ct["vmid"])
            out(f"  Container gelöscht")
        else:
            out(f"  Proxmox: Kein Container gefunden")

        # 2. Keycloak
        kc_user = kc.get_user_by_username(username)
        if kc_user:
            kc.delete_user(kc_user["id"])
            out(f"  Keycloak-User gelöscht")
        else:
            out(f"  Keycloak: User nicht gefunden")

        # 3. GNS3
        gns3_user = next((u for u in gns3_users if u["username"] == username), None)
        if gns3_user:
            uid = gns3_user["user_id"]
            for ace in gns3_acl:
                if ace.get("user_id") == uid:
                    path = ace.get("path", "")
                    if path.startswith("/projects/"):
                        pid = path.replace("/projects/", "")
                        if pid not in master_pids:
                            proj = next((p for p in gns3_projects if p["project_id"] == pid), None)
                            if proj:
                                gns3.delete_project(pid)
                                out(f"  GNS3-Projekt '{proj['name']}' gelöscht")
                    gns3.delete_acl(ace["ace_id"])
            gns3.delete_user(uid)
            out(f"  GNS3-User gelöscht")
        else:
            out(f"  GNS3: User nicht gefunden")

        # 4. Guacamole
        if isinstance(guac_conns, dict):
            for conn_id, conn in guac_conns.items():
                if f"Training-{username}" in conn.get("name", ""):
                    guac.delete_connection(conn_id)
                    out(f"  Guacamole-Verbindung gelöscht")
                    break
            else:
                out(f"  Guacamole: Keine Verbindung gefunden")

    out(f"\nLöschvorgang abgeschlossen.")


# =============================================================================
# SSE STREAM
# =============================================================================

@app.route("/stream/<task_id>")
def stream(task_id):
    """Server-Sent Events endpoint for task output."""
    if task_id not in tasks:
        return "Task not found", 404

    def generate():
        t = tasks[task_id]
        while True:
            try:
                msg = t["queue"].get(timeout=30)
                if msg is None:
                    yield f"event: done\ndata: finished\n\n"
                    break
                yield f"data: {msg}\n\n"
            except queue.Empty:
                yield f": keepalive\n\n"
                if t["done"]:
                    yield f"event: done\ndata: finished\n\n"
                    break

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# =============================================================================
# HTML TEMPLATES
# =============================================================================

BASE_CSS = """
:root {
    --bg: #1a1a2e;
    --surface: #16213e;
    --surface2: #0f3460;
    --accent: #e94560;
    --accent2: #533483;
    --text: #eee;
    --text2: #aaa;
    --ok: #4ecca3;
    --warn: #f0a500;
    --danger: #e94560;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
.container { max-width: 1100px; margin: 0 auto; padding: 20px; }
.card {
    background: var(--surface);
    border-radius: 12px;
    padding: 24px;
    margin-bottom: 20px;
    border: 1px solid rgba(255,255,255,0.05);
}
h1 { font-size: 1.6em; margin-bottom: 8px; }
h2 { font-size: 1.2em; margin-bottom: 12px; color: var(--text2); font-weight: 400; }
table { width: 100%; border-collapse: collapse; }
th { text-align: left; padding: 10px 12px; border-bottom: 2px solid var(--surface2); color: var(--text2); font-size: 0.85em; text-transform: uppercase; letter-spacing: 0.5px; }
td { padding: 10px 12px; border-bottom: 1px solid rgba(255,255,255,0.05); }
tr:hover td { background: rgba(255,255,255,0.02); }
.badge {
    display: inline-block; padding: 2px 10px; border-radius: 12px;
    font-size: 0.8em; font-weight: 600;
}
.badge-ok { background: rgba(78,204,163,0.15); color: var(--ok); }
.badge-no { background: rgba(255,255,255,0.05); color: var(--text2); }
.badge-running { background: rgba(78,204,163,0.2); color: var(--ok); }
.badge-stopped { background: rgba(240,165,0,0.15); color: var(--warn); }
btn, .btn {
    display: inline-block; padding: 8px 20px; border-radius: 8px;
    border: none; cursor: pointer; font-size: 0.9em; font-weight: 600;
    transition: all 0.15s;
}
.btn { display: inline-block; padding: 8px 20px; border-radius: 8px; border: none; cursor: pointer; font-size: 0.9em; font-weight: 600; transition: all 0.15s; text-align: center; }
.btn-primary { background: var(--accent); color: #fff; }
.btn-primary:hover { background: #d63651; }
.btn-danger { background: transparent; color: var(--danger); border: 1px solid var(--danger); padding: 4px 12px; font-size: 0.8em; }
.btn-danger:hover { background: var(--danger); color: #fff; }
.btn-secondary { background: var(--surface2); color: var(--text); }
.btn-secondary:hover { background: #1a4a80; }
.btn-sm { padding: 4px 12px; font-size: 0.8em; }
input, select {
    background: var(--bg); border: 1px solid rgba(255,255,255,0.1);
    color: var(--text); padding: 8px 12px; border-radius: 8px;
    font-size: 0.9em; width: 100%;
}
input:focus, select:focus { outline: none; border-color: var(--accent); }
label { display: block; margin-bottom: 4px; color: var(--text2); font-size: 0.85em; }
.form-group { margin-bottom: 14px; }
.form-row { display: flex; gap: 14px; }
.form-row > * { flex: 1; }
.nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 0; margin-bottom: 10px;
}
.nav-title { font-size: 1.3em; font-weight: 700; }
.nav-links { display: flex; gap: 16px; align-items: center; }
#console {
    background: #0d1117; border-radius: 8px; padding: 16px;
    font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 0.85em;
    line-height: 1.6; max-height: 500px; overflow-y: auto;
    white-space: pre-wrap; color: #c9d1d9;
    border: 1px solid rgba(255,255,255,0.05);
}
.overlay {
    display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6);
    z-index: 100; align-items: center; justify-content: center;
}
.overlay.active { display: flex; }
.modal {
    background: var(--surface); border-radius: 12px; padding: 28px;
    min-width: 320px; max-width: 500px; width: 90%;
    border: 1px solid rgba(255,255,255,0.1);
}
.modal h3 { margin-bottom: 16px; }
.modal-actions { display: flex; gap: 10px; justify-content: flex-end; margin-top: 20px; }
.checkbox-group { display: flex; flex-wrap: wrap; gap: 8px; }
.checkbox-group label {
    display: flex; align-items: center; gap: 6px;
    background: var(--bg); padding: 6px 12px; border-radius: 6px;
    cursor: pointer; font-size: 0.9em; color: var(--text);
}
.checkbox-group input[type=checkbox] { width: auto; }
.spinner { display: inline-block; width: 16px; height: 16px; border: 2px solid rgba(255,255,255,0.1); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.6s linear infinite; }
@keyframes spin { to { transform: rotate(360deg); } }
.hidden { display: none; }
.alert { padding: 12px 16px; border-radius: 8px; margin-bottom: 14px; font-size: 0.9em; }
.alert-info { background: rgba(83,52,131,0.2); border: 1px solid var(--accent2); }
"""

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login - Schulungsverwaltung</title>
<style>""" + BASE_CSS + """
.login-wrap { display:flex; align-items:center; justify-content:center; min-height:100vh; }
.login-card { width: 360px; }
.login-card h1 { text-align: center; margin-bottom: 4px; }
.login-card h2 { text-align: center; margin-bottom: 24px; }
.error { color: var(--danger); font-size: 0.85em; margin-bottom: 10px; }
</style></head><body>
<div class="login-wrap"><div class="card login-card">
<h1>Schulungsverwaltung</h1>
<h2>Bitte anmelden</h2>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
<form method="post">
<div class="form-group"><label>Passwort</label><input type="password" name="password" autofocus></div>
<button type="submit" class="btn btn-primary" style="width:100%">Anmelden</button>
</form>
</div></div></body></html>"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Schulungsverwaltung</title>
<style>""" + BASE_CSS + """</style></head><body>
<div class="container">

<div class="nav">
    <span class="nav-title">Schulungsverwaltung</span>
    <div class="nav-links">
        <button class="btn btn-secondary btn-sm" onclick="loadUsers()">Aktualisieren</button>
        <button class="btn btn-primary btn-sm" onclick="showCreate()">+ User erstellen</button>
        <a href="/logout" style="color:var(--text2);font-size:0.85em;">Abmelden</a>
    </div>
</div>

<!-- User Table -->
<div class="card">
    <h2>Provisionierte Benutzer</h2>
    <div id="userTableWrap">
        <div style="text-align:center;padding:30px;color:var(--text2)"><div class="spinner"></div> Lade...</div>
    </div>
</div>

<!-- Console Output -->
<div class="card hidden" id="consoleCard">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
        <h2 id="consoleTitle" style="margin:0">Ausgabe</h2>
        <button class="btn btn-secondary btn-sm" onclick="hideConsole()">Schliessen</button>
    </div>
    <div id="console"></div>
</div>

<!-- Create User Modal -->
<div class="overlay" id="createModal">
<div class="modal">
    <h3>User erstellen</h3>
    <div class="form-group">
        <label>Modus</label>
        <select id="createMode" onchange="toggleCreateMode()">
            <option value="count">Mehrere User (Prefix + Anzahl)</option>
            <option value="single">Einzelner User</option>
        </select>
    </div>
    <div id="createCountFields">
        <div class="form-row">
            <div class="form-group"><label>Prefix</label><input id="createPrefix" value="user"></div>
            <div class="form-group"><label>Anzahl</label><input id="createCount" type="number" value="1" min="1" max="30"></div>
        </div>
    </div>
    <div id="createSingleFields" class="hidden">
        <div class="form-group"><label>Username</label><input id="createName"></div>
    </div>
    <div class="form-group"><label>Passwort</label><input id="createPassword" value="schulung123"></div>
    <div class="form-group">
        <label>Projekte</label>
        <div class="checkbox-group">
            {% for p in projects %}
            <label><input type="checkbox" value="{{ p }}" checked> {{ p }}</label>
            {% endfor %}
        </div>
    </div>
    <div class="modal-actions">
        <button class="btn btn-secondary" onclick="hideCreate()">Abbrechen</button>
        <button class="btn btn-primary" id="createBtn" onclick="doCreate()">Erstellen</button>
    </div>
</div>
</div>

<!-- Delete Confirm Modal -->
<div class="overlay" id="deleteModal">
<div class="modal">
    <h3>User löschen</h3>
    <p style="margin-bottom:16px">Folgende User werden aus <strong>allen Systemen</strong> gelöscht (inkl. Container):</p>
    <div id="deleteList" style="background:var(--bg);padding:12px;border-radius:8px;margin-bottom:16px;font-family:monospace;font-size:0.9em"></div>
    <div class="modal-actions">
        <button class="btn btn-secondary" onclick="hideDelete()">Abbrechen</button>
        <button class="btn btn-primary" style="background:var(--danger)" id="deleteBtn" onclick="doDelete()">Endgueltig loeschen</button>
    </div>
</div>
</div>

<script>
let deleteTargets = [];

function loadUsers() {
    document.getElementById('userTableWrap').innerHTML = '<div style="text-align:center;padding:30px;color:var(--text2)"><div class="spinner"></div> Lade...</div>';
    fetch('/api/users').then(r => r.json()).then(data => {
        if (data.error) { document.getElementById('userTableWrap').innerHTML = '<div class="alert alert-info">Fehler: ' + data.error + '</div>'; return; }
        if (!data.length) { document.getElementById('userTableWrap').innerHTML = '<div style="text-align:center;padding:20px;color:var(--text2)">Keine User gefunden.</div>'; return; }
        let html = '<table><thead><tr><th><input type="checkbox" id="selectAll" onchange="toggleAll(this)"></th><th>Username</th><th>Proxmox</th><th>Keycloak</th><th>GNS3</th><th>Guacamole</th><th></th></tr></thead><tbody>';
        data.forEach(u => {
            let pxInfo = u.proxmox_id ? 'CT ' + u.proxmox_id + ' <span class="badge badge-' + (u.proxmox_status==='running'?'running':'stopped') + '">' + u.proxmox_status + '</span>' : '<span class="badge badge-no">---</span>';
            html += '<tr>';
            html += '<td><input type="checkbox" class="user-cb" value="' + u.username + '"></td>';
            html += '<td><strong>' + u.username + '</strong></td>';
            html += '<td>' + pxInfo + '</td>';
            html += '<td><span class="badge badge-' + (u.keycloak?'ok':'no') + '">' + (u.keycloak?'OK':'---') + '</span></td>';
            html += '<td><span class="badge badge-' + (u.gns3?'ok':'no') + '">' + (u.gns3?'OK':'---') + '</span></td>';
            html += '<td><span class="badge badge-' + (u.guacamole?'ok':'no') + '">' + (u.guacamole?'OK':'---') + '</span></td>';
            html += '<td><button class="btn btn-danger btn-sm" onclick="confirmDelete([\'' + u.username + '\'])">Loeschen</button></td>';
            html += '</tr>';
        });
        html += '</tbody></table>';
        html += '<div style="margin-top:12px;display:flex;gap:10px;align-items:center">';
        html += '<button class="btn btn-danger btn-sm" onclick="deleteSelected()">Ausgewaehlte loeschen</button>';
        html += '<span style="color:var(--text2);font-size:0.85em" id="selCount"></span>';
        html += '</div>';
        document.getElementById('userTableWrap').innerHTML = html;
    }).catch(e => {
        document.getElementById('userTableWrap').innerHTML = '<div class="alert alert-info">Verbindungsfehler: ' + e + '</div>';
    });
}

function toggleAll(el) {
    document.querySelectorAll('.user-cb').forEach(cb => cb.checked = el.checked);
}

function deleteSelected() {
    let sel = Array.from(document.querySelectorAll('.user-cb:checked')).map(cb => cb.value);
    if (!sel.length) return;
    confirmDelete(sel);
}

function confirmDelete(usernames) {
    deleteTargets = usernames;
    document.getElementById('deleteList').innerHTML = usernames.map(u => '- ' + u).join('<br>');
    document.getElementById('deleteModal').classList.add('active');
}
function hideDelete() { document.getElementById('deleteModal').classList.remove('active'); }

function doDelete() {
    hideDelete();
    showConsole('Lösche User...');
    document.getElementById('deleteBtn').disabled = true;
    fetch('/api/delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({usernames: deleteTargets})})
    .then(r => r.json()).then(data => {
        streamTask(data.task_id);
    });
}

function showCreate() { document.getElementById('createModal').classList.add('active'); }
function hideCreate() { document.getElementById('createModal').classList.remove('active'); }

function toggleCreateMode() {
    let mode = document.getElementById('createMode').value;
    document.getElementById('createCountFields').classList.toggle('hidden', mode==='single');
    document.getElementById('createSingleFields').classList.toggle('hidden', mode==='count');
}

function doCreate() {
    hideCreate();
    let mode = document.getElementById('createMode').value;
    let projects = Array.from(document.querySelectorAll('.checkbox-group input:checked')).map(cb => cb.value);
    let body = {
        mode: mode,
        prefix: document.getElementById('createPrefix').value,
        count: parseInt(document.getElementById('createCount').value),
        name: document.getElementById('createName').value,
        password: document.getElementById('createPassword').value,
        projects: projects,
    };
    showConsole('Erstelle User...');
    fetch('/api/create', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)})
    .then(r => r.json()).then(data => {
        streamTask(data.task_id);
    });
}

function showConsole(title) {
    document.getElementById('consoleCard').classList.remove('hidden');
    document.getElementById('consoleTitle').textContent = title || 'Ausgabe';
    document.getElementById('console').textContent = '';
}
function hideConsole() {
    document.getElementById('consoleCard').classList.add('hidden');
}

function streamTask(taskId) {
    let con = document.getElementById('console');
    let es = new EventSource('/stream/' + taskId);
    es.onmessage = function(e) {
        con.textContent += e.data + '\\n';
        con.scrollTop = con.scrollHeight;
    };
    es.addEventListener('done', function() {
        es.close();
        con.textContent += '\\n--- Fertig ---\\n';
        loadUsers();
    });
    es.onerror = function() {
        es.close();
        con.textContent += '\\n--- Verbindung unterbrochen ---\\n';
    };
}

// Initial load
loadUsers();
</script>
</div></body></html>"""


# =============================================================================
# MAIN
# =============================================================================

if __name__ == "__main__":
    print(f"Schulungsverwaltung Web-UI startet auf Port {WEBUI_PORT}...")
    print(f"Login-Passwort: {WEBUI_PASSWORD}")
    app.run(host="0.0.0.0", port=WEBUI_PORT, threaded=True)
