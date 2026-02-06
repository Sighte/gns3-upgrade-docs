# GNS3 3.0.5 Upgrade Dokumentation

## Übersicht

Diese Dokumentation beschreibt das Upgrade von GNS3 2.2.44.1 auf GNS3 3.0.5 auf einer Ubuntu 20.04 VM (talentlab026), die als GNS3-Server dient.

**Datum:** 2026-02-02 bis 2026-02-04
**System:** Ubuntu 20.04.6 LTS auf Proxmox VE
**Ziel:** GNS3 3.0.5 Server-Installation mit Erhalt aller bestehenden Projekte

---

## Ausgangssituation

| Komponente | Version |
|------------|---------|
| OS | Ubuntu 20.04.6 LTS |
| GNS3 | 2.2.44.1 (via apt/PPA) |
| Python | 3.8.10 |
| Projekte | SSRBasic, TalentLab |
| Projektgröße | 31 GB |

### Herausforderungen

1. **Python-Version:** GNS3 3.0.5 erfordert Python >= 3.9, Ubuntu 20.04 hat nur 3.8
2. **PPA-Limitierung:** Das offizielle GNS3 PPA bietet nur Version 2.2.x (auch für Ubuntu 24.04)
3. **Kompatibilität:** GNS3 3.x hat strengere Validierung für Projektdateien

---

## Durchgeführte Schritte

### 1. Backup erstellen

```bash
mkdir -p /root/gns3_backup_20260202
rsync -av /home/academy/GNS3/ /root/gns3_backup_20260202/GNS3/
rsync -av /home/academy/.config/GNS3/ /root/gns3_backup_20260202/config_GNS3/
```

**Gesicherte Daten:**
- `/home/academy/GNS3/` - Projekte, Images, Configs (31 GB)
- `/home/academy/.config/GNS3/2.2/` - Server-Konfiguration

### 2. GNS3 Projekte sauber stoppen

```bash
# Über GNS3 API alle Nodes stoppen
curl -u admin:PASSWORD -X POST http://127.0.0.1:3080/v2/projects/PROJECT_ID/nodes/stop

# Projekt schließen
curl -u admin:PASSWORD -X POST http://127.0.0.1:3080/v2/projects/PROJECT_ID/close

# Prozesse beenden
pkill -u academy gns3server
pkill -u academy -f "gns3-gui"
```

### 3. Python 3.9 installieren

```bash
apt-get install -y python3.9 python3.9-venv python3.9-dev
```

Python 3.9 ist im Ubuntu 20.04 Universe-Repository verfügbar (kein externes PPA nötig).

### 4. GNS3 3.0.5 in Virtual Environment installieren

```bash
# Venv erstellen
python3.9 -m venv /opt/gns3-venv

# pip aktualisieren
/opt/gns3-venv/bin/pip install --upgrade pip wheel

# GNS3 Server installieren
/opt/gns3-venv/bin/pip install gns3-server==3.0.5

# Symlink erstellen (optional)
ln -sf /opt/gns3-venv/bin/gns3server /usr/local/bin/gns3server-3
```

### 5. Konfiguration erstellen

**Verzeichnis:** `/home/academy/.config/GNS3/3.0/`

**Datei:** `gns3_server.conf`
```ini
[Server]
host = 0.0.0.0
port = 3080
images_path = /home/academy/GNS3/images
projects_path = /home/academy/GNS3/projects
appliances_path = /home/academy/GNS3/appliances
symbols_path = /home/academy/GNS3/symbols
configs_path = /home/academy/GNS3/configs
ubridge_path = /usr/bin/ubridge
report_errors = False
console_start_port_range = 5000
console_end_port_range = 10000
udp_start_port_range = 10000
udp_end_port_range = 20000
```

### 6. Systemd-Service erstellen

**Datei:** `/etc/systemd/system/gns3-server.service`
```ini
[Unit]
Description=GNS3 Server 3.0.5
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=academy
Group=academy
ExecStart=/opt/gns3-venv/bin/gns3server --local --config /home/academy/.config/GNS3/3.0/gns3_server.conf --log /home/academy/.config/GNS3/3.0/gns3_server.log --pid /home/academy/.config/GNS3/3.0/gns3_server.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**Wichtig:** Der `--local` Flag ist essentiell! Er bewirkt, dass der Server sowohl als Controller (Web-UI) als auch als Compute (VM-Ausführung) fungiert.

```bash
systemctl daemon-reload
systemctl enable gns3-server
systemctl start gns3-server
```

### 7. Admin-Passwort setzen

GNS3 3.x verwendet JWT-basierte Authentifizierung. Das Passwort wird in einer SQLite-Datenbank gespeichert:

```python
import bcrypt
import sqlite3

new_password = 'admin123'
hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

conn = sqlite3.connect('/home/academy/.config/GNS3/3.0/gns3_controller.db')
cursor = conn.cursor()
cursor.execute('UPDATE users SET hashed_password = ? WHERE username = ?', (hashed, 'admin'))
conn.commit()
conn.close()
```

### 8. Projektdatei reparieren (kritischer Schritt)

**Problem:** GNS3 2.x Projekte können leere `ethertype`-Felder in Ethernet-Switch-Konfigurationen haben. GNS3 3.x akzeptiert diese nicht mehr.

**Fehlermeldung:**
```
HTTP error 422: Input should be '0x8100', '0x88A8', '0x9100' or '0x9200'
```

**Lösung:** Leere `ethertype`-Felder aus der Projektdatei entfernen:

```python
import json

with open('/home/academy/GNS3/projects/SSRBasic/SSRBasic.gns3', 'r') as f:
    project = json.load(f)

for node in project.get('topology', {}).get('nodes', []):
    if node.get('node_type') == 'ethernet_switch':
        ports = node.get('properties', {}).get('ports_mapping', [])
        for port in ports:
            if 'ethertype' in port and port['ethertype'] == '':
                del port['ethertype']  # Leeres Feld entfernen

with open('/home/academy/GNS3/projects/SSRBasic/SSRBasic.gns3', 'w') as f:
    json.dump(project, f, indent=4)
```

**Vorher:**
```json
{
    "ethertype": "",
    "name": "Ethernet8",
    "port_number": 8,
    "type": "access",
    "vlan": 1
}
```

**Nachher:**
```json
{
    "name": "Ethernet8",
    "port_number": 8,
    "type": "access",
    "vlan": 1
}
```

---

## Ergebnis

| Komponente | Vorher | Nachher |
|------------|--------|---------|
| GNS3 Server | 2.2.44.1 | 3.0.5 |
| Python | 3.8.10 | 3.9.5 |
| Interface | Desktop-GUI | Web-UI |
| Zugriff | Lokal | http://IP:3080 |

### Zugangsdaten
- **URL:** http://100.64.0.73:3080
- **Benutzer:** admin
- **Passwort:** admin123

### Server-Verwaltung
```bash
systemctl status gns3-server   # Status prüfen
systemctl restart gns3-server  # Neustarten
systemctl stop gns3-server     # Stoppen
journalctl -u gns3-server -f   # Logs ansehen
```

---

## Wichtige Dateien

| Pfad | Beschreibung |
|------|--------------|
| `/opt/gns3-venv/` | GNS3 3.0.5 Python Virtual Environment |
| `/etc/systemd/system/gns3-server.service` | Systemd Service-Datei |
| `/home/academy/.config/GNS3/3.0/` | GNS3 3.x Konfiguration |
| `/home/academy/.config/GNS3/3.0/gns3_controller.db` | Benutzer-Datenbank (SQLite) |
| `/home/academy/.config/GNS3/3.0/gns3_server.log` | Server-Logdatei |
| `/home/academy/GNS3/projects/` | Projektverzeichnis |
| `/opt/gns3-scripts/manage_users.py` | Multi-User Schulungs-Verwaltungsskript |

---

## Multi-User Schulungsbetrieb

### Übersicht

GNS3 3.x unterstützt Multi-User mit RBAC (Role-Based Access Control). Für Schulungen wird jeder Teilnehmer ein eigener Account mit eigenen Projektkopien erstellt.

**Konzept:**
- Die Master-Projekte (SSRBasic, TalentLab) dienen als Vorlage
- Pro User werden die Projekte über die GNS3 API dupliziert
- ACL sorgt dafür, dass jeder User nur seine eigenen Projekte öffnen kann
- Master-Projekte sind für User gesperrt (HTTP 403)

### Voraussetzungen

**Speicherbedarf pro User:** ~21.4 GB (SSRBasic ~20 GB + TalentLab ~1.4 GB)

| Anzahl User | Zusätzlicher Bedarf | Empfohlene Disk-Größe |
|---|---|---|
| 2 | ~43 GB | ~80 GB |
| 5 | ~107 GB | ~145 GB |
| 10 | ~214 GB | ~250 GB |

**Disk-Erweiterung (Proxmox LXC auf ZFS):**
```bash
# Auf dem Proxmox-Host - Quota erhöhen:
zfs set refquota=<ZIELGRÖSSE> rpool/data/subvol-131-disk-0

# Alternativ:
pct resize 131 rootfs +100G
```

**Hinweis:** `pct resize` funktioniert möglicherweise nicht korrekt mit ZFS-Subvolumes. In diesem Fall die `refquota` direkt setzen.

### Abhängigkeiten

Folgende Pakete müssen installiert sein (wurden am 2026-02-06 nachinstalliert):

```bash
# uBridge (aus Source kompiliert, da kein apt-Paket verfügbar)
# Source: https://github.com/GNS3/ubridge
apt-get install -y libpcap-dev git make gcc
cd /tmp && git clone https://github.com/GNS3/ubridge.git
cd /tmp/ubridge && make
cp /tmp/ubridge/ubridge /usr/bin/ubridge
setcap cap_net_admin,cap_net_raw=ep /usr/bin/ubridge

# Dynamips (aus apt)
apt-get install -y dynamips
```

### Verwaltungsskript

**Pfad:** `/opt/gns3-scripts/manage_users.py`

```bash
# User erstellen (z.B. 5 User: user1-user5, Passwort: schulung123)
/opt/gns3-scripts/manage_users.py create --users 5

# Mit eigenem Prefix und Passwort
/opt/gns3-scripts/manage_users.py create --users 3 --prefix student --password geheim123

# Alle User und Projekte anzeigen
/opt/gns3-scripts/manage_users.py list

# Alle User mit Prefix löschen (inkl. Projekte)
/opt/gns3-scripts/manage_users.py delete --prefix user

# Einzelnen User löschen
/opt/gns3-scripts/manage_users.py delete --name user3
```

### ACL-Strategie

Pro User werden folgende ACL-Einträge erstellt:

| ACL | Pfad | Rolle | Allowed | Zweck |
|---|---|---|---|---|
| Basis-Zugriff | `/` | User | true | API-Zugriff (Templates, Images, etc.) |
| Master-Sperre | `/projects/<master_id>` | User | false | Master-Projekte nicht öffenbar |
| Projekt-Zugriff | `/projects/<user_projekt_id>` | User | true | Eigene Projekte voll nutzbar |

**Ergebnis:** User sehen Master-Projekte in der Liste, können sie aber **nicht öffnen** (HTTP 403). Eigene Projekte funktionieren normal.

### Workflow für eine Schulung

```bash
# 1. Vor der Schulung: User erstellen
/opt/gns3-scripts/manage_users.py create --users 5

# 2. Zugangsdaten an Teilnehmer verteilen
#    URL: http://100.64.0.73:3080
#    Username: user1, user2, ... user5
#    Passwort: schulung123

# 3. Nach der Schulung: User und Projekte löschen
/opt/gns3-scripts/manage_users.py delete --prefix user
```

---

## Fehlerbehebungen (2026-02-06)

### HTTP 500 beim Projekt-Öffnen

**Ursache:** Festplatte zu 97% voll (2.2 GB frei). GNS3 3.0.5 hat einen Bug: Bei wenig Speicherplatz versucht der Server eine Warnung zu senden (`project.emit`), aber der Worker-Thread hat keinen Zugriff auf die asyncio Event-Loop → `RuntimeError: no running event loop` → HTTP 500.

**Lösung:** Speicherplatz freigeben:
- Upgrade-Backup gelöscht (`/root/gns3_backup_20260202/`, 31 GB)
- APT-Cache bereinigt (`apt clean`, 1.4 GB)
- 43 gestoppte Docker-Container entfernt (`docker container prune`)
- Alte Downloads gelöscht (103 MB)

### Projektname-Mismatch bei Duplizierung

**Problem:** Der GNS3 Controller kannte das Projekt als "SSR Basics" (mit Leerzeichen), aber die Datei hieß "SSRBasic.gns3". Beim Duplizieren suchte GNS3 nach dem falschen Dateinamen.

**Lösung:** Projektname im Controller angepasst:
```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://127.0.0.1:3080/v3/projects/<PROJECT_ID> \
  -d '{"name":"SSRBasic"}'
```

### uBridge fehlt

**Problem:** `uBridge is not available` beim Duplizieren von Projekten.

**Lösung:** uBridge aus Source kompiliert und Capabilities gesetzt (siehe Abhängigkeiten oben).

---

## Bekannte Unterschiede GNS3 2.x vs 3.x

1. **Web-UI statt Desktop-App:** GNS3 3.x wird primär über den Browser bedient
2. **JWT-Authentifizierung:** Tokens statt einfacher Passwörter
3. **Strengere Validierung:** Projektdateien müssen valide sein
4. **Controller/Compute-Trennung:** `--local` Flag für All-in-One-Setup nötig
5. **API-Version:** `/v3/` statt `/v2/`

---

## Troubleshooting

### Projekt lässt sich nicht öffnen
1. Log prüfen: `tail -f /home/academy/.config/GNS3/3.0/gns3_server.log`
2. Auf `ethertype`-Fehler prüfen
3. Projektdatei mit dem Python-Skript reparieren

### Compute nicht verbunden
- Sicherstellen, dass `--local` Flag gesetzt ist
- Server neustarten: `systemctl restart gns3-server`

### Authentifizierung fehlgeschlagen
- Passwort in Datenbank zurücksetzen (siehe Schritt 7)
- Server neustarten

---

## Rollback

Falls nötig, kann auf GNS3 2.2.x zurückgewechselt werden:

```bash
# GNS3 3.x Service stoppen
systemctl stop gns3-server
systemctl disable gns3-server

# Backup wiederherstellen (falls nötig)
rsync -av /root/gns3_backup_20260202/GNS3/ /home/academy/GNS3/
rsync -av /root/gns3_backup_20260202/config_GNS3/ /home/academy/.config/GNS3/

# GNS3 2.2 ist noch installiert und kann normal gestartet werden
```
