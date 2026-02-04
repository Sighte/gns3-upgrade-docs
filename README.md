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
| `/root/gns3_backup_20260202/` | Vollständiges Backup |

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
