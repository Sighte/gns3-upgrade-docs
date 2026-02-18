# IHK-Projekt: Migration & Automatisierung der GNS3-Schulungsumgebung

**Fachinformatiker Systemintegration | ambiFOX GmbH, Ahaus | Sommer 2026**

---

## Zusammenfassung

Migration einer internen GNS3-basierten Netzwerk-Trainingsumgebung von einem externen Rechenzentrum ins Firmengebäude. Kernziel: Ein einziges Python-Skript (`provision_training.py`) erstellt pro Schulungsteilnehmer eine eigene VM, SSO-Zugang, GNS3-User mit Projektkopien und eine Guacamole-RDP-Verbindung.

### Ausgangsproblem: Dreifache Benutzerverwaltung

Benutzer mussten bisher **separat** in drei Systemen angelegt werden:

1. **GNS3** – hierfür existierte bereits ein Python-Skript (`manage_users.py`)
2. **Apache Guacamole** – manuell
3. **Keycloak** – manuell

### Lösung: Automatisierter Ablauf pro Teilnehmer

| Schritt | System | Aktion |
|---------|--------|--------|
| 1 | Proxmox API | LXC-Container aus Template 133 klonen |
| 2 | Netzwerk | DHCP auf vmbr2, IP-Adresse abwarten |
| 3 | Keycloak API | User anlegen (Realm: master) |
| 4 | GNS3 API | User + Projekte duplizieren + ACL setzen |
| 5 | Guacamole API | RDP-Verbindung zur neuen Container-IP + User berechtigen |

---

## Infrastruktur

| Komponente | Details |
|---|---|
| **Virtualisierung** | Proxmox VE, Node: `proxmox01a` |
| **Trainings-VMs** | LXC-Container (kein QEMU), Template-ID: `133` (Name: `Gns3Clienttest`) |
| **Netzwerk** | Linux Bridge `vmbr2`, DHCP, Subnetz `/24`, GNS3-Netz: `100.64.0.x` |
| **Storage** | Zu prüfen: `local-lvm` oder ZFS |
| **Reverse Proxy** | Traefik v2.3.2 (Container `traefik`, Ports 80/443) |

### Speicherbedarf pro User

Jeder User benötigt ca. **21,4 GB** (SSRBasic ~20 GB + TalentLab ~1,4 GB).

| Anzahl User | Zusätzlicher Bedarf | Empfohlene Disk-Größe |
|---|---|---|
| 2 | ~43 GB | ~80 GB |
| 5 | ~107 GB | ~145 GB |
| 10 | ~214 GB | ~250 GB |

Disk-Erweiterung (Proxmox LXC auf ZFS):

```bash
# Auf dem Proxmox-Host - Quota erhöhen:
zfs set refquota=<ZIELGRÖSSE> rpool/data/subvol-131-disk-0

# Alternativ:
pct resize 131 rootfs +100G
```

> **Hinweis:** `pct resize` funktioniert möglicherweise nicht korrekt mit ZFS-Subvolumes. In diesem Fall die refquota direkt setzen.

---

## Dienste (alle als Docker-Container auf `lab-dmz-srv01a`)

| Dienst | Container-Name | Image | Interner Port | Externe URL |
|---|---|---|---|---|
| **Guacamole** | `guacamole_guacamole_1` | `guacamole/guacamole` | 8080 | `https://lab.nocware.com` |
| **Guacd** | `guacamole_guacd_1` | `guacamole/guacd` | 4822 | intern |
| **Guacamole DB** | `guacamole_mariadb_1` | `mariadb` | 3306 | intern |
| **Keycloak** | `keycloak_keycloak_1` | `quay.io/keycloak/keycloak:latest` | 8080/8443 | `https://auth.academy.nocware.com` |
| **Keycloak DB** | `keycloak_mariadb_1` | `mariadb` | 3306 | intern |
| **GNS3 Server** | direkt auf Host/VM | GNS3 Server 3.0.5 | 3080 | `http://100.64.0.73:3080` |

### Zugangsdaten & Tokens

| Dienst | User | Hinweis |
|---|---|---|
| **Proxmox API** | `root@pam`, Token-ID: `UserScript` | Token-Secret bekannt |
| **GNS3 Admin** | `admin` / `admin123` | JWT-basierte Authentifizierung |
| **Guacamole Admin** | `guacadmin` | Passwort muss eingetragen werden |
| **Keycloak Admin** | `admin` | Passwort muss eingetragen werden, Realm: `master` |

---

## OIDC-Anbindung (Guacamole ↔ Keycloak)

Guacamole ist bereits per OpenID Connect an Keycloak angebunden. Konfiguration in `/home/guacamole/.guacamole/guacamole.properties` (im Container `guacamole_guacamole_1`):

```properties
guacd-hostname: guacd
guacd-port: 4822
mysql-username: guacamole
mysql-password: guacamole
mysql-database: guacamole
mysql-hostname: mariadb
mysql-port: 3306
openid-authorization-endpoint: https://auth.academy.nocware.com/realms/master/protocol/openid-connect/auth
openid-jwks-endpoint: http://keycloak:8080/realms/master/protocol/openid-connect/certs
openid-issuer: https://auth.academy.nocware.com/realms/master
openid-client-id: guacamole
openid-redirect-uri: https://lab.nocware.com
openid-username-claim-type: preferred_username
```

**Wichtig:** Der `jwks-endpoint` nutzt die interne Docker-URL (`http://keycloak:8080`), während `authorization-endpoint` und `issuer` die externe URL nutzen (Browser-Redirect). Das ist korrekt so.

**Verbleibendes Problem:** Trotz OIDC-Login müssen Benutzer in Guacamole weiterhin Verbindungen (RDP/SSH/VNC) zugewiesen bekommen. Das geht nicht automatisch über Keycloak – dafür wird die Guacamole REST API genutzt.

---

## GNS3 3.0.5 Upgrade-Dokumentation

**Datum:** 2026-02-02 bis 2026-02-04
**System:** Ubuntu 20.04.6 LTS auf Proxmox VE (VM: `talentlab026`) — mittlerweile auf **Ubuntu 24.04.4 LTS** upgegraded

### Ausgangssituation → Ergebnis

| Komponente | Vorher | Nachher |
|---|---|---|
| GNS3 Server | 2.2.44.1 | 3.0.5 |
| Python | 3.8.10 | 3.9.5 (venv) |
| Interface | Desktop-GUI | Web-UI |
| Zugriff | Lokal | `http://100.64.0.73:3080` |
| API-Version | `/v2/` | `/v3/` |
| Authentifizierung | Einfache Passwörter | JWT-Tokens |
| Projektgröße | 31 GB | 31 GB |

### Herausforderungen

- **Python-Version:** GNS3 3.0.5 erfordert Python >= 3.9, Ubuntu 20.04 hat nur 3.8
- **PPA-Limitierung:** Das offizielle GNS3 PPA bietet nur Version 2.2.x (auch für Ubuntu 24.04)
- **Kompatibilität:** GNS3 3.x hat strengere Validierung für Projektdateien (z.B. leere ethertype-Felder)

### Schritt 1: Backup

```bash
mkdir -p /root/gns3_backup_20260202
rsync -av /home/academy/GNS3/ /root/gns3_backup_20260202/GNS3/
rsync -av /home/academy/.config/GNS3/ /root/gns3_backup_20260202/config_GNS3/
```

Gesichert: `/home/academy/GNS3/` (Projekte, Images, Configs, 31 GB) und `/home/academy/.config/GNS3/2.2/` (Server-Konfiguration).

### Schritt 2: GNS3 Projekte stoppen

```bash
curl -u admin:PASSWORD -X POST http://127.0.0.1:3080/v2/projects/PROJECT_ID/nodes/stop
curl -u admin:PASSWORD -X POST http://127.0.0.1:3080/v2/projects/PROJECT_ID/close

pkill -u academy gns3server
pkill -u academy -f "gns3-gui"
```

### Schritt 3: Python 3.9 installieren

```bash
apt-get install -y python3.9 python3.9-venv python3.9-dev
```

Python 3.9 ist im Ubuntu 20.04 Universe-Repository verfügbar (kein externes PPA nötig).

### Schritt 4: GNS3 3.0.5 in Virtual Environment installieren

```bash
python3.9 -m venv /opt/gns3-venv
/opt/gns3-venv/bin/pip install --upgrade pip wheel
/opt/gns3-venv/bin/pip install gns3-server==3.0.5
ln -sf /opt/gns3-venv/bin/gns3server /usr/local/bin/gns3server-3
```

### Schritt 5: Konfiguration

Datei: `/home/academy/.config/GNS3/3.0/gns3_server.conf`

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

### Schritt 6: Systemd-Service

Datei: `/etc/systemd/system/gns3-server.service`

```ini
[Unit]
Description=GNS3 Server 3.0.5
After=network.target docker.service
Wants=docker.service

[Service]
Type=simple
User=academy
Group=academy
ExecStart=/opt/gns3-venv/bin/gns3server --local \
  --config /home/academy/.config/GNS3/3.0/gns3_server.conf \
  --log /home/academy/.config/GNS3/3.0/gns3_server.log \
  --pid /home/academy/.config/GNS3/3.0/gns3_server.pid
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

> **Wichtig:** Der `--local` Flag ist essentiell! Er bewirkt, dass der Server sowohl als Controller (Web-UI) als auch als Compute (VM-Ausführung) fungiert.

```bash
systemctl daemon-reload
systemctl enable gns3-server
systemctl start gns3-server
```

### Schritt 7: Admin-Passwort setzen

GNS3 3.x verwendet JWT-basierte Authentifizierung. Passwort in SQLite-Datenbank:

```python
import bcrypt, sqlite3

new_password = 'admin123'
hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()

conn = sqlite3.connect('/home/academy/.config/GNS3/3.0/gns3_controller.db')
cursor = conn.cursor()
cursor.execute('UPDATE users SET hashed_password = ? WHERE username = ?', (hashed, 'admin'))
conn.commit()
conn.close()
```

### Schritt 8: Projektdatei reparieren (kritisch)

GNS3 2.x Projekte können leere `ethertype`-Felder haben. GNS3 3.x akzeptiert diese nicht mehr.

**Fehlermeldung:** `HTTP error 422: Input should be '0x8100', '0x88A8', '0x9100' or '0x9200'`

```python
import json

with open('/home/academy/GNS3/projects/SSRBasic/SSRBasic.gns3', 'r') as f:
    project = json.load(f)

for node in project.get('topology', {}).get('nodes', []):
    if node.get('node_type') == 'ethernet_switch':
        ports = node.get('properties', {}).get('ports_mapping', [])
        for port in ports:
            if 'ethertype' in port and port['ethertype'] == '':
                del port['ethertype']

with open('/home/academy/GNS3/projects/SSRBasic/SSRBasic.gns3', 'w') as f:
    json.dump(project, f, indent=4)
```

---

## Abhängigkeiten & installierte Pakete

### uBridge (aus Source kompiliert)

```bash
apt-get install -y libpcap-dev git make gcc
cd /tmp && git clone https://github.com/GNS3/ubridge.git
cd /tmp/ubridge && make
cp /tmp/ubridge/ubridge /usr/bin/ubridge
setcap cap_net_admin,cap_net_raw=ep /usr/bin/ubridge
```

### Dynamips

```bash
apt-get install -y dynamips
```

---

## API-Endpunkte im Überblick

### Proxmox (LXC)

Auth-Header: `Authorization: PVEAPIToken=root@pam!UserScript=SECRET`

| Aktion | Methode | Endpunkt |
|---|---|---|
| Klonen | `POST` | `/nodes/{node}/lxc/{template_id}/clone` |
| Netzwerk konfigurieren | `PUT` | `/nodes/{node}/lxc/{vmid}/config` |
| Starten | `POST` | `/nodes/{node}/lxc/{vmid}/status/start` |
| IP auslesen | `GET` | `/nodes/{node}/lxc/{vmid}/interfaces` |

Netzwerk-Konfiguration: `net0=name=eth0,bridge=vmbr2,ip=dhcp`

### Keycloak (Admin REST API)

| Aktion | Methode | Endpunkt |
|---|---|---|
| Token holen | `POST` | `/realms/master/protocol/openid-connect/token` |
| User erstellen | `POST` | `/admin/realms/master/users` |
| User suchen | `GET` | `/admin/realms/master/users?username=xxx&exact=true` |
| User löschen | `DELETE` | `/admin/realms/master/users/{user_id}` |

Token-Request: `grant_type=password`, `client_id=admin-cli`

### GNS3 (v3 API)

| Aktion | Methode | Endpunkt |
|---|---|---|
| Authentifizierung | `POST` | `/v3/access/users/authenticate` → Bearer Token |
| User erstellen | `POST` | `/v3/access/users` |
| Projekte duplizieren | `POST` | `/v3/projects/{id}/duplicate` |
| ACL setzen | `POST` | `/v3/access/acl` |

### Guacamole (REST API)

| Aktion | Methode | Endpunkt |
|---|---|---|
| Auth-Token holen | `POST` | `/api/tokens` (form-urlencoded) |
| Verbindung erstellen | `POST` | `/api/session/data/mysql/connections?token=xxx` |
| Berechtigung setzen | `PATCH` | `/api/session/data/mysql/users/{username}/permissions?token=xxx` |

Guacamole verbindet sich per **RDP** zu den LXC-Containern.

---

## Multi-User-Schulungsbetrieb (GNS3)

GNS3 3.x unterstützt Multi-User mit RBAC (Role-Based Access Control). Master-Projekte (SSRBasic, TalentLab) dienen als Vorlage. Pro User werden Projekte über die GNS3 API dupliziert. ACL sorgt dafür, dass jeder User nur seine eigenen Projekte öffnen kann. Master-Projekte sind für User gesperrt (HTTP 403).

### Bestehendes Skript: `manage_users.py`

| Eigenschaft | Details |
|---|---|
| Pfad | `/opt/gns3-scripts/manage_users.py` |
| Sprache | Python 3.9 (venv: `/opt/gns3-venv/bin/python3.9`) |
| Funktionen | `create` (User + Projektkopien + ACL), `list`, `delete` |
| Master-Projekte | SSRBasic (`c0518772-...`) und TalentLab (`a786a84b-...`) |
| Default-Passwort | `schulung123` |
| GNS3 User-Rolle ID | `1ac9799b-...` |
| GNS3 No-Access Rolle ID | `837bd73e-...` |

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

| ACL | Pfad | Rolle | Allowed | Zweck |
|---|---|---|---|---|
| Basis-Zugriff | `/` | User | true | API-Zugriff (Templates, Images, etc.) |
| Master-Sperre | `/projects/<master_id>` | User | false | Master-Projekte nicht öffenbar |
| Projekt-Zugriff | `/projects/<user_projekt_id>` | User | true | Eigene Projekte voll nutzbar |

---

## Provisionierungsskript: `provision_training.py`

Das zentrale Skript, das alle vier Systeme in einem Durchlauf provisioniert:

```bash
# Teilnehmer erstellen
python3 provision_training.py create --users 5 --prefix user

# Übersicht
python3 provision_training.py list

# Aufräumen
python3 provision_training.py delete --prefix user
python3 provision_training.py delete --name user3
```

### Noch zu konfigurieren

| Parameter | Status |
|---|---|
| Keycloak Admin-Passwort | Muss eingetragen werden |
| Guacamole Admin-Passwort | Muss eingetragen werden |
| Proxmox Storage | Prüfen: `local-lvm` vs. ZFS |
| Start-VMID | Aktuell: 200 |

---

## Fehlerbehebungen (2026-02-06)

### HTTP 500 beim Projekt-Öffnen

**Ursache:** Festplatte zu 97% voll (2,2 GB frei). GNS3 3.0.5 Bug: Bei wenig Speicherplatz versucht der Server eine Warnung zu senden (`project.emit`), aber der Worker-Thread hat keinen Zugriff auf die asyncio Event-Loop → `RuntimeError: no running event loop` → HTTP 500.

**Lösung:** Speicherplatz freigeben – Upgrade-Backup gelöscht (31 GB), APT-Cache bereinigt (1,4 GB), 43 gestoppte Docker-Container entfernt, alte Downloads gelöscht (103 MB).

### Projektname-Mismatch bei Duplizierung

**Problem:** Der GNS3 Controller kannte das Projekt als "SSR Basics" (mit Leerzeichen), aber die Datei hieß "SSRBasic.gns3".

**Lösung:**

```bash
curl -X PUT -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  http://127.0.0.1:3080/v3/projects/<PROJECT_ID> \
  -d '{"name":"SSRBasic"}'
```

### uBridge fehlt

**Problem:** "uBridge is not available" beim Duplizieren von Projekten.

**Lösung:** uBridge aus Source kompiliert und Capabilities gesetzt (siehe Abhängigkeiten).

### ethertype-Validierungsfehler

**Problem:** HTTP 422 bei Projekten mit leeren ethertype-Feldern in Ethernet-Switch-Konfigurationen.

**Lösung:** Leere ethertype-Felder per Python-Skript aus der Projektdatei entfernt (siehe Upgrade Schritt 8).

---

## Wichtige Dateien & Pfade

| Pfad | Beschreibung |
|---|---|
| `/opt/gns3-venv/` | GNS3 3.0.5 Python Virtual Environment |
| `/etc/systemd/system/gns3-server.service` | Systemd Service-Datei |
| `/home/academy/.config/GNS3/3.0/` | GNS3 3.x Konfigurationsverzeichnis |
| `/home/academy/.config/GNS3/3.0/gns3_controller.db` | Benutzer-Datenbank (SQLite) |
| `/home/academy/.config/GNS3/3.0/gns3_server.log` | Server-Logdatei |
| `/home/academy/GNS3/projects/` | Projektverzeichnis |
| `/opt/gns3-scripts/manage_users.py` | Multi-User Schulungs-Verwaltungsskript |
| `/home/guacamole/.guacamole/guacamole.properties` | Guacamole OIDC-Konfiguration (im Container) |

### Server-Verwaltung

```bash
systemctl status gns3-server    # Status prüfen
systemctl restart gns3-server   # Neustarten
systemctl stop gns3-server      # Stoppen
journalctl -u gns3-server -f    # Logs ansehen
```

---

## Offene Punkte & Nächste Schritte

- [ ] Keycloak: Eigenen Realm statt `master` erwägen (z.B. `training` oder `academy`)
- [ ] GNS3 ↔ Keycloak: GNS3 hat keine native OIDC-Unterstützung – User werden per API angelegt
- [ ] Guacamole OIDC Extension: Version prüfen und ggf. aktualisieren (`guacamole-auth-sso-openid`)
- [ ] Docker Volumes: Prüfen ob `guacamole.properties` als Volume gemountet ist
- [ ] `provision_training.py` testen und Fehlerbehandlung verfeinern
- [ ] RDP im LXC-Template: Sicherstellen dass xrdp im Template installiert ist
- [ ] QEMU Guest Agent / LXC-Äquivalent für IP-Erkennung testen
- [ ] Proxmox Storage: Entscheidung `local-lvm` oder ZFS
- [ ] Keycloak & Guacamole Admin-Passwörter im Skript eintragen

---

## Troubleshooting

**Projekt lässt sich nicht öffnen:** Log prüfen mit `tail -f /home/academy/.config/GNS3/3.0/gns3_server.log`. Auf ethertype-Fehler prüfen. Projektdatei mit dem Python-Skript reparieren.

**Compute nicht verbunden:** Sicherstellen, dass `--local` Flag im Service gesetzt ist. Server neustarten: `systemctl restart gns3-server`.

**Authentifizierung fehlgeschlagen:** Passwort in SQLite-Datenbank zurücksetzen (siehe Upgrade Schritt 7). Server neustarten.

**Guacamole-RDP-Verbindung schlägt fehl (xrdp 0.9.21+ / OpenSSL 3.x):** Fehlerbild: Verbindung bricht sofort ab. In xrdp-Logs: `libxrdp_force_read: header read error` + `Processing [ITU-T T.125] Connect-Initial failed`. Ursache: xrdp 0.9.21+ mit OpenSSL 3.x ist inkompatibel mit `security_layer=negotiate` + `crypt_level=high` für Guacamoles FreeRDP-Client. Fix in `/etc/xrdp/xrdp.ini`:
```ini
security_layer=tls   ; statt negotiate
crypt_level=low      ; statt high
```
Dann `systemctl restart xrdp`. Betrifft Ubuntu 24.04 mit xrdp 0.9.24.

### Rollback auf GNS3 2.2.x

```bash
systemctl stop gns3-server
systemctl disable gns3-server

# Backup wiederherstellen (falls vorhanden)
rsync -av /root/gns3_backup_20260202/GNS3/ /home/academy/GNS3/
rsync -av /root/gns3_backup_20260202/config_GNS3/ /home/academy/.config/GNS3/

# GNS3 2.2 ist noch installiert und kann normal gestartet werden
```

---

## Bekannte Unterschiede GNS3 2.x vs 3.x

| Thema | 2.x | 3.x |
|---|---|---|
| Interface | Desktop-App | Web-UI (Browser) |
| Authentifizierung | Einfache Passwörter | JWT-Tokens |
| Validierung | Tolerant | Streng (z.B. ethertype) |
| Setup | Standalone | `--local` Flag für All-in-One |
| API | `/v2/` | `/v3/` |
