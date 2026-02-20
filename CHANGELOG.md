# Changelog

Alle wesentlichen Änderungen an diesem Projekt werden hier dokumentiert.

---

## [2026-02-20] – UserScript.py: RDP-Credentials und Security-Mode Fix

### Behoben
- **Guacamole RDP-Verbindung funktioniert nicht**: RDP-Credentials (`username: academy`, `password: academy`) werden nun automatisch in die Guacamole-Verbindung eingetragen. Diese Credentials entsprechen dem Standard-User im LXC-Template 135.
- **Security-Mode von `nla` auf `tls` geändert**: `nla` (Network Level Authentication) ist mit xrdp im Template inkompatibel. `tls` funktioniert korrekt.

---

## [2026-02-20] – UserScript.py: Vollständige Bugfix-Session

### Behoben
- **Proxmox Container startet nicht (HTTP 501)**
  - Ursache 1: `http_request()` mutierte das übergebene `headers`-Dict in-place. Nach einem Request mit Body (z.B. `configure_network`) enthielt `self.headers` dauerhaft `Content-Type: application/json`, das auch bei späteren Requests ohne Body mitgesendet wurde.
  - Ursache 2: `Content-Type: application/json` wurde auch gesetzt wenn kein Body vorhanden war. Proxmox lehnte POST-Requests auf `/status/start` und `/status/stop` mit diesem Header ab.
  - Fix: `headers`-Dict wird nun kopiert (`dict(headers)`) und `Content-Type` nur gesetzt wenn `body is not None`.
  - Fix: `start_container()` und `stop_container()` senden kein leeres `data={}` mehr.

- **GNS3 nicht erreichbar (No route to host)**
  - Ursache: IP-Adresse hatte sich per DHCP von `100.64.0.73` auf `100.64.0.80` geändert.
  - Fix: `GNS3_HOST` aktualisiert.

- **Guacamole-Verbindung schlägt fehl (HTTP 403 Permission denied)**
  - Ursache: Script authentifizierte sich mit dem allgemeinen Keycloak-Admin (`admin`), der keine Adminrechte im Guacamole MySQL-Datasource besitzt.
  - Fix: Separate Konfigurationsvariablen `GUACAMOLE_KEYCLOAK_USER` / `GUACAMOLE_KEYCLOAK_PASS` für den Guacamole OIDC-Login. Verwendet wird der Keycloak-User `guacadmin`, der in Guacamoles MySQL-Datasource vollständige Adminrechte hat.
  - Voraussetzung: Pflichtaktion `UPDATE_PASSWORD` für den Keycloak-User `guacadmin` muss in der Keycloak-Admin-UI entfernt sein.

- **Guacamole-Berechtigung schlägt fehl (HTTP 404 Not found)**
  - Ursache: OIDC-User existieren in Guacamoles MySQL-Datenbank erst nach dem ersten Login. `assign_connection_to_user()` schlug daher immer fehl.
  - Fix: Neue Methode `Guacamole.create_user()` legt den User vorab im MySQL-Datasource an, damit Berechtigungen direkt beim Provisionieren zugewiesen werden können.

### Hinzugefügt
- `Guacamole.create_user()`: Legt User im mysql-Datasource an (für Berechtigungszuweisung vor erstem Login).
- `Guacamole.authenticate()`: Versucht zuerst lokalen Login, fällt auf OIDC zurück (bei OIDC-only Setups immer OIDC).
- OIDC-Login gibt nun den verwendeten `datasource` aus (Diagnosehilfe).

---

## [2026-02-18] – UserScript.py: Stabilisierung und Erweiterungen

### Behoben
- **GNS3-Projekte konnten nicht dupliziert werden**: Nodes werden nun vor dem Schließen gestoppt.
- **Token-Ablauf bei langen Läufen**: Keycloak, GNS3 und Guacamole werden vor jedem User neu authentifiziert.
- **Proxmox Template-ID**: Von 133 auf 135 (ClientTemplate) korrigiert.
- **Proxmox DNS-Konfiguration**: Netzwerkeinstellungen für Container korrigiert.
- **Guacamole OIDC-Authentifizierung**: Initialer OIDC Implicit Flow implementiert.

### Hinzugefügt
- Parameter `--name` für einzelne User-Provisionierung.
- Parameter `--projects` zur Auswahl spezifischer GNS3-Projekte.

### Dokumentation
- README überarbeitet: GNS3-Migration und Automatisierung dokumentiert.
- xrdp/Guacamole RDP-Verbindungsproblem (OpenSSL 3.x) dokumentiert.
- OS-Version auf Ubuntu 24.04.4 LTS aktualisiert.

---

## [2026-02-11] – UserScript.py: Initiale Version

### Hinzugefügt
- Komplett-Provisionierungs-Script für Schulungsumgebungen.
- Automatisierte Erstellung von:
  - LXC-Container (Klon von Proxmox-Template)
  - Keycloak-User (SSO Login)
  - GNS3-User mit Projektkopien und ACL
  - Guacamole-RDP-Verbindung mit Berechtigung
- Befehle: `create`, `list`, `delete`

---

## [2026-02-06] – manage_users.py und Dokumentation

### Hinzugefügt
- `manage_users.py`: Multi-User-Verwaltung für GNS3-Schulungen.
- Troubleshooting-Dokumentation für häufige GNS3 3.x Probleme.

---

## [2026-02-04] – Initiales Release

### Hinzugefügt
- GNS3 3.0.5 Upgrade-Dokumentation (von 2.2.44.1).
- Upgrade-Schritte: Backup, Python-Venv, Konfiguration, Systemd-Service, Passwort-Reset, Projektdatei-Reparatur.
- Bekannte Unterschiede GNS3 2.x vs. 3.x.
- Rollback-Anleitung.
