#!/usr/bin/env python3
"""
Schulungs-Provisionierung - Komplett-Skript
=============================================
Erstellt für jeden Teilnehmer:
  1. LXC-Container (Klon von Template) auf Proxmox
  2. Keycloak-User (SSO Login)
  3. GNS3-User mit Projektkopien und ACL
  4. Guacamole-RDP-Verbindung mit Berechtigung

Verwendung:
  ./provision_training.py create --users 5                     # 5 Teilnehmer (user1-user5)
  ./provision_training.py create --users 3 --prefix student    # student1-student3
  ./provision_training.py list                                 # Übersicht aller Teilnehmer
  ./provision_training.py delete --prefix user                 # Alle user* löschen (inkl. VMs)
  ./provision_training.py delete --name user3                  # Einzelnen User löschen

Voraussetzungen:
  - Proxmox API Token
  - Keycloak Admin-Zugang
  - GNS3 Admin-Zugang
  - Guacamole Admin-Zugang
"""

import argparse
import http.cookiejar
import json
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# =============================================================================
# KONFIGURATION - HIER ANPASSEN
# =============================================================================

# --- Proxmox ---
PROXMOX_HOST = "https://10.128.10.1:8006"
PROXMOX_NODE = "proxmox01a"
PROXMOX_TOKEN = "root@pam!UserScript=8c1bab2b-2a4d-428a-a94c-5ab1a2e5a250"
PROXMOX_TEMPLATE_ID = 201
PROXMOX_BRIDGE = "vmbr2"
PROXMOX_START_VMID = 200       # Ab welcher ID neue Container erstellt werden
PROXMOX_STORAGE = "neuer-pool-storage"  # ZFS pool with available space

# --- Keycloak ---
KEYCLOAK_HOST = "https://auth.academy.nocware.com"
KEYCLOAK_REALM = "master"
KEYCLOAK_ADMIN_USER = "admin"
KEYCLOAK_ADMIN_PASS = "6QAG9N3XZa00JPgyy4TY"  # <-- ANPASSEN

# --- GNS3 ---
GNS3_HOST = "http://100.64.0.80:3080"
GNS3_ADMIN_USER = "admin"
GNS3_ADMIN_PASS = "admin123"

# GNS3 Master-Projekte (werden pro User dupliziert)
GNS3_MASTER_PROJECTS = {
    "SSRBasic": "c0518772-8dbe-4b65-ac16-04779af3bac7",
    "TalentLab": "a786a84b-b926-41f1-a26e-73e908117d08",
}

# GNS3 Built-in Role IDs
GNS3_ROLE_USER = "1ac9799b-4e41-4968-8a4a-3b26cfa40a91"

# --- Guacamole ---
GUACAMOLE_HOST = "https://lab.nocware.com"
GUACAMOLE_ADMIN_USER = "guacadmin"
GUACAMOLE_ADMIN_PASS = "3JSalbY84Se6nUOaB6SN"  # lokaler Login (deaktiviert bei OIDC-only)
GUACAMOLE_DATASOURCE = "mysql"  # oder "postgresql"
# Keycloak-User für Guacamole OIDC-Login (muss guacadmin-Rechte in Guacamole haben)
GUACAMOLE_KEYCLOAK_USER = "guacadmin"
GUACAMOLE_KEYCLOAK_PASS = "nYVBO4aY0i"

# --- Allgemein ---
DEFAULT_PASSWORD = "schulung123"

# =============================================================================
# SSL-Kontext (Self-signed Certs akzeptieren)
# =============================================================================
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE


# =============================================================================
# HILFSFUNKTIONEN
# =============================================================================

def http_request(method, url, headers=None, data=None, timeout=300):
    """Universeller HTTP-Request mit SSL-Support."""
    headers = dict(headers) if headers else {}

    body = json.dumps(data).encode() if data and isinstance(data, (dict, list)) else data
    if body is not None:
        headers.setdefault("Content-Type", "application/json")
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=SSL_CTX) as resp:
            if resp.status == 204:
                return None
            raw = resp.read().decode()
            if raw:
                return json.loads(raw)
            return None
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        print(f"    HTTP {e.code} bei {method} {url}: {error_body[:300]}")
        return None
    except Exception as e:
        print(f"    Fehler bei {method} {url}: {e}")
        return None


# =============================================================================
# PROXMOX - LXC Container Verwaltung
# =============================================================================

class Proxmox:
    def __init__(self):
        self.headers = {"Authorization": f"PVEAPIToken={PROXMOX_TOKEN}"}

    def _api(self, method, path, data=None):
        url = f"{PROXMOX_HOST}/api2/json{path}"
        return http_request(method, url, headers=self.headers, data=data)

    def get_next_vmid(self):
        """Nächste freie VMID ab PROXMOX_START_VMID holen."""
        result = self._api("GET", "/cluster/resources?type=vm")
        if not result or "data" not in result:
            return PROXMOX_START_VMID

        used_ids = {r["vmid"] for r in result["data"]}
        vmid = PROXMOX_START_VMID
        while vmid in used_ids:
            vmid += 1
        return vmid

    def unlock_container(self, vmid):
        """Lock von Container entfernen."""
        self._api("PUT", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/config", data={"delete": "lock"})

    def clone_container(self, new_vmid, hostname):
        """LXC Container aus Template klonen. Returns UPID string or None."""
        # Template entsperren falls von vorherigem Fehlversuch gesperrt
        self.unlock_container(PROXMOX_TEMPLATE_ID)
        time.sleep(1)

        data = {
            "newid": new_vmid,
            "hostname": hostname,
            "full": 1,
            "storage": PROXMOX_STORAGE,
        }
        result = self._api(
            "POST",
            f"/nodes/{PROXMOX_NODE}/lxc/{PROXMOX_TEMPLATE_ID}/clone",
            data=data,
        )
        if result and "data" in result and result["data"]:
            return result["data"]  # UPID string
        return None

    def configure_network(self, vmid):
        """Netzwerk auf DHCP setzen (vmbr2)."""
        data = {
            "net0": f"name=eth0,bridge={PROXMOX_BRIDGE},ip=dhcp,firewall=0",
        }
        return self._api("PUT", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/config", data=data)

    def start_container(self, vmid):
        """Container starten."""
        return self._api("POST", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/status/start")

    def stop_container(self, vmid):
        """Container stoppen."""
        return self._api("POST", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/status/stop")

    def delete_container(self, vmid):
        """Container löschen (muss gestoppt sein)."""
        self.stop_container(vmid)
        time.sleep(3)
        return self._api("DELETE", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}?purge=1&force=1")

    def get_container_ip(self, vmid, retries=12, interval=10):
        """IP-Adresse des Containers auslesen (wartet auf DHCP).

        Gibt gezielt die IP von eth0 zurück (vmbr2-Interface, DHCP).
        Andere Interfaces (docker0, virbr0, internal) werden ignoriert.
        """
        print(f"    Warte auf IP-Adresse (max {retries * interval}s)...", end="", flush=True)
        for i in range(retries):
            result = self._api("GET", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/interfaces")
            if result and result.get("data"):
                ifaces = result["data"]
                # Erst gezielt eth0 suchen (konfiguriertes vmbr2-Interface)
                for iface in ifaces:
                    if iface.get("name") == "eth0" and iface.get("inet"):
                        ip = iface["inet"].split("/")[0]
                        print(f" {ip} (eth0)")
                        return ip
            print(".", end="", flush=True)
            time.sleep(interval)
        print(" TIMEOUT!")
        return None

    def get_all_containers(self):
        """Alle LXC-Container auf dem Node auflisten."""
        result = self._api("GET", f"/nodes/{PROXMOX_NODE}/lxc")
        return result.get("data", []) if result else []

    def wait_for_task(self, upid, timeout=600):
        """Auf Proxmox-Task warten."""
        if not upid:
            return True
        encoded_upid = urllib.parse.quote(upid, safe="")
        start = time.time()
        while time.time() - start < timeout:
            result = self._api("GET", f"/nodes/{PROXMOX_NODE}/tasks/{encoded_upid}/status")
            if result and result.get("data", {}).get("status") == "stopped":
                exitstatus = result["data"].get("exitstatus", "")
                if exitstatus == "OK":
                    return True
                print(f"    Task fehlgeschlagen: {exitstatus}")
                return False
            time.sleep(5)
        return False


# =============================================================================
# KEYCLOAK - Benutzerverwaltung
# =============================================================================

class Keycloak:
    def __init__(self):
        self.token = None

    def authenticate(self):
        """Admin-Token holen."""
        url = f"{KEYCLOAK_HOST}/realms/master/protocol/openid-connect/token"
        data = (
            f"grant_type=password"
            f"&client_id=admin-cli"
            f"&username={KEYCLOAK_ADMIN_USER}"
            f"&password={KEYCLOAK_ADMIN_PASS}"
        ).encode()

        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        result = http_request("POST", url, headers=headers, data=data)

        if result and "access_token" in result:
            self.token = result["access_token"]
            return True
        print("    FEHLER: Keycloak-Authentifizierung fehlgeschlagen!")
        return False

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def create_user(self, username, password, email=None):
        """User in Keycloak anlegen."""
        url = f"{KEYCLOAK_HOST}/admin/realms/{KEYCLOAK_REALM}/users"
        data = {
            "username": username,
            "email": email or f"{username}@schulung.lab",
            "enabled": True,
            "emailVerified": True,
            "credentials": [{
                "type": "password",
                "value": password,
                "temporary": False,
            }],
        }
        result = http_request("POST", url, headers=self._headers(), data=data)
        # Keycloak gibt 201 ohne Body zurück - User-ID aus Location-Header holen
        # Wir holen stattdessen den User per Username
        return self.get_user_by_username(username)

    def get_user_by_username(self, username):
        """User-ID anhand des Usernamens finden."""
        url = f"{KEYCLOAK_HOST}/admin/realms/{KEYCLOAK_REALM}/users?username={username}&exact=true"
        result = http_request("GET", url, headers=self._headers())
        if result and len(result) > 0:
            return result[0]
        return None

    def delete_user(self, user_id):
        """User löschen."""
        url = f"{KEYCLOAK_HOST}/admin/realms/{KEYCLOAK_REALM}/users/{user_id}"
        return http_request("DELETE", url, headers=self._headers())

    def get_all_users(self):
        """Alle User im Realm auflisten."""
        url = f"{KEYCLOAK_HOST}/admin/realms/{KEYCLOAK_REALM}/users?max=1000"
        return http_request("GET", url, headers=self._headers()) or []


# =============================================================================
# GNS3 - Benutzerverwaltung (aus bestehendem Skript integriert)
# =============================================================================

class GNS3:
    def __init__(self):
        self.token = None

    def authenticate(self):
        """Admin-Token holen."""
        result = http_request("POST", f"{GNS3_HOST}/v3/access/users/authenticate", data={
            "username": GNS3_ADMIN_USER,
            "password": GNS3_ADMIN_PASS,
        })
        if result and "access_token" in result:
            self.token = result["access_token"]
            return True
        print("    FEHLER: GNS3-Authentifizierung fehlgeschlagen!")
        return False

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }

    def create_user(self, username, password):
        """GNS3-User erstellen."""
        result = http_request("POST", f"{GNS3_HOST}/v3/access/users", headers=self._headers(), data={
            "username": username,
            "password": password,
            "is_active": True,
            "email": f"{username}@schulung.lab",
            "full_name": username.capitalize(),
        })
        return result

    def stop_nodes(self, project_id):
        """Alle Nodes eines Projekts stoppen."""
        http_request("POST", f"{GNS3_HOST}/v3/projects/{project_id}/nodes/stop", headers=self._headers())

    def close_project(self, project_id):
        """Projekt schließen."""
        http_request("POST", f"{GNS3_HOST}/v3/projects/{project_id}/close", headers=self._headers())

    def duplicate_project(self, project_id, new_name):
        """Projekt duplizieren."""
        return http_request(
            "POST",
            f"{GNS3_HOST}/v3/projects/{project_id}/duplicate",
            headers=self._headers(),
            data={"name": new_name},
        )

    def create_acl(self, user_id, path, role_id, propagate=True, allowed=True):
        """ACL-Eintrag erstellen."""
        return http_request("POST", f"{GNS3_HOST}/v3/access/acl", headers=self._headers(), data={
            "ace_type": "user",
            "user_id": user_id,
            "path": path,
            "role_id": role_id,
            "propagate": propagate,
            "allowed": allowed,
        })

    def setup_user_projects(self, user_id, username, projects=None):
        """Projekte duplizieren und ACL setzen (Logik aus bestehendem Skript)."""
        if projects is None:
            projects = GNS3_MASTER_PROJECTS
        user_projects = []

        # Master-Projekte stoppen, schließen und duplizieren
        for proj_name, proj_id in projects.items():
            self.stop_nodes(proj_id)
            time.sleep(2)
            self.close_project(proj_id)
            time.sleep(1)
            dup_name = f"{proj_name}_{username}"
            dup = self.duplicate_project(proj_id, dup_name)
            if dup:
                user_projects.append(dup)
                print(f"    GNS3-Projekt '{dup_name}' erstellt")
            time.sleep(1)

        # ACL: Basis-Zugriff
        self.create_acl(user_id, "/", GNS3_ROLE_USER, propagate=True, allowed=True)

        # ACL: Master-Projekte sperren
        for master_name, master_pid in projects.items():
            self.create_acl(user_id, f"/projects/{master_pid}", GNS3_ROLE_USER, propagate=True, allowed=False)

        # ACL: Eigene Projekte erlauben
        for proj in user_projects:
            self.create_acl(user_id, f"/projects/{proj['project_id']}", GNS3_ROLE_USER, propagate=True, allowed=True)

        return user_projects

    def get_all_users(self):
        return http_request("GET", f"{GNS3_HOST}/v3/access/users", headers=self._headers()) or []

    def get_all_projects(self):
        return http_request("GET", f"{GNS3_HOST}/v3/projects", headers=self._headers()) or []

    def get_all_acl(self):
        return http_request("GET", f"{GNS3_HOST}/v3/access/acl", headers=self._headers()) or []

    def delete_user(self, user_id):
        return http_request("DELETE", f"{GNS3_HOST}/v3/access/users/{user_id}", headers=self._headers())

    def delete_project(self, project_id):
        self.close_project(project_id)
        time.sleep(1)
        return http_request("DELETE", f"{GNS3_HOST}/v3/projects/{project_id}", headers=self._headers())

    def delete_acl(self, ace_id):
        return http_request("DELETE", f"{GNS3_HOST}/v3/access/acl/{ace_id}", headers=self._headers())


# =============================================================================
# GUACAMOLE - Verbindungsverwaltung
# =============================================================================

class Guacamole:
    def __init__(self):
        self.token = None
        self.datasource = GUACAMOLE_DATASOURCE

    def authenticate(self):
        """Admin-Token holen - erst lokaler Login, dann OIDC als Fallback."""
        local_data = urllib.parse.urlencode({
            "username": GUACAMOLE_ADMIN_USER,
            "password": GUACAMOLE_ADMIN_PASS,
        }).encode()
        result = http_request(
            "POST",
            f"{GUACAMOLE_HOST}/api/tokens",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=local_data,
        )
        if result and "authToken" in result:
            self.token = result["authToken"]
            self.datasource = result.get("dataSource", GUACAMOLE_DATASOURCE)
            return True
        # Fallback: Keycloak OIDC Implicit Flow
        return self._authenticate_oidc()

    def _authenticate_oidc(self):
        """Admin-Token via Keycloak OIDC Implicit Flow holen.

        Guacamole nutzt OpenID Connect mit Nonce-Validierung. Der Flow ist:
        1. POST an Guacamole /api/tokens -> 403 mit Redirect-URL inkl. Nonce
        2. GET Keycloak Auth-Seite -> Login-Formular
        3. POST Credentials an Keycloak -> Redirect mit id_token im Fragment
        4. POST id_token an Guacamole /api/tokens -> authToken
        """
        try:
            cj = http.cookiejar.CookieJar()
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                urllib.request.HTTPCookieProcessor(cj),
            )

            # Schritt 1: Nonce von Guacamole holen
            req = urllib.request.Request(
                f"{GUACAMOLE_HOST}/api/tokens",
                data=b"",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                opener.open(req, timeout=10)
            except urllib.error.HTTPError as e:
                body = json.loads(e.read().decode())
                expected = body.get("expected", [])
                if not expected or "redirectUrl" not in expected[0]:
                    print("    FEHLER: Guacamole OIDC-Redirect nicht erhalten!")
                    return False
                redirect_url = expected[0]["redirectUrl"]

            parsed = urllib.parse.urlparse(redirect_url)
            qs = urllib.parse.parse_qs(parsed.query)
            nonce = qs["nonce"][0]

            # Schritt 2: Keycloak Login-Seite laden
            with opener.open(urllib.request.Request(redirect_url), timeout=10) as resp:
                html = resp.read().decode()
            action_match = re.search(r'action="([^"]+)"', html)
            if not action_match:
                print("    FEHLER: Keycloak Login-Formular nicht gefunden!")
                return False
            action_url = action_match.group(1).replace("&amp;", "&")

            # Schritt 3: Credentials an Keycloak senden, Redirect abfangen
            class _RedirectCatcher(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    self.redirect_url = newurl
                    raise urllib.error.HTTPError(newurl, code, msg, headers, fp)

            catcher = _RedirectCatcher()
            login_opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=SSL_CTX),
                urllib.request.HTTPCookieProcessor(cj),
                catcher,
            )
            login_data = urllib.parse.urlencode({
                "username": GUACAMOLE_KEYCLOAK_USER,
                "password": GUACAMOLE_KEYCLOAK_PASS,
            }).encode()
            login_req = urllib.request.Request(
                action_url,
                data=login_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                method="POST",
            )
            try:
                login_opener.open(login_req, timeout=10)
                print("    FEHLER: Keycloak-Login hat keinen Redirect ausgelöst!")
                return False
            except urllib.error.HTTPError as e:
                location = e.headers.get("Location", "") or getattr(catcher, "redirect_url", "")

            if "#" not in location:
                print("    FEHLER: Keycloak-Redirect enthält kein id_token-Fragment!")
                return False

            fragment = location.split("#", 1)[1]
            frag_params = urllib.parse.parse_qs(fragment)
            id_token = frag_params.get("id_token", [None])[0]
            if not id_token:
                print("    FEHLER: Kein id_token im Keycloak-Redirect!")
                return False

            # Schritt 4: id_token an Guacamole übergeben
            guac_data = f"id_token={id_token}".encode()
            result = http_request(
                "POST",
                f"{GUACAMOLE_HOST}/api/tokens",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data=guac_data,
            )
            if result and "authToken" in result:
                self.token = result["authToken"]
                self.datasource = result.get("dataSource", GUACAMOLE_DATASOURCE)
                print(f"    OIDC-Login: datasource='{self.datasource}'")
                return True
            print("    FEHLER: Guacamole hat das Keycloak-Token abgelehnt!")
            return False

        except Exception as e:
            print(f"    FEHLER: Guacamole-Authentifizierung fehlgeschlagen: {e}")
            return False

    def _url(self, path):
        return f"{GUACAMOLE_HOST}/api/session/data/{GUACAMOLE_DATASOURCE}{path}?token={self.token}"

    def create_connection(self, name, hostname, port=3389, protocol="rdp"):
        """RDP-Verbindung erstellen."""
        data = {
            "parentIdentifier": "ROOT",
            "name": name,
            "protocol": protocol,
            "parameters": {
                "hostname": hostname,
                "port": str(port),
                "security": "tls",
                "ignore-cert": "true",
                "resize-method": "display-update",
                "username": "academy",
                "password": "academy",
            },
            "attributes": {
                "max-connections": "2",
                "max-connections-per-user": "2",
            },
        }
        result = http_request("POST", self._url("/connections"), data=data)
        return result

    def create_user(self, username):
        """User in Guacamole anlegen (damit Berechtigungen vor erstem Login zuweisbar sind)."""
        return http_request("POST", self._url("/users"), data={"username": username, "attributes": {}})

    def assign_connection_to_user(self, username, connection_id):
        """User Zugriff auf eine Verbindung geben."""
        url = f"{GUACAMOLE_HOST}/api/session/data/{GUACAMOLE_DATASOURCE}/users/{username}/permissions?token={self.token}"
        data = [{
            "op": "add",
            "path": f"/connectionPermissions/{connection_id}",
            "value": "READ",
        }]
        return http_request("PATCH", url, data=data)

    def delete_connection(self, connection_id):
        """Verbindung löschen."""
        url = self._url(f"/connections/{connection_id}")
        return http_request("DELETE", url)

    def get_all_connections(self):
        """Alle Verbindungen auflisten."""
        result = http_request("GET", self._url("/connections"))
        return result if result else {}

    def get_user_permissions(self, username):
        """Berechtigungen eines Users auslesen."""
        url = f"{GUACAMOLE_HOST}/api/session/data/{GUACAMOLE_DATASOURCE}/users/{username}/permissions?token={self.token}"
        return http_request("GET", url)


# =============================================================================
# KOMMANDOS
# =============================================================================

def cmd_create(args):
    """Komplette Provisionierung: VM + Keycloak + GNS3 + Guacamole."""
    password = args.password or DEFAULT_PASSWORD

    # Username-Liste aufbauen
    if args.name:
        usernames = [args.name]
    else:
        usernames = [f"{args.prefix}{i}" for i in range(1, args.users + 1)]

    # Projekte filtern
    if args.projects:
        selected_projects = {k: v for k, v in GNS3_MASTER_PROJECTS.items() if k in args.projects}
    else:
        selected_projects = GNS3_MASTER_PROJECTS

    # Alle Dienste authentifizieren
    print("\n[0/5] Authentifizierung bei allen Diensten...")
    pve = Proxmox()
    kc = Keycloak()
    gns3 = GNS3()
    guac = Guacamole()

    if not kc.authenticate():
        sys.exit(1)
    print("  ✓ Keycloak")

    if not gns3.authenticate():
        sys.exit(1)
    print("  ✓ GNS3")

    if not guac.authenticate():
        sys.exit(1)
    print("  ✓ Guacamole")
    print("  ✓ Proxmox (Token-Auth)")

    results = []

    for username in usernames:
        print(f"\n{'='*60}")
        print(f"  Provisioniere: {username}")
        print(f"{'='*60}")

        # --- 1. PROXMOX: Container klonen ---
        print(f"\n[1/5] Proxmox - Container erstellen...")
        vmid = pve.get_next_vmid()
        hostname = f"training-{username}"

        print(f"    Klone Template {PROXMOX_TEMPLATE_ID} -> CT {vmid} ({hostname})...")
        upid = pve.clone_container(vmid, hostname)
        if not upid:
            print(f"    FEHLER beim Klonen! Überspringe {username}.")
            continue

        # Warten bis Klon fertig (67GB, dauert ca. 8-10 Minuten)
        print(f"    Warte auf Abschluss des Klonvorgangs...")
        if not pve.wait_for_task(upid, timeout=900):
            print(f"    FEHLER: Klonvorgang nicht abgeschlossen! Räume auf...")
            pve.unlock_container(vmid)
            pve.delete_container(vmid)
            pve.unlock_container(PROXMOX_TEMPLATE_ID)
            print(f"    Überspringe {username}.")
            continue
        print(f"    ✓ Klon abgeschlossen")

        # Protection deaktivieren (vom Template geerbt)
        pve._api("PUT", f"/nodes/{PROXMOX_NODE}/lxc/{vmid}/config", data={"protection": 0})
        print(f"    Netzwerk vom Template übernommen (DHCP auf {PROXMOX_BRIDGE})")

        # Container starten
        pve.start_container(vmid)
        print(f"    Container {vmid} gestartet")

        # IP-Adresse warten
        container_ip = pve.get_container_ip(vmid)
        if not container_ip:
            print(f"    WARNUNG: Keine IP erhalten! Manuell prüfen.")
            container_ip = f"UNKNOWN-CT{vmid}"

        # --- 2. KEYCLOAK: User anlegen ---
        print(f"\n[2/5] Keycloak - User anlegen...")
        kc.authenticate()
        kc_user = kc.create_user(username, password)
        if kc_user:
            print(f"    ✓ Keycloak-User '{username}' erstellt (ID: {kc_user['id'][:8]}...)")
        else:
            print(f"    WARNUNG: Keycloak-User konnte nicht erstellt/gefunden werden")

        # --- 3. GNS3: User + Projekte ---
        print(f"\n[3/5] GNS3 - User und Projekte anlegen...")
        gns3.authenticate()
        gns3_user = gns3.create_user(username, password)
        if gns3_user:
            print(f"    ✓ GNS3-User '{username}' erstellt")
            gns3_projects = gns3.setup_user_projects(gns3_user["user_id"], username, selected_projects)
            print(f"    ✓ {len(gns3_projects)} Projekte dupliziert und berechtigt")
        else:
            print(f"    WARNUNG: GNS3-User konnte nicht erstellt werden")
            gns3_projects = []

        # --- 4. GUACAMOLE: RDP-Verbindung ---
        print(f"\n[4/5] Guacamole - RDP-Verbindung erstellen...")
        guac.authenticate()
        conn_name = f"Training-{username} (CT {vmid})"
        connection = guac.create_connection(conn_name, container_ip)
        if connection and "identifier" in connection:
            conn_id = connection["identifier"]
            print(f"    ✓ Verbindung '{conn_name}' erstellt (ID: {conn_id})")

            # User in Guacamole anlegen (damit Berechtigung vor erstem Login zuweisbar ist)
            guac.create_user(username)
            guac.assign_connection_to_user(username, conn_id)
            print(f"    ✓ User '{username}' berechtigt")
        else:
            print(f"    WARNUNG: Guacamole-Verbindung konnte nicht erstellt werden")
            conn_id = None

        # --- 5. Zusammenfassung ---
        print(f"\n[5/5] ✓ {username} fertig provisioniert!")

        results.append({
            "username": username,
            "password": password,
            "vmid": vmid,
            "ip": container_ip,
            "hostname": hostname,
            "guac_connection": conn_id,
            "gns3_projects": [p["name"] for p in gns3_projects],
        })

    # Gesamtübersicht
    if results:
        print(f"\n{'='*80}")
        print("ZUSAMMENFASSUNG - Provisionierte Schulungsumgebungen")
        print(f"{'='*80}")
        print(f"{'Username':<12} {'Passwort':<14} {'CT-ID':<8} {'IP-Adresse':<16} {'Projekte'}")
        print(f"{'-'*80}")
        for r in results:
            projs = ", ".join(r["gns3_projects"][:2])
            if len(r["gns3_projects"]) > 2:
                projs += f" (+{len(r['gns3_projects'])-2})"
            print(f"{r['username']:<12} {r['password']:<14} {r['vmid']:<8} {r['ip']:<16} {projs}")
        print(f"{'-'*80}")
        print(f"  Teilnehmer: {len(results)}")
        print(f"  Guacamole:  {GUACAMOLE_HOST}")
        print(f"  Keycloak:   {KEYCLOAK_HOST}")
        print(f"  GNS3:       {GNS3_HOST}")
        print()


def cmd_list(args):
    """Übersicht aller provisionierten Umgebungen."""
    pve = Proxmox()
    kc = Keycloak()
    gns3 = GNS3()
    guac = Guacamole()

    print("\nAuthentifizierung...", end=" ")
    kc.authenticate()
    gns3.authenticate()
    guac.authenticate()
    print("OK\n")

    # Proxmox Container mit "training-" Prefix
    containers = pve.get_all_containers()
    training_cts = [c for c in containers if c.get("name", "").startswith("training-")]

    # Keycloak Users
    kc_users = kc.get_all_users()

    # GNS3 Users
    gns3_users = gns3.get_all_users()

    # Guacamole Connections
    guac_conns = guac.get_all_connections()

    print(f"{'Username':<14} {'Proxmox':<20} {'Keycloak':<10} {'GNS3':<10} {'Guacamole'}")
    print(f"{'-'*70}")

    # Alle Usernames sammeln (aus allen Quellen)
    usernames = set()
    for ct in training_cts:
        name = ct.get("name", "").replace("training-", "")
        if name:
            usernames.add(name)
    for u in gns3_users:
        if not u.get("is_superadmin"):
            usernames.add(u["username"])

    for username in sorted(usernames):
        ct = next((c for c in training_cts if c.get("name") == f"training-{username}"), None)
        ct_info = f"CT {ct['vmid']} ({ct.get('status', '?')})" if ct else "---"

        kc_found = any(u["username"] == username for u in kc_users)
        gns3_found = any(u["username"] == username for u in gns3_users)

        guac_found = False
        if isinstance(guac_conns, dict):
            guac_found = any(f"Training-{username}" in c.get("name", "") for c in guac_conns.values())

        print(f"{username:<14} {ct_info:<20} {'✓' if kc_found else '✗':<10} {'✓' if gns3_found else '✗':<10} {'✓' if guac_found else '✗'}")


def cmd_delete(args):
    """User und alle zugehörigen Ressourcen löschen."""
    pve = Proxmox()
    kc = Keycloak()
    gns3 = GNS3()
    guac = Guacamole()

    print("\nAuthentifizierung...", end=" ")
    kc.authenticate()
    gns3.authenticate()
    guac.authenticate()
    print("OK\n")

    # Ziel-Usernames ermitteln
    gns3_users = gns3.get_all_users()
    if args.name:
        targets = [args.name]
    else:
        targets = [
            u["username"] for u in gns3_users
            if u["username"].startswith(args.prefix) and not u.get("is_superadmin")
        ]

    if not targets:
        print("Keine passenden User gefunden.")
        return

    print("Folgende User werden komplett gelöscht (inkl. Container):")
    for t in targets:
        print(f"  - {t}")

    confirm = input("\nFortfahren? (j/N): ").strip().lower()
    if confirm != "j":
        print("Abgebrochen.")
        return

    containers = pve.get_all_containers()
    guac_conns = guac.get_all_connections()
    gns3_acl = gns3.get_all_acl()
    gns3_projects = gns3.get_all_projects()
    master_pids = set(GNS3_MASTER_PROJECTS.values())

    for username in targets:
        print(f"\n--- Lösche {username} ---")

        # 1. Proxmox Container löschen
        ct = next((c for c in containers if c.get("name") == f"training-{username}"), None)
        if ct:
            print(f"  Proxmox: Lösche CT {ct['vmid']}...")
            pve.delete_container(ct["vmid"])
            print(f"  ✓ Container gelöscht")
        else:
            print(f"  Proxmox: Kein Container gefunden")

        # 2. Keycloak User löschen
        kc_user = kc.get_user_by_username(username)
        if kc_user:
            kc.delete_user(kc_user["id"])
            print(f"  ✓ Keycloak-User gelöscht")
        else:
            print(f"  Keycloak: User nicht gefunden")

        # 3. GNS3 User + Projekte + ACL löschen
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
                                print(f"  ✓ GNS3-Projekt '{proj['name']}' gelöscht")
                    gns3.delete_acl(ace["ace_id"])
            gns3.delete_user(uid)
            print(f"  ✓ GNS3-User gelöscht")
        else:
            print(f"  GNS3: User nicht gefunden")

        # 4. Guacamole Verbindung löschen
        if isinstance(guac_conns, dict):
            for conn_id, conn in guac_conns.items():
                if f"Training-{username}" in conn.get("name", ""):
                    guac.delete_connection(conn_id)
                    print(f"  ✓ Guacamole-Verbindung gelöscht")
                    break
            else:
                print(f"  Guacamole: Keine Verbindung gefunden")

    print("\n✓ Löschvorgang abgeschlossen.")


# =============================================================================
# MAIN
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Schulungs-Provisionierung - Komplett-Skript",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    # create
    p_create = sub.add_parser("create", help="Teilnehmer komplett provisionieren")
    name_group = p_create.add_mutually_exclusive_group(required=True)
    name_group.add_argument("--name", help="Einzelner Username (explizit)")
    name_group.add_argument("--users", type=int, help="Anzahl Teilnehmer (mit --prefix)")
    p_create.add_argument("--prefix", default="user", help="Username-Prefix (default: user)")
    p_create.add_argument("--password", default=None, help=f"Passwort (default: {DEFAULT_PASSWORD})")
    p_create.add_argument(
        "--projects", nargs="+", default=None,
        metavar="PROJEKT",
        help=f"Zu klonende Projekte (default: alle). Erlaubt: {', '.join(GNS3_MASTER_PROJECTS)}",
    )

    # list
    sub.add_parser("list", help="Übersicht aller Schulungsumgebungen")

    # delete
    p_delete = sub.add_parser("delete", help="Teilnehmer komplett löschen")
    p_delete.add_argument("--prefix", default=None, help="Alle User mit Prefix löschen")
    p_delete.add_argument("--name", default=None, help="Einzelnen User löschen")

    args = parser.parse_args()

    if args.command == "create":
        if args.name and args.prefix != "user":
            print("WARNUNG: --prefix wird ignoriert wenn --name angegeben ist.")
        if args.projects:
            unknown = [p for p in args.projects if p not in GNS3_MASTER_PROJECTS]
            if unknown:
                print(f"FEHLER: Unbekannte Projekte: {', '.join(unknown)}")
                print(f"  Verfügbar: {', '.join(GNS3_MASTER_PROJECTS)}")
                sys.exit(1)
        cmd_create(args)
    elif args.command == "list":
        cmd_list(args)
    elif args.command == "delete":
        if not args.prefix and not args.name:
            print("FEHLER: --prefix oder --name angeben!")
            sys.exit(1)
        cmd_delete(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
