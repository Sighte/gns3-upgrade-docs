#!/opt/gns3-venv/bin/python3.9
"""
GNS3 Multi-User Schulungsmanagement
====================================
Erstellt GNS3-User mit eigenen Projektkopien und passenden ACL-Rechten.

Verwendung:
  ./manage_users.py create --users 5                    # 5 User erstellen (user1-user5)
  ./manage_users.py create --users 3 --prefix student   # student1-student3
  ./manage_users.py create --users 1 --prefix test      # 1 Test-User
  ./manage_users.py list                                 # Alle User und Projekte anzeigen
  ./manage_users.py delete --prefix user                 # Alle user* User + Projekte löschen
  ./manage_users.py delete --name user3                  # Einzelnen User löschen
"""

import argparse
import json
import sys
import time
import urllib.request
import urllib.error

GNS3_HOST = "http://127.0.0.1:3080"
ADMIN_USER = "admin"
ADMIN_PASS = 'Y~u[4hw1(N&]eW*NOj5"0BLr(qysaFE7'

# Master-Projekte (werden dupliziert)
MASTER_PROJECTS = {
    "SSRBasic": "c0518772-8dbe-4b65-ac16-04779af3bac7",
    "TalentLab": "a786a84b-b926-41f1-a26e-73e908117d08",
    "SSRBGPBasic": "d34db245-d152-43fb-9f16-c6562e61c17d",
}

# GNS3 Built-in Role IDs
ROLE_USER = "1ac9799b-4e41-4968-8a4a-3b26cfa40a91"
ROLE_NO_ACCESS = "837bd73e-90f9-471f-8df8-7c3d551fae4a"


def api_request(method, path, token=None, data=None):
    """GNS3 API Request."""
    url = f"{GNS3_HOST}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    body = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        error_body = e.read().decode() if e.fp else ""
        print(f"  API Fehler {e.code} bei {method} {path}: {error_body[:200]}")
        return None


def get_token():
    """Admin-Token holen."""
    result = api_request("POST", "/v3/access/users/authenticate", data={
        "username": ADMIN_USER,
        "password": ADMIN_PASS,
    })
    if not result or "access_token" not in result:
        print("FEHLER: Authentifizierung fehlgeschlagen!")
        sys.exit(1)
    return result["access_token"]


def get_all_users(token):
    """Alle User auflisten."""
    return api_request("GET", "/v3/access/users", token) or []


def get_all_projects(token):
    """Alle Projekte auflisten."""
    return api_request("GET", "/v3/projects", token) or []


def get_all_acl(token):
    """Alle ACL-Einträge auflisten."""
    return api_request("GET", "/v3/access/acl", token) or []


def close_project(token, project_id):
    """Projekt schließen."""
    api_request("POST", f"/v3/projects/{project_id}/close", token)


def create_user(token, username, password):
    """GNS3-User erstellen."""
    result = api_request("POST", "/v3/access/users", token, data={
        "username": username,
        "password": password,
        "is_active": True,
        "email": f"{username}@schulung.lab",
        "full_name": username.capitalize(),
    })
    if result:
        print(f"  User '{username}' erstellt (ID: {result['user_id'][:8]}...)")
    return result


def duplicate_project(token, project_id, new_name):
    """Projekt duplizieren."""
    print(f"  Dupliziere '{new_name}'...", end=" ", flush=True)
    result = api_request("POST", f"/v3/projects/{project_id}/duplicate", token, data={
        "name": new_name,
    })
    if result:
        print(f"OK (ID: {result['project_id'][:8]}...)")
    else:
        print("FEHLER!")
    return result


def create_acl(token, user_id, path, role_id, propagate=True, allowed=True):
    """ACL-Eintrag erstellen."""
    return api_request("POST", "/v3/access/acl", token, data={
        "ace_type": "user",
        "user_id": user_id,
        "path": path,
        "role_id": role_id,
        "propagate": propagate,
        "allowed": allowed,
    })


def delete_user(token, user_id):
    """User löschen."""
    return api_request("DELETE", f"/v3/access/users/{user_id}", token)


def delete_project(token, project_id):
    """Projekt löschen."""
    close_project(token, project_id)
    time.sleep(1)
    return api_request("DELETE", f"/v3/projects/{project_id}", token)


def delete_acl(token, ace_id):
    """ACL-Eintrag löschen."""
    return api_request("DELETE", f"/v3/access/acl/{ace_id}", token)


def cmd_create(args):
    """User mit Projekten erstellen."""
    token = get_token()
    default_password = args.password or "schulung123"

    # Master-Projekte schließen
    print("\n[1/4] Master-Projekte schließen...")
    for name, pid in MASTER_PROJECTS.items():
        close_project(token, pid)
        print(f"  {name} geschlossen")

    time.sleep(2)

    results = []

    for i in range(1, args.users + 1):
        username = f"{args.prefix}{i}"
        print(f"\n[2/4] User '{username}' erstellen...")

        # User erstellen
        user = create_user(token, username, default_password)
        if not user:
            print(f"  ÜBERSPRUNGEN (existiert bereits?)")
            continue

        user_id = user["user_id"]
        user_projects = []

        # Projekte duplizieren
        print(f"[3/4] Projekte für '{username}' duplizieren...")
        for proj_name, proj_id in MASTER_PROJECTS.items():
            dup_name = f"{proj_name}_{username}"
            dup = duplicate_project(token, proj_id, dup_name)
            if dup:
                user_projects.append(dup)
            time.sleep(1)

        # ACL einrichten:
        # 1. User-Rolle auf / (Basis-Zugriff für API-Endpunkte)
        # 2. Deny auf Master-Projekte (User kann sie sehen, aber nicht öffnen)
        print(f"[4/4] Berechtigungen für '{username}' setzen...")

        # Basis-Zugriff
        create_acl(token, user_id, "/", ROLE_USER, propagate=True, allowed=True)
        print(f"  Basis-Zugriff gewährt")

        # Master-Projekte sperren
        for master_name, master_pid in MASTER_PROJECTS.items():
            create_acl(
                token, user_id,
                f"/projects/{master_pid}",
                ROLE_USER,
                propagate=True, allowed=False,
            )
            print(f"  Master '{master_name}' gesperrt")

        # Eigene Projekte explizit erlauben (überschreibt ggf. Deny)
        for proj in user_projects:
            create_acl(
                token, user_id,
                f"/projects/{proj['project_id']}",
                ROLE_USER,
                propagate=True, allowed=True,
            )
            print(f"  Zugriff auf '{proj['name']}' gewährt")

        results.append({
            "username": username,
            "password": default_password,
            "projects": [p["name"] for p in user_projects],
        })

    # Zusammenfassung
    if results:
        print("\n" + "=" * 60)
        print("ZUSAMMENFASSUNG - Erstellte Schulungs-Accounts")
        print("=" * 60)
        print(f"{'Username':<15} {'Passwort':<15} {'Projekte'}")
        print("-" * 60)
        for r in results:
            projs = ", ".join(r["projects"])
            print(f"{r['username']:<15} {r['password']:<15} {projs}")
        print("-" * 60)
        print(f"Web-UI: {GNS3_HOST}")
        print(f"Anzahl User: {len(results)}")
        print()


def cmd_list(args):
    """Alle User und zugehörige Projekte anzeigen."""
    token = get_token()
    users = get_all_users(token)
    projects = get_all_projects(token)
    acl_entries = get_all_acl(token)

    # ACL nach User-ID gruppieren
    user_acl = {}
    for ace in acl_entries:
        uid = ace.get("user_id")
        if uid:
            user_acl.setdefault(uid, []).append(ace)

    # Projekt-ID -> Name Mapping
    proj_map = {p["project_id"]: p["name"] for p in projects}

    print(f"\n{'Username':<15} {'Rolle':<12} {'Projekte'}")
    print("-" * 70)

    for user in users:
        uid = user["user_id"]
        role = "superadmin" if user["is_superadmin"] else "user"
        aces = user_acl.get(uid, [])

        proj_names = []
        for ace in aces:
            path = ace.get("path", "")
            if path.startswith("/projects/"):
                pid = path.replace("/projects/", "")
                name = proj_map.get(pid, pid[:8] + "...")
                proj_names.append(name)
            elif path == "/":
                proj_names.append("(alle - Pfad /)")

        projs = ", ".join(proj_names) if proj_names else "(keine ACL)"
        if user["is_superadmin"]:
            projs = "(alle - superadmin)"

        print(f"{user['username']:<15} {role:<12} {projs}")

    print(f"\n  Master-Projekte:")
    for name, pid in MASTER_PROJECTS.items():
        status = next((p["status"] for p in projects if p["project_id"] == pid), "?")
        print(f"    {name:<20} [{status}]  {pid}")

    total_projs = len(projects) - len(MASTER_PROJECTS)
    print(f"\n  {len(users)} User, {total_projs} duplizierte Projekte, {len(projects)} Projekte gesamt")


def cmd_delete(args):
    """User und zugehörige Projekte löschen."""
    token = get_token()
    users = get_all_users(token)
    projects = get_all_projects(token)
    acl_entries = get_all_acl(token)

    if args.name:
        targets = [u for u in users if u["username"] == args.name]
    else:
        targets = [u for u in users if u["username"].startswith(args.prefix) and not u["is_superadmin"]]

    if not targets:
        print("Keine passenden User gefunden.")
        return

    print(f"\nFolgende User werden gelöscht:")
    for u in targets:
        print(f"  - {u['username']}")

    confirm = input("\nFortfahren? (j/N): ").strip().lower()
    if confirm != "j":
        print("Abgebrochen.")
        return

    for user in targets:
        uid = user["user_id"]
        uname = user["username"]
        print(f"\n  Lösche '{uname}'...")

        # ACL-Einträge des Users finden und User-Projekte löschen
        master_pids = set(MASTER_PROJECTS.values())
        for ace in acl_entries:
            if ace.get("user_id") == uid:
                path = ace.get("path", "")
                # Nur User-eigene Projekte löschen (nicht die Master)
                if path.startswith("/projects/"):
                    pid = path.replace("/projects/", "")
                    if pid not in master_pids:
                        proj = next((p for p in projects if p["project_id"] == pid), None)
                        if proj:
                            print(f"    Lösche Projekt '{proj['name']}'...")
                            delete_project(token, pid)
                # Alle ACL-Einträge des Users löschen
                delete_acl(token, ace["ace_id"])

        # User löschen
        delete_user(token, uid)
        print(f"    User '{uname}' gelöscht")

    print("\nFertig.")


def main():
    parser = argparse.ArgumentParser(
        description="GNS3 Schulungs-User-Verwaltung",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command")

    # create
    p_create = sub.add_parser("create", help="User mit Projektkopien erstellen")
    p_create.add_argument("--users", type=int, required=True, help="Anzahl User")
    p_create.add_argument("--prefix", default="user", help="Username-Prefix (default: user)")
    p_create.add_argument("--password", default=None, help="Passwort (default: schulung123)")

    # list
    sub.add_parser("list", help="Alle User und Projekte anzeigen")

    # delete
    p_delete = sub.add_parser("delete", help="User und Projekte löschen")
    p_delete.add_argument("--prefix", default=None, help="Alle User mit diesem Prefix löschen")
    p_delete.add_argument("--name", default=None, help="Einzelnen User löschen")

    args = parser.parse_args()

    if args.command == "create":
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
