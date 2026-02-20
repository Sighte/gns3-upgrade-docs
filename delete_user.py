#!/usr/bin/env python3
"""
Schulungs-User vollständig löschen
====================================
Löscht einen Teilnehmer aus allen Systemen:
  1. Proxmox: LXC-Container (training-<username>)
  2. Keycloak: User
  3. GNS3: User + Projekte + ACL
  4. Guacamole: RDP-Verbindung

Verwendung:
  ./delete_user.py <username>
  ./delete_user.py Peter
"""

import sys
import time

sys.path.insert(0, '/root/gns3-upgrade-docs')
from UserScript import (
    Proxmox, Keycloak, GNS3, Guacamole,
    http_request, GUACAMOLE_HOST, GNS3_MASTER_PROJECTS,
)


def delete_user(username):
    print(f"\nLösche Benutzer '{username}' aus allen Systemen...")
    print("=" * 50)

    pve = Proxmox()
    kc = Keycloak()
    gns3 = GNS3()
    guac = Guacamole()

    kc.authenticate()
    gns3.authenticate()
    guac.authenticate()

    # --- 1. Proxmox ---
    print("\n[1/4] Proxmox - Container löschen...")
    containers = pve.get_all_containers()
    ct = next((c for c in containers if c.get("name") == f"training-{username}"), None)
    if ct:
        print(f"  Lösche CT {ct['vmid']} ({ct['name']})...")
        pve.delete_container(ct["vmid"])
        print(f"  ✓ Container gelöscht")
    else:
        print(f"  Kein Container 'training-{username}' gefunden")

    # --- 2. Keycloak ---
    print("\n[2/4] Keycloak - User löschen...")
    kc_user = kc.get_user_by_username(username)
    if kc_user:
        kc.delete_user(kc_user["id"])
        print(f"  ✓ Keycloak-User gelöscht")
    else:
        print(f"  User nicht gefunden")

    # --- 3. GNS3 ---
    print("\n[3/4] GNS3 - User, Projekte und ACL löschen...")
    gns3_users = gns3.get_all_users()
    gns3_user = next((u for u in gns3_users if u["username"] == username), None)
    if gns3_user:
        uid = gns3_user["user_id"]
        master_pids = set(GNS3_MASTER_PROJECTS.values())
        acl_entries = gns3.get_all_acl()
        projects = gns3.get_all_projects()

        for ace in acl_entries:
            if ace.get("user_id") == uid:
                path = ace.get("path", "")
                if path.startswith("/projects/"):
                    pid = path.replace("/projects/", "")
                    if pid not in master_pids:
                        proj = next((p for p in projects if p["project_id"] == pid), None)
                        if proj:
                            print(f"  Lösche Projekt '{proj['name']}'...")
                            gns3.delete_project(pid)
                gns3.delete_acl(ace["ace_id"])

        gns3.delete_user(uid)
        print(f"  ✓ GNS3-User und Projekte gelöscht")
    else:
        print(f"  User nicht gefunden")

    # --- 4. Guacamole ---
    print("\n[4/4] Guacamole - Verbindung löschen...")
    conns = http_request("GET", f"{GUACAMOLE_HOST}/api/session/data/mysql/connections?token={guac.token}")
    if isinstance(conns, dict):
        for cid, conn in conns.items():
            if f"Training-{username}" in conn.get("name", ""):
                guac.delete_connection(cid)
                print(f"  ✓ Verbindung '{conn['name']}' gelöscht")
                break
        else:
            print(f"  Keine Verbindung für '{username}' gefunden")

    print(f"\n✓ '{username}' vollständig gelöscht.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Verwendung: {sys.argv[0]} <username>")
        sys.exit(1)

    username = sys.argv[1]
    confirm = input(f"'{username}' aus allen Systemen löschen (inkl. VM)? (j/N): ").strip().lower()
    if confirm != "j":
        print("Abgebrochen.")
        sys.exit(0)

    delete_user(username)
