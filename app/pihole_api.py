import requests
from pprint import pprint
import yaml
from pathlib import Path

DB_FILE = Path("/app/db/pihole_hosts_db.yaml")


def load_db():
    """Load the YAML database of added hosts."""
    if DB_FILE.exists():
        with open(DB_FILE, "r") as f:
            return yaml.safe_load(f) or {"hosts": [], "cnames": []}
    return {"hosts": [], "cnames": []}

def save_db(db):
    """Save the YAML database."""
    with open(DB_FILE, "w") as f:
        yaml.safe_dump(db, f)

def pihole_request(method, url, sid, json_data=None):
    headers = {
        "X-FTL-SID": sid,
        "accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=json_data,
            verify=False,
            timeout=5
        )
        response.raise_for_status()

    except requests.exceptions.HTTPError:
        try:
            return {"ok": False, "error": response.json()["error"]["hint"]}
        except ValueError:
            return {"ok": False, "error": response.text}

    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}

    try:
        return {"ok": True, "data": response.json()}
    except ValueError:
        return {"ok": True, "data": None}
    
def pihole_get_sid(pihole_url: str, password: str) -> str:
    url = f"{pihole_url}/api/auth"
    result = pihole_request("POST", url, sid=None, json_data={"password": password})

    if not result["ok"] or "session" not in result["data"]:
        print(f"Pi-hole authentication failed: {result}")
        return None

    return result["data"]["session"]["sid"]

def pihole_add_dns_host(pihole_url: str, ip: str, hostname: str, sid: str):
    url = f"{pihole_url}/api/config/dns/hosts/{ip}%20{hostname}"
    data = [{"name": hostname, "address": ip, "comment": ""}]

    result = pihole_request("PUT", url, sid, data)

    if not result["ok"]:
        #print(f"❌ Error adding host {hostname}:")
        #pprint(result["error"])
        return result

    print(f"✅ Host {hostname} -> {ip} added successfully.")

    db = load_db()
    db.setdefault("hosts", [])
    db["hosts"].append({"hostname": hostname, "ip": ip})
    save_db(db)

    return result

def pihole_add_cname(pihole_url: str, alias: str, target: str, sid: str):
    url = f"{pihole_url}/api/config/dns/cnameRecords/{alias},{target}"
    data = [{"domain": alias, "target": target}]

    result = pihole_request("PUT", url, sid, data)

    if not result["ok"]:
        #print(f"❌ Error adding CNAME {alias} -> {target}:")
        #pprint(result["error"])
        return result

    print(f"✅ CNAME {alias} -> {target} added successfully.")

    db = load_db()
    db.setdefault("cnames", [])
    db["cnames"].append({"alias": alias, "target": target})
    save_db(db)

    return result

def pihole_delete_dns_host(pihole_url: str, ip: str, hostname: str, sid: str):
    """Delete an A record from Pi-hole config."""
    url = f"{pihole_url}/api/config/dns/hosts/{ip}%20{hostname}"
    headers = {"X-FTL-SID": sid, "accept": "application/json"}

    try:
        response = requests.delete(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        try:
            error_json = response.json()
        except Exception:
            error_json = {"error": "Invalid JSON response", "text": response.text}

        print(f"❌ Error deleting host {hostname} -> {ip}:")
        pprint(error_json)
        return error_json

    print(f"✅ Host {hostname} -> {ip} deleted successfully.")

    db = load_db()
    db["hosts"] = [
        h for h in db.get("hosts", [])
        if not (h["hostname"] == hostname and h["ip"] == ip)
    ]
    save_db(db)

    return response.json() if response.text else {"status": "deleted"}

def pihole_delete_cname(pihole_url: str, alias: str, target: str, sid: str):
    """Delete a CNAME record from Pi-hole config."""
    url = f"{pihole_url}/api/config/dns/cnameRecords/{alias},{target}"
    headers = {"X-FTL-SID": sid, "accept": "application/json"}

    try:
        response = requests.delete(url, headers=headers, verify=False)
        response.raise_for_status()
    except requests.exceptions.HTTPError:
        try:
            error_json = response.json()
        except Exception:
            error_json = {"error": "Invalid JSON response", "text": response.text}

        print(f"❌ Error deleting CNAME {alias} -> {target}:")
        pprint(error_json)
        return error_json

    print(f"✅ CNAME {alias} -> {target} deleted successfully.")

    db = load_db()
    db["cnames"] = [
        c for c in db.get("cnames", [])
        if not (c["alias"] == alias and c["target"] == target)
    ]
    save_db(db)

    return response.json() if response.text else {"status": "deleted"}

