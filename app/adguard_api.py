import requests
from pprint import pprint
import yaml
from pathlib import Path

DB_FILE = Path("/app/db/adguard_hosts_db.yaml")


def load_db_adguard():
    """Load the YAML database of added hosts."""
    if DB_FILE.exists():
        with open(DB_FILE, "r") as f:
            return yaml.safe_load(f) or {"hosts": [], "cnames": []}
    return {"hosts": [], "cnames": []}

def save_db_adguard(db):
    """Save the YAML database."""
    with open(DB_FILE, "w") as f:
        yaml.safe_dump(db, f)


def adguard_request(method, url, auth, json_data=None):
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json"
    }

    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=json_data,
            auth=auth,
            verify=False, 
            timeout=5
        )
        response.raise_for_status()

    except requests.exceptions.HTTPError:
        try:
            return {"ok": False, "error": response.json().get("error", response.text)}
        except ValueError:
            return {"ok": False, "error": response.text}

    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}

    try:
        return {"ok": True, "data": response.json() if response.text else None}
    except ValueError:
        return {"ok": True, "data": None}
    
def adguard_add_dns_host(adguard_url: str, domain: str, answer: str, username: str, password: str):
    """
    Dodaje rekord A/AAAA lub CNAME w AdGuard Home,
    tylko jeśli nie istnieje już w lokalnym DB.
    """
    db = load_db_adguard()
    db.setdefault("hosts", [])

    # sprawdzanie czy już istnieje w lokalnym DB
    for host in db["hosts"]:
        if host["domain"] == domain and host["answer"] == answer:
            #print(f"⚠️ Host {domain} -> {answer} już istnieje w bazie, pomijam dodanie.")
            return {"ok": True, "data": None, "info": "already exists"}

    # dodanie przez API AdGuard
    url = f"{adguard_url}/control/rewrite/add"
    auth = (username, password)
    data = {"domain": domain, "answer": answer}

    result = adguard_request("POST", url, auth, data)

    if not result["ok"]:
        # print(f"❌ Error adding host {domain}:")
        # pprint(result["error"])
        return result

    print(f"✅ Host {domain} -> {answer} added successfully to AdGuard Home.")

    # zapis do lokalnego DB YAML
    db["hosts"].append({"domain": domain, "answer": answer})
    save_db_adguard(db)

    return result


def adguard_delete_dns_host(adguard_url: str, domain: str, answer: str, username: str, password: str):
    """
    Usuwa rekord A/AAAA (DNS Rewrite) z AdGuard Home.
    """
    url = f"{adguard_url}/control/rewrite/delete"
    auth = (username, password)

    data = {
        "domain": domain,
        "answer": answer
    }

    result = adguard_request("POST", url, auth, data)

    if not result["ok"]:
        print(f"❌ Error deleting host {domain} -> {answer}:")
        print(result["error"])
        return result

    print(f"✅ Host {domain} -> {answer} deleted successfully from AdGuard Home.")
    db = load_db_adguard()
    db["hosts"] = [
        h for h in db.get("hosts", [])
        if not (h["domain"] == domain and h["answer"] == answer)
    ]
    save_db_adguard(db)

    return result
