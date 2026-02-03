import requests
from pprint import pprint
import yaml
from pathlib import Path
from routeros_api import RouterOsApiPool
import routeros_api

DB_FILE = Path("/app/db/mikrotik_hosts_db.yaml")


def load_db_mikrotik():
    """Load the YAML database of added hosts."""
    if DB_FILE.exists():
        with open(DB_FILE, "r") as f:
            return yaml.safe_load(f) or {"hosts": [], "cnames": []}
    return {"hosts": [], "cnames": []}

def save_db_mikrotik(db):
    """Save the YAML database."""
    with open(DB_FILE, "w") as f:
        yaml.safe_dump(db, f)

def get_dns_records(mikrotik_ip, username, password, port=8728):
    api = RouterOsApiPool(mikrotik_ip, username=username, password=password, port=port, plaintext_login=True )
    api_connection = api.get_api()

    dns_records = api_connection.get_resource('/ip/dns/static').get()
    api.disconnect()

    result = {}
    for record in dns_records:
        name = record.get('name')
        rtype = record.get('type', 'A')  # MikroTik domyślnie A jeśli brak type
        value = record.get('address', record.get('cname', ''))
        ttl = record.get('ttl', '')
        result[name] = {
            "type": rtype,
            "value": value,
            "ttl": ttl
        }
    return result

# -------------------------------
# Funkcja dodająca rekord A
# -------------------------------
def mikrotik_add_a(mikrotik_ip, username, password, port, hostname: str, ip_address: str):
    """
    Dodaje rekord A do MikroTik przez API.
    """
    api_connection = RouterOsApiPool(mikrotik_ip, username=username, password=password, port=port, plaintext_login=True )
    api_connection=api_connection.get_api()

    resource = api_connection.get_resource('/ip/dns/static')
    try:
        resource.add(name=hostname, address=ip_address, ttl='1h')
        print(f"✅ A record {hostname} -> {ip_address} added successfully.")
        db = load_db_mikrotik()
        db.setdefault("hosts", [])
        db["hosts"].append({"hostname": hostname, "ip": ip_address})
        save_db_mikrotik(db)
        return {"ok": True}
    except routeros_api.exceptions.RouterOsApiCommunicationError as e:
        if not "already exists" in str(e):
            pprint(f"❌ Error adding A record {hostname}")
        #return {"ok": False, "error": str(e)}

# -------------------------------
# Funkcja dodająca rekord CNAME
# -------------------------------
def mikrotik_add_cname(mikrotik_ip, username, password, port, alias: str, target: str):
    """
    Dodaje rekord CNAME do MikroTik przez API.
    """
    api_connection = RouterOsApiPool(mikrotik_ip, username=username, password=password, port=port, plaintext_login=True )
    api_connection=api_connection.get_api()
    resource = api_connection.get_resource('/ip/dns/static')
    try:
        resource.add(name=alias, type='CNAME', cname=target, ttl='1h')
        db = load_db_mikrotik()
        db.setdefault("cnames", [])
        db["cnames"].append({"hostname": alias, "cname": target})
        save_db_mikrotik(db)
        print(f"✅ CNAME {alias} -> {target} added successfully.")
        return {"ok": True}
    except routeros_api.exceptions.RouterOsApiCommunicationError as e:
        if not "already exists" in str(e):
            pprint(f"❌ Error adding CNAME {alias}")
        #return {"ok": False, "error": str(e)}

def mikrotik_delete_a(mikrotik_ip, username, password, port, hostname: str, ip_address: str):
    try:
        api_pool = RouterOsApiPool(
            mikrotik_ip,
            username=username,
            password=password,
            port=port,
            plaintext_login=True
        )
        api = api_pool.get_api()
        resource = api.get_resource('/ip/dns/static')

        # Pobieramy wszystkie rekordy
        all_records = resource.get()

        for r in all_records:
            # sprawdzamy, czy to nasz rekord A
            if r.get("name") == hostname and r.get("address") == ip_address:
                try:
                    # Wywołanie remove na instancji zasobu przez .id
                    resource.remove(id=r['id'])  # w najnowszej wersji wystarczy 'id'
                    print(f"✅ A record {hostname} -> {ip_address} deleted successfully.")
                    db = load_db_mikrotik()
                    db["hosts"] = [
                        h for h in db.get("hosts", [])
                        if not (h["hostname"] == hostname and h["ip"] == ip_address)
                    ]
                    save_db_mikrotik(db)
                except Exception as e:
                    print(f"⚠️ Attempted to delete {hostname} -> {ip_address}, got error (ignored): {e}")

        api_pool.disconnect()

    except Exception as e:
        print(f"⚠️ Error connecting to MikroTik or fetching DNS records: {e}")

    # Aktualizacja lokalnej bazy


    return {"ok": True, "status": "deleted"}
# -------------------------------
# Funkcja usuwająca rekord CNAME
# -------------------------------
def mikrotik_delete_cname(mikrotik_ip, username, password, port, alias: str, target: str):
    api_connection = RouterOsApiPool(
        mikrotik_ip, username=username, password=password, port=port, plaintext_login=True
    ).get_api()

    resource = api_connection.get_resource('/ip/dns/static')

    try:
        # iterujemy po wszystkich rekordach i usuwamy te, które pasują
        for r in resource.get():
            if r.get("name") == alias and r.get("cname") == target:
                try:
                    resource.remove(id=r.get("id"))
                    print(f"✅ CNAME {alias} -> {target} deleted successfully.")
                    db = load_db_mikrotik()
                    db["cnames"] = [
                        c for c in db.get("cnames", [])
                        if not (c["cname"] == alias and c["hostname"] == target)
                    ]
                    save_db_mikrotik(db)
                except Exception as e:
                    # ignorujemy błędy jeśli rekord został już usunięty
                    print(f"⚠️ Attempted to delete {alias} -> {target}, got error (ignored): {e}")
    except Exception as e:
        print(f"⚠️ Error fetching DNS records: {e}")

    # aktualizacja lokalnej bazy


    return {"ok": True, "status": "deleted"}