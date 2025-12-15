import requests
from pprint import pprint
import yaml
from pathlib import Path

NPM_DB_FILE = Path("/app/db/npm_hosts_db.yaml")

def load_npm_db():
    """Load the YAML database of added NPM hosts."""
    if NPM_DB_FILE.exists():
        with open(NPM_DB_FILE, "r") as f:
            return yaml.safe_load(f) or {"hosts": []}
    return {"hosts": []}

def save_npm_db(db):
    """Save the YAML database."""
    with open(NPM_DB_FILE, "w") as f:
        yaml.safe_dump(db, f)

def npm_get_token(npm_url: str, identity: str, secret: str) -> str:
    url = f"{npm_url}/api/tokens"
    data = {"identity": identity, "secret": secret}
    headers = {"accept": "application/json", "Content-Type": "application/json"}

    try:
        response = requests.post(url, headers=headers, json=data, verify=False, timeout=5)
        response.raise_for_status()
        token = response.json().get("token")
        if not token:
            print(f"Token not found in response: {response.text}")
            return None
        return token
    except requests.exceptions.RequestException as e:
        print(f"Failed to get token from NPM: {e}, Check login and Password.")
        return None


def npm_request(method, url, token, json_data=None):
    headers = {
        "accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}"
    }
    try:
        response = requests.request(
            method, url, headers=headers, json=json_data, verify=False, timeout=5
        )
        #pprint(response.json())
        response.raise_for_status()
        return {"ok": True, "data": response.json()}
    except requests.exceptions.RequestException as e:
        return {"ok": False, "error": str(e)}

def npm_get_certificate_id_by_name(npm_url: str, token: str, cert_name: str) -> int:
    """
    Return certificate_id for given certificate name.
    """
    url = f"{npm_url}/api/nginx/certificates"
    result = npm_request("GET", url, token)
    if not result["ok"]:
        print(f"Failed to get certificates: {result['error']}")
        return None
    for cert in result["data"]:
        # cert['name'] = nazwa certyfikatu w NPM
        if cert.get("nice_name") == cert_name:
            return cert["id"]

    #print(f"Certificate '{cert_name}' not found")
    return None
   
def npm_get_access_list_id_by_name(npm_url: str, token: str, acl_name: str) -> int:
    """
    Return access_list_id for given Access List name.
    """
    url = f"{npm_url}/api/nginx/access-lists"
    result = npm_request("GET", url, token)

    if not result["ok"]:
        print(f"Failed to get access lists: {result['error']}")
        return "1"  # Default access list ID
    for acl in result["data"]:
        # acl['name'] = access list name in NPM
        if acl.get("name") == acl_name:
            return acl["id"]

    print(f"⚠ Access list '{acl_name}' not found")
    return None
    
def npm_add_proxy_host(npm_url: str, token: str, host_config: dict):

    url = f"{npm_url}/api/nginx/proxy-hosts"
    result = npm_request("POST", url, token, host_config)

    if not result["ok"]:
        #print(f"❌ Error adding NPM host {host_config.get('domain_names')}:")
        #pprint(result["error"])
        return result

    print(f"✅ NPM Host {host_config.get('domain_names')} added successfully.")

    # Save to local YAML DB
    db = load_npm_db()
    db.setdefault("hosts", [])
    db["hosts"].append(host_config["domain_names"][0])
    save_npm_db(db)

    return result


def npm_delete_proxy_host(npm_url: str, token: str, domain_name: str):
    """
    Delete a proxy host from Nginx Proxy Manager by domain_name.
    """
    # 1. Pobierz wszystkie proxy hosts
    url_list = f"{npm_url}/api/nginx/proxy-hosts"
    result_list = npm_request("GET", url_list, token)

    if not result_list["ok"]:
        print(f"❌ Error fetching NPM hosts:")
        pprint(result_list["error"])
        return result_list

    # 2. Znajdź host po domain_name
    host_id = None
    for host in result_list["data"]:
        if domain_name in host.get("domain_names", []):
            host_id = host["id"]
            break

    if host_id is None:
        print(f"❌ Host {domain_name} not found.")
        return {"ok": False, "error": "Host not found"}

    # 3. Usuń host
    url_delete = f"{npm_url}/api/nginx/proxy-hosts/{host_id}"
    result_delete = npm_request("DELETE", url_delete, token)

    if not result_delete["ok"]:
        print(f"❌ Error deleting NPM host {domain_name}:")
        pprint(result_delete["error"])
        return result_delete

    print(f"✅ NPM Host {domain_name} deleted successfully.")

    # 4. Usuń z lokalnego YAML
    db = load_npm_db()
    db["hosts"] = [h for h in db.get("hosts", []) if domain_name not in h]
    save_npm_db(db)

    return result_delete

    #npm_delete_proxy_host(npm_url, token, "pairdroppp.mp-studio.duckdns.org")
