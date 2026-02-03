import yaml
from pathlib import Path
import docker
from pprint import pprint
import requests
from pihole_api import *
from apscheduler.schedulers.background import BackgroundScheduler
import time
from npm_api import *
from adguard_api import *
from mikrotik_api import *
CONFIG_FILE = Path("/app/config/config.yaml")



def load_config():
    """Load configuration from /app/config/config.yaml."""
    if not CONFIG_FILE.exists():
        raise FileNotFoundError(f"Config file {CONFIG_FILE} not found")
    
    with open(CONFIG_FILE, "r") as f:
        config = yaml.safe_load(f)
    
    return config

def get_docker_client(config: dict):
    """
    Return Docker client for local socket or TCP.
    """
    tcp_url = config.get("DOCKER_TCP_URL")

    if tcp_url:
        print(f"✅ Using remote Docker API: {tcp_url}")
        return docker.DockerClient(base_url=tcp_url)

    print("✅ Using local Docker socket")
    return docker.from_env()

def get_containers_by_label(label_key: str, config: dict):
    """
    Return containers that have labels containing label_key.
    Supports local Docker socket and remote TCP.
    """
    docker_info = {}

    client = get_docker_client(config)

    for container in client.containers.list(all=True):
        labels = container.labels or {}

        for label_name, label_value in labels.items():
            if label_key in label_name:
                docker_info.setdefault(container.name, {})
                docker_info[container.name][label_name] = label_value

    return docker_info

def scheduled_job():
    print("✅ Scheduler job Started")
    config = load_config()
    docker_info = get_containers_by_label("MP-HomeCore",config)
    #pprint(docker_info)
    if config.get("MIKROTIK_ENABLED", False):
        mikrotik_defaults = config.get("MIKROTIK_DEFAULTS", {})
        for host,labels in docker_info.items():
            #pprint(f"Processing container: {host} with labels: {labels}")
            if labels.get("MP-HomeCore.mikrotik_disable","false") == "true":
                print(f"⚠ Mikrotik integration disabled for container {host} via label.")
                continue
            target=labels.get("MP-HomeCore.mikrotik_target", mikrotik_defaults.get("mikrotik_target", None))
            hostname = labels.get("MP-HomeCore.mikrotik_hostname")
            mikrotik_type = labels.get("MP-HomeCore.mikrotik_type", mikrotik_defaults.get("mikrotik_type", "dns"))
            if  hostname and target:
                #print(f"Processing container: {host} with IP: {ip}, Hostname: {hostname}, CNAME Target: {cname_target}, Type: {mikrotik_type}")
                try:
                    if "dns" == mikrotik_type:
                        mikrotik_add_a(config["MIKROTIK_IP"], config["MIKROTIK_USERNAME"], config["MIKROTIK_PASSWORD"], config["MIKROTIK_PORT"], hostname, target)
                    if "cname" == mikrotik_type:
                        mikrotik_add_cname(config["MIKROTIK_IP"], config["MIKROTIK_USERNAME"], config["MIKROTIK_PASSWORD"], config["MIKROTIK_PORT"], hostname, target)
                except ValueError as e:
                    print(f"❌ Mikrotik operation failed: {e}")
            else:
                print(f"⚠ Skipping container {host}, No labels for Mikrotik hostname/target found.")
        # Deleting hosts/CNAMEs that are no longer in Docker containers
        db = load_db_mikrotik()
        for type,hosts in db.items():
            for entry in hosts:
                if type == "hosts":
                    hostname = entry["hostname"]
                    ip = entry["ip"]
                    if not any(labels.get("MP-HomeCore.mikrotik_hostname") == hostname for labels in docker_info.values()):
                        try:
                            mikrotik_delete_a(config["MIKROTIK_IP"], config["MIKROTIK_USERNAME"], config["MIKROTIK_PASSWORD"], config["MIKROTIK_PORT"], hostname, ip)
                        except ValueError as e:
                            print(f"❌ Mikrotik deletion failed: {e}")
                elif type == "cnames":
                    alias = entry["hostname"]
                    target = entry["cname"]
                    if not any(labels.get("MP-HomeCore.mikrotik_hostname") == alias for labels in docker_info.values()):
                        try:
                            mikrotik_delete_cname(config["MIKROTIK_IP"], config["MIKROTIK_USERNAME"], config["MIKROTIK_PASSWORD"], config["MIKROTIK_PORT"], alias, target)
                        except ValueError as e:
                            print(f"❌ Mikrotik deletion failed: {e}")
    else:
        print("⚠️ Mikrotik integration is disabled in config.")
    if config.get("PIHOLE_ENABLED", False):
        pihole_defaults = config.get("PIHOLE_DEFAULTS", {})
        for host,labels in docker_info.items():
            #pprint(f"Processing container: {host} with labels: {labels}")
            if labels.get("MP-HomeCore.pihole_disable","false") == "true":
                print(f"⚠ Pi-hole integration disabled for container {host} via label.")
                continue
            ip = labels.get("MP-HomeCore.dns_ip")
            hostname = labels.get("MP-HomeCore.hostname")
            cname_target = labels.get("MP-HomeCore.cname_target", pihole_defaults.get("cname_target", None))
            pihole_type = labels.get("MP-HomeCore.pihole_type", pihole_defaults.get("pihole_type", "dns"))
            
            #print(f"Processing container: {host} with IP: {ip}, Hostname: {hostname}, CNAME Target: {cname_target}, Type: {pihole_type}")
            try:
                sid = pihole_get_sid(config["PIHOLE_URL"], config["PIHOLE_PASSWORD"])
                if "dns" in pihole_type:
                    pihole_add_dns_host(config["PIHOLE_URL"], ip, hostname, sid)
                if "cname" in pihole_type and cname_target:
                    pihole_add_cname(config["PIHOLE_URL"], hostname, cname_target, sid)
            except ValueError as e:
                print(f"❌ Pi-hole operation failed: {e}")
        # Deleting hosts/CNAMEs that are no longer in Docker containers
        db = load_db_pihole()
        for type,hosts in db.items():
            for entry in hosts:
                if type == "hosts":
                    hostname = entry["hostname"]
                    ip = entry["ip"]
                    if not any(labels.get("MP-HomeCore.hostname") == hostname for labels in docker_info.values()):
                        try:
                            sid = pihole_get_sid(config["PIHOLE_URL"], config["PIHOLE_PASSWORD"])
                            pihole_delete_dns_host(config["PIHOLE_URL"], ip, hostname, sid)
                        except ValueError as e:
                            print(f"❌ Pi-hole deletion failed: {e}")
                elif type == "cnames":
                    alias = entry["alias"]
                    target = entry["target"]
                    if not any(labels.get("MP-HomeCore.hostname") == alias for labels in docker_info.values()):
                        try:
                            sid = pihole_get_sid(config["PIHOLE_URL"], config["PIHOLE_PASSWORD"])
                            pihole_delete_cname(config["PIHOLE_URL"], alias, target, sid)
                        except ValueError as e:
                            print(f"❌ Pi-hole CNAME deletion failed: {e}")
    else:
        print("⚠️ Pi-hole integration is disabled in config.")
    if config.get("NPM_ENABLED", False):
        token=npm_get_token(config["NPM_URL"], config["NPM_USERNAME"], config["NPM_PASSWORD"])
        for host,labels in docker_info.items():
            if labels.get("MP-HomeCore.pihole_disable","false") == "true":
                print(f"⚠ NPM integration disabled for container {host} via label.")
                continue
            #Get default values from config
            #pprint(config)
            npm_defaults = config.get("NPM_DEFAULTS", {})
            if npm_defaults.get("access_list_name",None):
                npm_defaults["access_list_id"] = npm_get_access_list_id_by_name(config["NPM_URL"], token, npm_defaults["access_list_name"])
            if npm_defaults.get("certificate_name",None):
                npm_defaults["certificate_id"] = npm_get_certificate_id_by_name(config["NPM_URL"], token, npm_defaults["certificate_name"])
            
            acl=labels.get("MP-HomeCore.accessList", None)
            if acl:
                acl_id = npm_get_access_list_id_by_name(config["NPM_URL"], token, acl)
                if acl_id is None:
                    print(f"❌ NPM operation failed, access list '{acl}' not found for container {host}")
                    continue
            else:
                acl_name = npm_defaults.get("access_list_name",None)  # Default access list ID
                if acl_name:
                    acl_id = npm_get_access_list_id_by_name(config["NPM_URL"], token, acl_name)
                else:
                    acl_id = 1
                    
            cert=labels.get("MP-HomeCore.sslCertificate", None)
            if cert:
                cert_id = npm_get_certificate_id_by_name(config["NPM_URL"], token, cert)
            else: 
                cert_name = npm_defaults.get("certificate_name",None)  # Default certificate ID
                if cert_name:
                    cert_id = npm_get_certificate_id_by_name(config["NPM_URL"], token, cert_name)
                else:
                    cert_id = None
            try:
                #Dodać defaulty w konfiguracji
                host_config = {
                    "domain_names": [labels.get("MP-HomeCore.hostname")],
                    "forward_host": labels.get("MP-HomeCore.forward_host"),
                    "forward_port": int(labels.get("MP-HomeCore.forward_port")),
                    "forward_scheme": labels.get("MP-HomeCore.targetScheme", npm_defaults.get("forward_scheme","http")),
                    "certificate_id": cert_id,
                    "access_list_id": acl_id,
                    "block_exploits": labels.get("MP-HomeCore.blockCommExploits", npm_defaults.get("block_exploits","false")),
                    "caching_enabled": labels.get("MP-HomeCore.Caching", npm_defaults.get("caching_enabled","false")) ,
                    "ssl_forced": labels.get("MP-HomeCore.forceHttps",npm_defaults.get("ssl_forced","false")) ,
                    "http2_support": labels.get("MP-HomeCore.enableHttp2", npm_defaults.get("http2_support","false")),
                    "hsts_enabled": labels.get("MP-HomeCore.hstsEnabled", npm_defaults.get("hsts_enabled","false")),
                    "hsts_subdomains": labels.get("MP-HomeCore.includeSubdomainsInHsts", npm_defaults.get("hsts_subdomains","false")),
                    "allow_websocket_upgrade": labels.get("MP-HomeCore.allowWebsockets", npm_defaults.get("block_explallow_websocket_upgradeoits","false")),
                }
                npm_add_proxy_host(config["NPM_URL"], token, host_config)
            except (ValueError, TypeError) as e:
                print(f"❌ NPM operation failed, check labels for container {host}")
        # Deleting NPM hosts that are no longer in Docker containers
            db = load_npm_db()
            for domain in db.get("hosts", []):
                # jeśli hostname nie istnieje w Docker labels
                if not any(labels.get("MP-HomeCore.hostname") == domain for labels in docker_info.values()):
                    try:
                        npm_delete_proxy_host(config["NPM_URL"], token, domain)
                    except ValueError as e:
                        print(f"❌ NPM deletion failed: {e}, hostname: {domain}")
    else:
        print("⚠️ NPM integration is disabled in config.")

    if config.get("ADGUARD_ENABLED", False):
        adguard_defaults = config.get("ADGUARD_DEFAULTS", {})

        for host, labels in docker_info.items():
            if labels.get("MP-HomeCore.adguard_disable", "false") == "true":
                print(f"⚠ AdGuard integration disabled for container {host} via label.")
                continue

            domain = labels.get("MP-HomeCore.adguard_hostname")
            answer = labels.get("MP-HomeCore.adguard_target") or adguard_defaults.get("adguard_target")
            if not domain or not answer:
                print(f"⚠ Skipping container {host}, No labels for AdGuard hostname/target found.")
                continue

            try:
                adguard_add_dns_host(
                    adguard_url=config["ADGUARD_URL"],
                    domain=domain,
                    answer=answer,
                    username=config["ADGUARD_USERNAME"],
                    password=config["ADGUARD_PASSWORD"]
                )
            except ValueError as e:
                print(f"❌ AdGuard operation failed: {e}")

        # Usuwanie wpisów, które już nie istnieją w docker_info
        db = load_db_adguard()
        for entry in db.get("hosts", []):
            domain = entry["domain"]
            answer = entry["answer"]
            if not any(labels.get("MP-HomeCore.adguard_hostname") == domain for labels in docker_info.values()):
                try:
                    adguard_delete_dns_host(
                        adguard_url=config["ADGUARD_URL"],
                        domain=domain,
                        answer=answer,
                        username=config["ADGUARD_USERNAME"],
                        password=config["ADGUARD_PASSWORD"]
                    )
                except ValueError as e:
                    print(f"❌ AdGuard deletion failed: {e}")

    else:
        print("⚠️ AdGuard integration is disabled in config.")

if __name__ == "__main__":
    config = load_config()
    print("✅ Configuration loaded successfully.")
    scheduled_job()
    scheduler = BackgroundScheduler()
    scheduler.add_job(scheduled_job, "interval", minutes=config.get("SCHEDULER_INTERVAL_MINUTES", 1))
    scheduler.start()

    print(f'✅ Scheduler started (every {config.get("SCHEDULER_INTERVAL_MINUTES", 1)} minutes)')

    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
    


