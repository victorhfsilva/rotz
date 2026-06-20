#!/usr/bin/env python3
"""
Script genérico de reconhecimento para Bug Bounty / Penetration Testing.
Uso:
    python3 recon_summary.py --base /caminho/base --org "Nome da Org" --domain exemplo.com
    python3 recon_summary.py --base /caminho/base --out /caminho/saida/summary.md --org "ACME Corp" --domains "exemplo.com,exemplo.com.br"
"""
import json
import os
import re
import csv
import argparse
from collections import defaultdict, Counter
from urllib.parse import urlparse

# =================== ARGUMENTOS ===================
def parse_args():
    parser = argparse.ArgumentParser(description="Gerador de relatório de reconhecimento para Bug Bounty/Pentest")
    parser.add_argument("--base", required=True, help="Diretório base com os dados de reconhecimento")
    parser.add_argument("--out", default=None, help="Caminho do arquivo de saída (default: {base}/_summary/summary.md)")
    parser.add_argument("--org", default="Alvo", help="Nome da organização para o relatório")
    parser.add_argument("--domains", default=None, help="Domínios alvo separados por vírgula (opcional; detectados automaticamente dos subdomínios)")
    return parser.parse_args()

args = parse_args()

BASE = args.base.rstrip("/")
ORG_NAME = args.org
OUT = args.out if args.out else os.path.join(BASE, "_summary", "summary.md")
os.makedirs(os.path.dirname(OUT), exist_ok=True)

# =================== HELPERS ===================
def read_lines(path):
    try:
        with open(path, 'r', errors='ignore') as f:
            return [l.strip() for l in f if l.strip()]
    except Exception as e:
        return []

def read_file(path, limit=0):
    try:
        with open(path, 'r', errors='ignore') as f:
            data = f.read()
            if limit and len(data) > limit:
                return data[:limit]
            return data
    except:
        return ""

def extract_domain(url):
    try:
        p = urlparse(url)
        return p.netloc.split(':')[0]
    except:
        return ""

def detect_root_domains(subs_list):
    """Detecta os domínios raiz a partir da lista de subdomínios."""
    domains = set()
    for s in subs_list:
        d = extract_domain(s)
        parts = d.split(".")
        if len(parts) >= 2:
            # Pega os dois últimos (exemplo.com) ou três (exemplo.com.br)
            root = ".".join(parts[-2:]) if parts[-1] not in ("com", "org", "net", "gov", "edu", "mil", "io", "co", "br", "uk", "de", "fr", "jp", "au", "ru", "cn", "in") else ".".join(parts[-3:])
            # Simplifica: pega os 2 últimos se não for TLD composto
            if parts[-1] in ("br", "uk", "au", "jp", "ru", "cn", "in", "ar", "mx", "za", "nz", "kr", "pl", "se", "no", "fi", "dk", "nl", "be", "ch", "at", "it", "es", "pt", "gr", "tr", "il", "sg", "my", "th", "ph", "id", "vn", "hk", "tw"):
                root = ".".join(parts[-3:]) if len(parts) >= 3 else d
            else:
                root = ".".join(parts[-2:]) if len(parts) >= 2 else d
        else:
            root = d
        domains.add(root.lower())
    return sorted(domains)

# =================== SUBDOMÍNIOS ===================
print("[*] Processando subdomínios...")
subs_path = os.path.join(BASE, "subs", "all.live.subs.txt")
if not os.path.exists(subs_path):
    # Tenta caminhos alternativos comuns
    for alt in ["subs", "subdomains", "recon"]:
        for fname in ["all.live.subs.txt", "all.subs.txt", "alive.txt", "subdomains.txt", "final_subs.txt"]:
            test_path = os.path.join(BASE, alt, fname)
            if os.path.exists(test_path):
                subs_path = test_path
                break
        if os.path.exists(subs_path):
            break

subs = read_lines(subs_path)

# Detecta domínios raiz automaticamente se não fornecidos
root_domains = []
if args.domains:
    root_domains = [d.strip().lower() for d in args.domains.split(",")]
else:
    root_domains = detect_root_domains(subs)
    print(f"[*] Domínios raiz detectados: {', '.join(root_domains)}")

subs_http = [s for s in subs if s.startswith("http://")]
subs_https = [s for s in subs if s.startswith("https://")]
subs_all = subs_http + subs_https

# categorização
keywords = {
    "admin": ["admin", "administrator", "adm", "manage", "management", "console", "panel", "dashboard"],
    "auth": ["auth", "login", "sso", "signin", "signup", "register", "account", "password", "credential", "certauth", "launchpad", "oauth", "idp", "iam"],
    "api": ["api", "graphql", "rest", "swagger", "openapi", "ws", "websocket", "grpc"],
    "dev/staging/test": ["dev", "staging", "stage", "test", "uat", "qa", "sandbox", "sbx", "demo", "preview", "beta", "alpha"],
    "internal": ["internal", "intranet", "vpn", "proxy", "ldap", "ad.", "dc.", "dc1", "dc2", "private", "corp"],
    "infra/monitoring": ["monitor", "grafana", "prometheus", "kibana", "elastic", "zabbix", "nagios", "splunk", "metrics", "logs", "jenkins", "gitlab", "ci", "cd", "git", "registry", "repo", "repository", "nexus", "artifactory"],
    "database": ["db", "database", "sql", "mysql", "postgres", "mongo", "redis", "elasticsearch", "cassandra", "couchdb"],
    "backup/storage": ["backup", "archive", "storage", "s3", "blob", "ftp", "files", "dump", "snapshot"],
    "kubernetes": ["k8s", "kube", "cluster", "pod", "node", "container", "openshift", "helm"],
    "email/communication": ["mail", "email", "smtp", "exchange", "imap", "pop", "webmail", "autodiscover", "mx", "outlook", "teams", "chat", "slack"],
    "data/science": ["data", "science", "research", "analytics", "ml", "ai", "dataset", "datasets"],
    "cdn/assets": ["cdn", "assets", "static", "img", "images", "media", "download", "files"],
    "legacy/old": ["old", "legacy", "v1", "v2", "classic", "www1", "www2", "www0", "obsolete"]
}

categories = defaultdict(list)
for s in subs_all:
    domain = extract_domain(s).lower()
    found = False
    for cat, kws in keywords.items():
        if any(kw in domain for kw in kws):
            categories[cat].append(s)
            found = True
            break
    if not found:
        categories["outros"].append(s)

# vulneráveis por nome
vuln_names = ["dev", "staging", "test", "uat", "sandbox", "demo", "old", "legacy", "beta", "alpha", "api", "admin", "git", "registry", "backup", "db", "internal", "vpn", "proxy", "k8s", "kube", "autodiscover", "sso"]
sensitive_names = ["admin", "auth", "login", "sso", "signin", "account", "password", "credential", "certauth", "secure", "private", "internal", "vpn", "iam", "api", "db", "database", "backup", "git", "registry", "nexus", "jenkins"]

subs_vuln = [s for s in subs_all if any(v in extract_domain(s).lower() for v in vuln_names)]
subs_sensitive = [s for s in subs_all if any(v in extract_domain(s).lower() for v in sensitive_names)]

# =================== IPs / INFRA ===================
print("[*] Processando IPs...")
ports = read_lines(os.path.join(BASE, "ips", "naabu", "open_ports.txt"))
# Tenta caminhos alternativos
if not ports:
    for alt_dir in ["ips", "recon", "network"]:
        for fname in ["open_ports.txt", "all_ports.txt", "ports.txt"]:
            test_path = os.path.join(BASE, alt_dir, fname)
            if os.path.exists(test_path):
                ports = read_lines(test_path)
                break
        if ports:
            break

host_ports = defaultdict(set)
for line in ports:
    if ":" in line:
        ip, port = line.rsplit(":", 1)
        host_ports[ip].add(port)

# Scans JSON
scans_dir = None
for test_dir in [os.path.join(BASE, "ips", "scans"), os.path.join(BASE, "scans"), os.path.join(BASE, "nmap")]:
    if os.path.isdir(test_dir):
        scans_dir = test_dir
        break

scan_data = {}
scan_files = []
if scans_dir:
    scan_files = [f for f in os.listdir(scans_dir) if f.endswith(".scan.json") or f.endswith(".json")][:500]
for sf in scan_files:
    ip = sf.replace(".scan.json", "").replace(".json", "")
    try:
        with open(os.path.join(scans_dir, sf), 'r', errors='ignore') as f:
            data = json.load(f)
            scan_data[ip] = data
    except:
        pass

# IPs com serviços não-padrão ou sensíveis
interesting_ports = {"21", "23", "25", "53", "110", "143", "445", "3306", "3389", "5432", "6379", "27017", "8080", "8443", "9200", "9300", "9990", "9000", "5000", "3000", "8000", "8001", "8888", "9200", "5601", "8081", "9090", "50000"}
vuln_ips = []
sensitive_ips = []
for ip, ports_set in host_ports.items():
    inter = ports_set & interesting_ports
    if inter:
        info = scan_data.get(ip, {})
        banners = []
        if isinstance(info, dict) and "services" in info:
            for svc in info["services"]:
                banner = svc.get("banner", "") or svc.get("product", "") or ""
                if banner:
                    banners.append(f"{svc.get('port','')}/{svc.get('name','')}:{banner}")
        vuln_ips.append((ip, sorted(ports_set), banners))
    if {"22", "3389", "5900", "5901", "5985", "5986"} & ports_set:
        sensitive_ips.append((ip, sorted(ports_set), []))

# =================== DNS ===================
print("[*] Processando DNS...")
dns_lines = read_lines(os.path.join(BASE, "dns", "all.dns.txt"))
if not dns_lines:
    for alt_dir in ["dns", "dnsrec"]:
        for fname in ["all.dns.txt", "dns_records.txt", "records.txt"]:
            test_path = os.path.join(BASE, alt_dir, fname)
            if os.path.exists(test_path):
                dns_lines = read_lines(test_path)
                break
        if dns_lines:
            break

spf_dmarc = defaultdict(lambda: {"a": [], "mx": [], "ns": [], "txt": [], "cname": [], "soa": []})
for line in dns_lines:
    parts = line.split()
    if len(parts) >= 4:
        domain = parts[0]
        rtype = parts[2].upper()
        val = parts[3]
        if rtype in spf_dmarc[domain]:
            spf_dmarc[domain][rtype].append(val)

# Subdomain takeover indicators
takeover_indicators = ["heroku", "github.io", "amazonaws.com", "aws", "cloudfront", "fastly", "azure", "windows.net", "googleusercontent.com", "blogspot", "shopify", "surge.sh", "bit.ly", "tinyurl", "vercel", "netlify", "firebase", "pingdom", "tumblr", "unbounce", "wpengine", "zendesk", "desk.com", "teamwork.com", "helpjuice", "helpscout", "hostinger", "strikingly", "pageserve.co", "readme.io"]

potential_takeover = []
for domain, records in spf_dmarc.items():
    for cname in records["cname"]:
        for ind in takeover_indicators:
            if ind in cname.lower():
                potential_takeover.append((domain, cname))
                break

# Email spoofing (domínios alvo sem SPF/DMARC)
spoof_candidates = []
for domain, records in spf_dmarc.items():
    # Verifica se o domínio pertence ao alvo
    is_target = any(root in domain.lower() for root in root_domains)
    if not is_target:
        continue
    txts = " ".join(records["txt"]).lower()
    has_spf = "v=spf" in txts
    has_dmarc = "dmarc" in txts
    if not has_spf and not has_dmarc and (records["mx"] or records["a"]):
        if domain.count(".") >= 2:
            spoof_candidates.append(domain)

# =================== TECNOLOGIAS ===================
print("[*] Processando tecnologias...")
gowitness_lines = []
# Procura o arquivo de gowitness em várias localizações possíveis
for gw_path_candidate in [
    os.path.join(BASE, "content", "enum", "gowitness.enum.subs.jsonl"),
    os.path.join(BASE, "content", "gowitness", "results.jsonl"),
    os.path.join(BASE, "screenshots", "gowitness.jsonl"),
    os.path.join(BASE, "gowitness", "output.jsonl"),
]:
    if os.path.exists(gw_path_candidate):
        with open(gw_path_candidate, 'r', errors='ignore') as f:
            gowitness_lines = [l.strip() for l in f if l.strip()]
        break

tech_counter = Counter()
server_counter = Counter()
cms_counter = Counter()
framework_counter = Counter()
js_lib_counter = Counter()

sub_technologies = defaultdict(list)

for line in gowitness_lines:
    try:
        data = json.loads(line)
        url = data.get("url", "")
        domain = extract_domain(url)
        html = data.get("html", "")
        headers = data.get("headers", [])
        header_dict = {}
        for h in headers:
            if isinstance(h, dict):
                header_dict[h.get("key", "").lower()] = h.get("value", "")
            elif isinstance(h, list) and len(h) >= 2:
                header_dict[h[0].lower()] = h[1]

        server = header_dict.get("server", "")
        powered = header_dict.get("x-powered-by", "")
        via = header_dict.get("via", "")
        if server:
            server_counter[server] += 1
            sub_technologies[domain].append(f"Server: {server}")
        if powered:
            tech_counter[powered] += 1
            sub_technologies[domain].append(f"X-Powered-By: {powered}")
        if via:
            tech_counter[via] += 1

        # Detect from HTML
        if "wordpress" in html.lower() or "wp-content" in html.lower():
            cms_counter["WordPress"] += 1
            sub_technologies[domain].append("CMS: WordPress")
        if "drupal" in html.lower():
            cms_counter["Drupal"] += 1
            sub_technologies[domain].append("CMS: Drupal")
        if "joomla" in html.lower():
            cms_counter["Joomla"] += 1
            sub_technologies[domain].append("CMS: Joomla")
        if "django" in html.lower():
            framework_counter["Django"] += 1
            sub_technologies[domain].append("Framework: Django")
        if "rails" in html.lower() or "ruby" in html.lower():
            framework_counter["Ruby on Rails"] += 1
        if "laravel" in html.lower():
            framework_counter["Laravel"] += 1
        if "next.js" in html.lower() or "_next" in html.lower():
            framework_counter["Next.js"] += 1
        if "react" in html.lower():
            framework_counter["React"] += 1
        if "angular" in html.lower():
            framework_counter["Angular"] += 1
        if "vue" in html.lower():
            framework_counter["Vue.js"] += 1
        if "ckan" in html.lower():
            cms_counter["CKAN"] += 1
            sub_technologies[domain].append("CMS: CKAN")
        if "aem" in html.lower() or "/etc.clientlibs/" in html.lower():
            cms_counter["Adobe AEM"] += 1
            sub_technologies[domain].append("CMS: Adobe AEM")
        if "shiny" in html.lower() or "shinyapps" in html.lower():
            framework_counter["R Shiny"] += 1
            sub_technologies[domain].append("Framework: R Shiny")
        # SharePoint detection
        if "sharepoint" in html.lower() or "_sp" in html.lower() or "sprequest" in html.lower():
            cms_counter["SharePoint"] += 1
            sub_technologies[domain].append("CMS: SharePoint")

        # Detect vulnerable/old tech from HTML/headers
        old_tech = []
        if "apache/2.2" in (server + powered).lower():
            old_tech.append("Apache 2.2 (EOL)")
        if "apache/2.4" in (server + powered).lower():
            old_tech.append("Apache 2.4")
        if "nginx/1." in (server + powered).lower():
            old_tech.append("Nginx 1.x")
        if "iis/7" in (server + powered).lower() or "iis/6" in (server + powered).lower():
            old_tech.append("IIS 6/7 (EOL)")
        if "php/5" in (server + powered).lower():
            old_tech.append("PHP 5 (EOL)")
        if "php/7." in (server + powered).lower():
            old_tech.append("PHP 7.x")
        if "asp.net" in (server + powered).lower():
            framework_counter["ASP.NET"] += 1
        for t in old_tech:
            sub_technologies[domain].append(f"OLD: {t}")
    except:
        pass

# Tecnologias mais comuns
common_tech = server_counter.most_common(20) + tech_counter.most_common(20)

# Subdomínios vulneráveis por tecnologia
vuln_tech_subs = []
sensitive_tech_subs = []
for domain, techs in sub_technologies.items():
    tech_str = ", ".join(set(techs))
    if any(x in tech_str.lower() for x in ["old", "eol", "php 5", "iis 6", "iis 7", "apache 2.2", "wordpress", "drupal", "joomla", "rails"]):
        vuln_tech_subs.append((domain, tech_str))
    if any(x in tech_str.lower() for x in ["admin", "auth", "login", "sso", "api", "ckan", "aem", "jenkins", "gitlab", "sharepoint"]):
        sensitive_tech_subs.append((domain, tech_str))

# =================== JAVASCRIPT ===================
print("[*] Processando JavaScript...")
# Procura diretórios de JS em várias localizações
js_dir = None
beaut_dir = None
for js_base in [os.path.join(BASE, "content", "javascript", "downloads"), os.path.join(BASE, "js"), os.path.join(BASE, "javascript")]:
    js_test = os.path.join(js_base, "js_files")
    beaut_test = os.path.join(js_base, "beautified")
    if os.path.isdir(js_test):
        js_dir = js_test
    if os.path.isdir(beaut_test):
        beaut_dir = beaut_test
    if js_dir or beaut_dir:
        break

js_files = []
if js_dir:
    js_files = [os.path.join(js_dir, f) for f in os.listdir(js_dir) if f.endswith(".js")][:300]
if beaut_dir:
    js_files += [os.path.join(beaut_dir, f) for f in os.listdir(beaut_dir) if f.endswith(".js")][:300]

js_secrets = defaultdict(list)
js_endpoints = defaultdict(list)
js_graphql = []
js_websocket = []
js_eval = []
js_innerhtml = []
js_document_write = []
js_postmessage = []
js_localstorage = []
js_cookie = []
js_fetch_xhr = []
js_dangerous = []

secret_patterns = {
    "AWS Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret": r"['\"][0-9a-zA-Z/+]{40}['\"]",
    "Generic API Key": r"api[_-]?key['\"\s:=]+['\"][a-zA-Z0-9_\-]{16,}['\"]",
    "Secret Key": r"secret[_-]?key['\"\s:=]+['\"][a-zA-Z0-9_\-]{8,}['\"]",
    "Authorization Bearer": r"authorization['\"\s:=]+['\"]Bearer\s+[a-zA-Z0-9_\-\.]+['\"]",
    "Token": r"token['\"\s:=]+['\"][a-zA-Z0-9_\-\.]{16,}['\"]",
    "JWT": r"eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*",
    "Password": r"password['\"\s:=]+['\"][^\"\s]{4,}['\"]",
    "Email": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "CSRF Token": r"csrf[_-]?token['\"\s:=]+['\"][a-zA-Z0-9_-]+['\"]",
    "Private Key": r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
    "Slack Token": r"xox[baprs]-[0-9a-zA-Z]{10,48}",
    "GitHub Token": r"gh[pousr]_[A-Za-z0-9_]{36,}",
    "Google API Key": r"AIza[0-9A-Za-z_-]{35}",
    "Firebase URL": r"https://[a-z0-9-]+\.firebaseio\.com",
}

for jf in js_files:
    content = read_file(jf, limit=500000)
    fname = os.path.basename(jf)
    # secrets
    for name, pattern in secret_patterns.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        for m in matches[:5]:
            js_secrets[fname].append((name, str(m)[:120]))
    # endpoints
    eps = re.findall(r"['\"]((?:/|https?://)[a-zA-Z0-9_\-/\.\?=&+%]{5,200})['\"]", content)
    for ep in list(set(eps))[:20]:
        js_endpoints[fname].append(ep)
    # graphql
    if "graphql" in content.lower() or "/graphql" in content.lower():
        js_graphql.append(fname)
    # websocket
    if "websocket" in content.lower() or "ws://" in content.lower() or "wss://" in content.lower():
        js_websocket.append(fname)
    # dangerous patterns
    if "eval(" in content.lower():
        js_eval.append(fname)
    if ".innerHTML" in content:
        js_innerhtml.append(fname)
    if "document.write" in content.lower():
        js_document_write.append(fname)
    if "postMessage" in content:
        js_postmessage.append(fname)
    if "localStorage" in content or "sessionStorage" in content:
        js_localstorage.append(fname)
    if "document.cookie" in content:
        js_cookie.append(fname)
    if "fetch(" in content or "XMLHttpRequest" in content or "$.ajax" in content:
        js_fetch_xhr.append(fname)
    if any(x in content for x in ["innerHTML", "document.write", "eval(", "setTimeout('", "setInterval('", "Function(", "WebSocket(", "postMessage("]):
        js_dangerous.append(fname)

# =================== URLs / FUZZING ===================
print("[*] Processando URLs...")
urls = read_lines(os.path.join(BASE, "content", "urls", "all.cleaned.urls.txt"))
if not urls:
    urls = read_lines(os.path.join(BASE, "content", "urls", "all.urls.txt"))
if not urls:
    for alt_dir in ["content", "urls", "recon"]:
        for fname in ["all.urls.txt", "all.cleaned.urls.txt", "urls.txt", "endpoints.txt"]:
            test_path = os.path.join(BASE, alt_dir, fname)
            if os.path.exists(test_path):
                urls = read_lines(test_path)
                break
        if urls:
            break

vuln_paths = ["admin", "login", "config", "backup", "db", "api", "graphql", "websocket", "ws", "internal", "test", "dev", "staging", "debug", "trace", "actuator", "swagger", "openapi", "phpmyadmin", "wp-admin", "wp-login", "jmx-console", "manager", "console", "shell", "upload", "download", "file", "export", "import", "sql", "dump", "log", "logs", "error", "env", "config", "settings", "credentials", "secrets", "key", "keys", "token", "tokens", "password", "pwd", "auth", "oauth", "saml", "sso", "proxy", "vpn", "ssh", "ftp", "telnet", "remote", "xmlrpc", "jsonrpc", "rpc", "soap", "rest", "v1", "v2", "beta", "alpha", "old", "new", "tmp", "temp", "cache", "src", "source", "git", "svn", "cvs", "hg", "repo", "repository", "jenkins", "gitlab", "github", "bitbucket", "nexus", "artifactory", "kibana", "grafana", "prometheus", "elastic", "solr", "hadoop", "spark", "kafka", "zookeeper", "etcd", "consul", "vault", "firebase", "aws", "azure", "gcp", "cloud", "lambda", "function", "webhook", "callback", "redirect", "forward", "proxy", "gateway", "ingress", "service", "pod", "node", "cluster", "namespace", "helm"]
sensitive_paths = ["admin", "login", "auth", "sso", "signin", "account", "user", "users", "profile", "dashboard", "manage", "management", "control", "panel", "console", "settings", "config", "credentials", "secrets", "keys", "tokens", "passwords", "api-keys", "private", "internal", "restricted", "secure", "confidential", "classified", "sensitive", "pii", "phi", "gdpr", "hipaa", "pci", "sox", "audit", "compliance", "legal", "hr", "payroll", "finance", "billing", "invoice", "backup", "archive", "snapshot", "dump", "export", "import", "git", "svn", "repository", "source-code", "log", "logs", "audit-log", "monitor", "metric", "health", "status", "deploy", "deployment", "ci", "cd", "test", "staging", "uat", "preprod", "production", "prod", "pen-test", "vulnerability", "exploit", "cve"]

vuln_urls = []
sensitive_urls = []
for u in urls:
    low = u.lower()
    if any(v in low for v in vuln_paths):
        vuln_urls.append(u)
    if any(s in low for s in sensitive_paths):
        sensitive_urls.append(u)

# Fuzzing results
fuzz_dir = os.path.join(BASE, "content", "fuzzing")
if not os.path.isdir(fuzz_dir):
    fuzz_dir = os.path.join(BASE, "fuzzing")
fuzz_results = []
if os.path.isdir(fuzz_dir):
    for f in os.listdir(fuzz_dir):
        if f.endswith(".txt") and (f.startswith("gobuster.") or f.startswith("ffuf.") or f.startswith("dirsearch.") or f.startswith("feroxbuster.")):
            path = os.path.join(fuzz_dir, f)
            size = os.path.getsize(path)
            if size > 0 and size < 500000:
                lines = read_lines(path)
                if lines:
                    domain = f.replace("gobuster.", "").replace("ffuf.", "").replace("dirsearch.", "").replace("feroxbuster.", "").replace(".txt", "").replace("_", ".")
                    for line in lines[:10]:
                        fuzz_results.append((domain, line))

# =================== HTML SENSITIVE DATA ===================
print("[*] Processando HTMLs...")
html_dir = os.path.join(BASE, "content", "screenshots", "aquatone", "html")
if not os.path.isdir(html_dir):
    for alt in [os.path.join(BASE, "screenshots", "html"), os.path.join(BASE, "html"), os.path.join(BASE, "content", "html")]:
        if os.path.isdir(alt):
            html_dir = alt
            break

html_sensitive = defaultdict(list)
if os.path.isdir(html_dir):
    html_files = [os.path.join(html_dir, f) for f in os.listdir(html_dir) if f.endswith(".html")][:200]
    for hf in html_files:
        content = read_file(hf, limit=200000).lower()
        domain = os.path.basename(hf).replace(".html", "").replace("-", ".")
        emails = re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", content)
        for e in list(set(emails))[:10]:
            html_sensitive[domain].append(f"Email: {e}")
        if re.search(r"password['\"\s:=]+['\"][^\"\s]{3,}['\"]", content):
            html_sensitive[domain].append("Password in HTML")
        if "_csrf_token" in content or "csrf_token" in content:
            html_sensitive[domain].append("CSRF token exposed")
        if "api_key" in content or "apikey" in content:
            html_sensitive[domain].append("API key reference")
        if "secret" in content:
            html_sensitive[domain].append("Secret reference")
        if "aws_access_key_id" in content or "aws_secret_access_key" in content:
            html_sensitive[domain].append("AWS credentials")
        if "<form" in content and "csrf" not in content:
            html_sensitive[domain].append("Form without CSRF protection")

# =================== GIT EXPOSURE ===================
print("[*] Processando exposição Git...")
git_dir = os.path.join(BASE, "content", "fuzzing", "git")
if not os.path.isdir(git_dir):
    git_dir = os.path.join(BASE, "git")
git_exposed = []
if os.path.isdir(git_dir):
    for f in os.listdir(git_dir):
        if f.endswith(".txt"):
            lines = read_lines(os.path.join(git_dir, f))
            if lines:
                git_exposed.append((f.replace(".txt", "").replace("_", "."), lines[:5]))

# =================== WORDLISTS ===================
print("[*] Processando wordlists...")
wordlist_dir = os.path.join(BASE, "content", "wordlists", "cewl")
cewl_words = []
if os.path.isdir(wordlist_dir):
    for f in os.listdir(wordlist_dir):
        if f.endswith(".txt"):
            words = read_lines(os.path.join(wordlist_dir, f))
            cewl_words.extend(words)

# =================== GERAR RELATÓRIO ===================
print(f"[*] Gerando relatório para {ORG_NAME}...")

# Prepara observações dinâmicas
dynamic_observacoes = []

# Verifica presença de subdomínios legados
legacy_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["www1", "www2", "www0", "old", "legacy", "v1", "v2"])])
if legacy_count > 0:
    dynamic_observacoes.append(f"- Presença de {legacy_count} subdomínios com nomenclatura legada (`www1`, `www2`, `old`, `legacy`, `v1`, `v2`) que podem executar software desatualizado ou sem manutenção.")

# Verifica ambientes de staging/teste
staging_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["staging", "uat", "dev", "sandbox", "demo", "beta", "alpha", "test", "qa"])])
if staging_count > 0:
    dynamic_observacoes.append(f"- {staging_count} subdomínios de ambientes de staging/teste/desenvolvimento identificados. Estes ambientes frequentemente possuem configurações de segurança relaxadas, credenciais padrão ou dados de teste expostos.")

# Verifica presença de API
api_count = len([s for s in subs_all if "api" in extract_domain(s).lower()])
if api_count > 0:
    dynamic_observacoes.append(f"- {api_count} subdomínios com `api` no nome. APIs requerem testes específicos de segurança como BOLA, BFLA, excesso de dados, rate limiting e autenticação.")

# Verifica CDN
cdn_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["cdn", "assets", "static"])])
if cdn_count > 0 and (any("cloudfront" in str(server_counter).lower() for _ in range(1)) or True):
    dynamic_observacoes.append(f"- Infraestrutura com CDN identificada. Pode mascarar a origem real dos servidores, mas também introduz riscos de cache poisoning e bypass.")

# Verifica kubernetes
k8s_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["k8s", "kube", "cluster", "openshift"])])
if k8s_count > 0:
    dynamic_observacoes.append(f"- {k8s_count} subdomínios relacionados a Kubernetes/OpenShift. Estes ambientes podem expor dashboards, APIs (ex: `/api/v1/namespaces`), métricas ou painéis sem autenticação.")

# Verifica autenticação centralizada
sso_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["sso", "login", "auth", "oauth", "saml", "idp", "iam"])])
if sso_count > 0:
    dynamic_observacoes.append(f"- {sso_count} subdomínios relacionados a autenticação centralizada (SSO, IAM, Login). Um comprometimento destes serviços poderia afetar todo o ecossistema de aplicações.")

# Verifica admin panels
admin_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["admin", "dashboard", "console", "panel", "manage"])])
if admin_count > 0:
    dynamic_observacoes.append(f"- {admin_count} painéis administrativos expostos. Verificar credenciais padrão, autenticação fraca e falta de rate limiting.")

# Verifica servidores de e-mail
mail_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["mail", "email", "smtp", "exchange", "webmail", "autodiscover"])])
if mail_count > 0:
    dynamic_observacoes.append(f"- {mail_count} servidores de e-mail identificados. Testar open relay, enumeração de usuários, spoofing e configurações de segurança.")

# Verifica bancos de dados expostos
db_count = len([s for s in subs_all if any(x in extract_domain(s).lower() for x in ["db", "database", "sql", "mysql", "postgres", "mongo", "redis", "elasticsearch"])])
if db_count > 0:
    dynamic_observacoes.append(f"- {db_count} referências a bancos de dados em subdomínios. Extremamente crítico se acessível externamente — testar autenticação padrão e exposição indevida.")

# Verifica Git exposto
if git_exposed:
    dynamic_observacoes.append(f"- {len(git_exposed)} repositórios Git expostos encontrados. Podem conter credenciais, chaves de API, configurações de infraestrutura e código-fonte proprietário.")

# Verifica subdomain takeover
if potential_takeover:
    dynamic_observacoes.append(f"- {len(potential_takeover)} potenciais casos de subdomain takeover identificados via CNAME para serviços de terceiros. Priorizar verificação.")

# Verifica se tem muitas portas abertas
total_ports = sum(len(ps) for ps in host_ports.values())
if total_ports > 0:
    dynamic_observacoes.append(f"- Total de {total_ports} portas abertas em {len(host_ports)} hosts. Cada serviço adicional aumenta a superfície de ataque.")

# Observação genérica sobre múltiplos datacenters se aplicável
if len(root_domains) > 1:
    dynamic_observacoes.append(f"- Múltiplos domínios alvo ({', '.join(root_domais[:5])}{'...' if len(root_domains) > 5 else ''}) aumentam a superfície de ataque. Verificar relações de confiança entre eles.")

# Se não encontrou nada específico
if not dynamic_observacoes:
    dynamic_observacoes.append("- Nenhuma observação específica gerada automaticamente. Revisar dados manualmente para identificar padrões de vulnerabilidade.")

with open(OUT, 'w', encoding='utf-8') as md:
    md.write(f"# Resumo de Reconhecimento - {ORG_NAME}\n\n")
    md.write(f"**Data:** 2026-06-09\n\n")
    md.write(f"**Domínios alvo:** {', '.join(root_domains)}\n\n")
    md.write(f"**Total de subdomínios ativos:** {len(subs_all)}\n\n")
    md.write(f"**Total de hosts com portas abertas:** {len(host_ports)}\n\n")
    md.write(f"**Total de URLs coletadas:** {len(urls)}\n\n")
    md.write("---\n\n")

    # SUBDOMÍNIOS
    md.write("## 1. Subdomínios\n\n")
    md.write("### 1.1 Subdomínios aparentemente mais vulneráveis (baseado no nome)\n\n")
    md.write("Subdomínios com palavras-chave indicativas de ambientes de desenvolvimento, teste, legado ou infraestrutura exposta:\n\n")
    for s in subs_vuln[:40]:
        md.write(f"- `{s}`\n")
    if len(subs_vuln) > 40:
        md.write(f"- ... e mais {len(subs_vuln)-40} outros\n")
    md.write("\n")

    md.write("### 1.2 Subdomínios aparentemente mais sensíveis (baseado no nome)\n\n")
    md.write("Subdomínios com palavras-chave indicativas de autenticação, administração, dados sensíveis ou infraestrutura crítica:\n\n")
    for s in subs_sensitive[:40]:
        md.write(f"- `{s}`\n")
    if len(subs_sensitive) > 40:
        md.write(f"- ... e mais {len(subs_sensitive)-40} outros\n")
    md.write("\n")

    md.write("### 1.3 Categorização dos subdomínios\n\n")
    for cat in sorted(categories.keys()):
        md.write(f"#### {cat.upper()} ({len(categories[cat])})\n\n")
        for s in categories[cat][:15]:
            md.write(f"- `{s}`\n")
        if len(categories[cat]) > 15:
            md.write(f"- ... e mais {len(categories[cat])-15} outros\n")
        md.write("\n")

    # INFRAESTRUTURA
    md.write("---\n\n")
    md.write("## 2. Infraestrutura\n\n")
    md.write("### 2.1 IPs mais vulneráveis (baseado em serviços/portas)\n\n")
    md.write("Hosts com portas não-padrão, serviços legados ou potencialmente vulneráveis:\n\n")
    md.write("| IP | Portas | Banners/Serviços |\n")
    md.write("|---|---|---|\n")
    for ip, ports_list, banners in vuln_ips[:30]:
        banner_str = "; ".join(banners) if banners else "N/A"
        if len(banner_str) > 100:
            banner_str = banner_str[:100] + "..."
        md.write(f"| {ip} | {', '.join(ports_list)} | {banner_str} |\n")
    md.write("\n")

    md.write("### 2.2 IPs mais sensíveis (baseado em serviços/portas)\n\n")
    md.write("Hosts com acesso remoto, administração ou serviços críticos:\n\n")
    md.write("| IP | Portas | Banners/Serviços |\n")
    md.write("|---|---|---|\n")
    for ip, ports_list, banners in sensitive_ips[:30]:
        banner_str = "; ".join(banners) if banners else "N/A"
        if len(banner_str) > 100:
            banner_str = banner_str[:100] + "..."
        md.write(f"| {ip} | {', '.join(ports_list)} | {banner_str} |\n")
    md.write("\n")

    # DNS
    md.write("---\n\n")
    md.write("## 3. DNS\n\n")
    md.write("### 3.1 Subdomínios potencialmente vulneráveis a Subdomain Takeover\n\n")
    md.write("Registros CNAME apontando para serviços de terceiros que podem estar desprotegidos:\n\n")
    md.write("| Subdomínio | CNAME |\n")
    md.write("|---|---|\n")
    for domain, cname in potential_takeover[:30]:
        md.write(f"| {domain} | {cname} |\n")
    if not potential_takeover:
        md.write("Nenhum indicador claro de takeover encontrado nos registros analisados.\n")
    md.write("\n")

    md.write("### 3.2 Subdomínios potencialmente vulneráveis a Email Spoofing\n\n")
    md.write("Domínios sem registros SPF/DMARC visíveis (requer validação adicional):\n\n")
    for d in sorted(set(spoof_candidates))[:40]:
        md.write(f"- `{d}`\n")
    if not spoof_candidates:
        md.write("Nenhum domínio sem SPF/DMARC identificado nos registros analisados.\n")
    md.write("\n")

    # TECNOLOGIAS
    md.write("---\n\n")
    md.write("## 4. Tecnologias\n\n")

    md.write("### 4.1 Tecnologias potencialmente vulneráveis/legadas detectadas\n\n")
    old_tech_found = set()
    for domain, techs in sub_technologies.items():
        for t in techs:
            if "OLD:" in t or "eol" in t.lower():
                old_tech_found.add(f"{domain}: {t}")
    for item in sorted(old_tech_found)[:30]:
        md.write(f"- `{item}`\n")
    if not old_tech_found:
        md.write("Nenhuma tecnologia claramente EOL identificada nos headers. Requer análise manual aprofundada.\n")
    md.write("\n")

    md.write("### 4.2 Tecnologias mais utilizadas\n\n")
    md.write("#### Servidores Web\n\n")
    for tech, count in server_counter.most_common(20):
        md.write(f"- {tech}: {count} ocorrências\n")
    md.write("\n#### Frameworks/CMS detectados via HTML\n\n")
    for tech, count in (cms_counter + framework_counter).most_common(20):
        md.write(f"- {tech}: {count} ocorrências\n")
    md.write("\n")

    md.write("### 4.3 Vulnerabilidades comuns nas tecnologias identificadas\n\n")
    md.write("Com base nas tecnologias detectadas, as seguintes classes de vulnerabilidades são historicamente relevantes:\n\n")
    tech_vulns = {
        "WordPress": ["CVEs em plugins/temas", "XML-RPC abuse", "Autenticação fraca", "Upload não restrito", "SQL Injection em plugins"],
        "Drupal": ["SA-CORE-2018-002 (Drupalgeddon)", "PHP Object Injection", "Access Bypass"],
        "Joomla": ["RCE em extensões", "SQL Injection", "Authentication Bypass"],
        "CKAN": ["API Key exposure", "Authorization bypass", "Data leakage"],
        "Adobe AEM": ["Dispatcher bypass", "CRXDE exposure", "SSRF", "RCE"],
        "SharePoint": ["Information disclosure", "Privilege escalation", "Workflow bypass", "ViewState deserialization"],
        "Apache": ["HTTP Request Smuggling", "Path Traversal", "Mod_proxy exploits", "Log4j (se Java presente)"],
        "Nginx": ["HTTP Request Smuggling", "Alias Traversal", "Lua injection (se OpenResty)"],
        "IIS": ["HTTP Request Smuggling", "Shortname Scanning", "ASP.NET ViewState RCE", "Token leak"],
        "PHP": ["Deserialization", "File Inclusion (LFI/RFI)", "SQL Injection", "XXE", "Open Redirect"],
        "ASP.NET": ["ViewState deserialization", "JWT bypass", "SQL Injection", "XXE", "Request Validation Bypass"],
        "React/Next.js": ["XSS via dangerouslySetInnerHTML", "SSRF em getServerSideProps", "Open Redirect", "Cache Poisoning"],
        "Angular": ["XSS via bypassSecurityTrust", "Template Injection", "Open Redirect"],
        "R Shiny": ["RCE via serialize/deserialize", "SSRF", "Path Traversal"],
        "Django": ["SQL Injection", "XSS", "CSRF bypass", "Debug mode exposure", "Mass assignment"],
        "Laravel": ["Debug mode exposed (.env)", "Deserialization", "Mass assignment", "SQL Injection"],
        "Ruby on Rails": ["Mass assignment", "SQL Injection", "Deserialization (YAML)", "Open Redirect"],
        "Vue.js": ["Template Injection", "XSS via v-html", "Component injection"],
    }
    for tech, vulns in tech_vulns.items():
        md.write(f"**{tech}**:\n")
        for v in vulns:
            md.write(f"  - {v}\n")
        md.write("\n")

    md.write("### 4.4 Subdomínios mais vulneráveis por tecnologia/versão\n\n")
    for domain, techs in vuln_tech_subs[:30]:
        md.write(f"- `{domain}`: {techs}\n")
    md.write("\n")

    md.write("### 4.5 Subdomínios mais sensíveis por tecnologia/versão\n\n")
    for domain, techs in sensitive_tech_subs[:30]:
        md.write(f"- `{domain}`: {techs}\n")
    md.write("\n")

    md.write("### 4.6 Informações sensíveis em HTMLs\n\n")
    for domain, findings in sorted(html_sensitive.items())[:30]:
        md.write(f"**{domain}**:\n")
        for f in set(findings):
            md.write(f"  - {f}\n")
        md.write("\n")

    # JAVASCRIPT
    md.write("---\n\n")
    md.write("## 5. JavaScript\n\n")

    md.write("### 5.1 Vulnerabilidades client-side detectadas\n\n")
    md.write("#### Uso de eval() (potencial XSS/Code Injection)\n\n")
    for f in list(set(js_eval))[:15]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_eval))} arquivos\n\n")

    md.write("#### Uso de innerHTML (potencial XSS/DOM-based)\n\n")
    for f in list(set(js_innerhtml))[:15]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_innerhtml))} arquivos\n\n")

    md.write("#### Uso de document.write (potencial XSS)\n\n")
    for f in list(set(js_document_write))[:15]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_document_write))} arquivos\n\n")

    md.write("#### Uso de postMessage (potencial XSS/CSRF via origem não validada)\n\n")
    for f in list(set(js_postmessage))[:15]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_postmessage))} arquivos\n\n")

    md.write("#### Uso de localStorage/sessionStorage (potencial leak de dados sensíveis)\n\n")
    for f in list(set(js_localstorage))[:15]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_localstorage))} arquivos\n\n")

    md.write("#### Uso de document.cookie (potencial XSS/Session Hijacking)\n\n")
    for f in list(set(js_cookie))[:15]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_cookie))} arquivos\n\n")

    md.write("### 5.2 Informações sensíveis em JavaScript\n\n")
    md.write("| Arquivo | Tipo | Valor (truncado) |\n")
    md.write("|---|---|---|\n")
    shown = 0
    for fname, secrets in js_secrets.items():
        for stype, sval in secrets:
            if shown < 50:
                md.write(f"| {fname} | {stype} | `{sval[:80]}` |\n")
                shown += 1
    if shown == 0:
        md.write("Nenhum segredo óbvio encontrado nos arquivos JavaScript analisados (amostra limitada).\n")
    md.write("\n")

    md.write("### 5.3 Subdomínios mais vulneráveis por robustez do JavaScript\n\n")
    md.write("Arquivos JavaScript com padrões perigosos (eval, innerHTML, document.write):\n\n")
    for f in list(set(js_dangerous))[:30]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(set(js_dangerous))} arquivos com padrões perigosos\n\n")

    md.write("### 5.4 Subdomínios mais sensíveis por lógica do JavaScript\n\n")
    md.write("Arquivos com manipulação de autenticação, tokens, storage ou cookies:\n\n")
    sensitive_js = set(js_cookie) | set(js_localstorage) | set(js_postmessage)
    for f in list(set(sensitive_js))[:30]:
        md.write(f"- `{f}`\n")
    md.write(f"\nTotal: {len(sensitive_js)} arquivos\n\n")

    md.write("### 5.5 Endpoints GraphQL e WebSocket\n\n")
    md.write("#### GraphQL\n\n")
    for f in list(set(js_graphql))[:20]:
        md.write(f"- `{f}`\n")
    if not js_graphql:
        md.write("Nenhuma referência a GraphQL encontrada nos JavaScript analisados.\n")
    md.write("\n#### WebSocket\n\n")
    for f in list(set(js_websocket))[:20]:
        md.write(f"- `{f}`\n")
    if not js_websocket:
        md.write("Nenhuma referência a WebSocket encontrada nos JavaScript analisados.\n")
    md.write("\n")

    # URLs E FUZZING
    md.write("---\n\n")
    md.write("## 6. URLs e Fuzzing\n\n")

    md.write("### 6.1 URLs mais vulneráveis (baseado no nome/caminho)\n\n")
    for u in vuln_urls[:40]:
        md.write(f"- `{u}`\n")
    if len(vuln_urls) > 40:
        md.write(f"- ... e mais {len(vuln_urls)-40} outras\n")
    md.write("\n")

    md.write("### 6.2 URLs mais sensíveis (baseado no nome/caminho)\n\n")
    for u in sensitive_urls[:40]:
        md.write(f"- `{u}`\n")
    if len(sensitive_urls) > 40:
        md.write(f"- ... e mais {len(sensitive_urls)-40} outras\n")
    md.write("\n")

    md.write("### 6.3 Resultados de Fuzzing (amostra)\n\n")
    for domain, line in fuzz_results[:30]:
        md.write(f"- `{domain}`: `{line}`\n")
    if not fuzz_results:
        md.write("Nenhum resultado de fuzzing disponível ou arquivos vazios.\n")
    md.write("\n")

    # OUTROS
    md.write("---\n\n")
    md.write("## 7. Outros Achados Interessantes\n\n")

    md.write("### 7.1 Exposição de repositórios Git\n\n")
    for domain, lines in git_exposed[:10]:
        md.write(f"- `{domain}`: {lines}\n")
    if not git_exposed:
        md.write("Nenhum repositório Git exposto identificado.\n")
    md.write("\n")

    md.write("### 7.2 Subdomínios com wildcard TLS (indicativo de infraestrutura compartilhada)\n\n")
    wildcard_domains = []
    for line in gowitness_lines:
        try:
            data = json.loads(line)
            tls = data.get("tls", {})
            if tls and tls.get("subject_common_name", "").startswith("*."):
                wildcard_domains.append(extract_domain(data.get("url", "")))
        except:
            pass
    for d in sorted(set(wildcard_domains))[:20]:
        md.write(f"- `{d}`\n")
    md.write("\n")

    md.write("### 7.3 Redirecionamentos para autenticação (SSO)\n\n")
    sso_redirects = []
    for line in gowitness_lines:
        try:
            data = json.loads(line)
            url = data.get("url", "")
            final = data.get("final_url", "")
            if any(x in final.lower() for x in ["login", "sso", "signin", "auth", "oauth", "saml", "idp"]):
                if "login" in final.lower() or "sso" in final.lower():
                    sso_redirects.append(extract_domain(url))
        except:
            pass
    for d in sorted(set(sso_redirects))[:20]:
        md.write(f"- `{d}` -> Redireciona para SSO\n")
    md.write("\n")

    md.write("### 7.4 Potenciais vulnerabilidades de CORS/CSP\n\n")
    md.write("Alguns subdomínios podem apresentar headers CSP complexos com múltiplas origens permitidas. Verificar:\n")
    md.write("- Endpoints que aceitam `Origin` headers sem validação rigorosa\n")
    md.write("- Headers `Access-Control-Allow-Origin: *` em endpoints com dados sensíveis\n")
    md.write("- Políticas CSP com `*` em `script-src`, `frame-ancestors` ou `connect-src`\n")
    md.write("\n")

    md.write("### 7.5 Ambientes Kubernetes expostos\n\n")
    k8s_domains = [extract_domain(s) for s in subs_all if any(x in extract_domain(s).lower() for x in ["k8s", "kube", "cluster"])]
    for d in sorted(set(k8s_domains))[:20]:
        md.write(f"- `{d}`\n")
    if k8s_domains:
        md.write("\nEstes ambientes podem expor dashboards, APIs ou métricas do Kubernetes (ex: `/api/v1/namespaces`, `/metrics`).\n")
    md.write("\n")

    md.write("### 7.6 Observações gerais\n\n")
    for obs in dynamic_observacoes:
        md.write(f"{obs}\n")
    md.write("\n")

    md.write("---\n\n")
    md.write(f"*Relatório gerado automaticamente para {ORG_NAME} a partir de dados de reconhecimento. Requer validação manual para confirmação de vulnerabilidades.*\n")

print(f"[+] Relatório gerado em: {OUT}")