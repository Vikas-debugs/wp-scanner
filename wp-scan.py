import argparse, re, json, requests, concurrent.futures, hashlib, random, time
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()

# --- CONFIGURATION ---
WPSCAN_API_TOKEN = "xOeejWBHk7HByal10JfJJEKLdlOn2e4qnsGdzh6K5Z8" # <--- PASTE YOUR TOKEN HERE
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
]

HOMEPAGE_HASH = None

def get(url, s, timeout=15, allow_redirects=True, verbose=False):
    headers = {
        "User-Agent": random.choice(UAS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close"
    }
    try:
        time.sleep(random.uniform(0.1, 0.3))
        r = s.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=allow_redirects)
        if verbose:
            print(f"    {r.status_code:>3}  {url}  ({len(r.content)}b)")
        return r
    except Exception as e:
        if verbose:
            print(f"    ERR   {url}  -> {type(e).__name__}")
        return None

def check_fallback(base, s):
    global HOMEPAGE_HASH
    r = get(base, s, verbose=False)
    if r:
        HOMEPAGE_HASH = hashlib.md5(r.content).hexdigest()

def is_fallback(r):
    if not r or not HOMEPAGE_HASH: return False
    return hashlib.md5(r.content).hexdigest() == HOMEPAGE_HASH

def detect_wp(base, s):
    info = {"version": None}
    r = get(urljoin(base, "/readme.html"), s, verbose=False)
    if r and r.status_code == 200 and not is_fallback(r):
        m = re.search(r'Version ([\d.]+)', r.text)
        if m: info["version"] = m.group(1)

    if not info["version"]:
        r = get(base, s, verbose=False)
        if r:
            vers = re.findall(r'wp-(?:includes|content)/.*?\?ver=([\d]+\.[\d\.]+)', r.text)
            if vers:
                info["version"] = sorted(set(vers), key=vers.count, reverse=True)[0]

    print(f"[*] Core Version: {info['version'] or 'unknown'}")
    return info

def enum_users(base, s):
    users = set()
    
    r = get(urljoin(base, "/wp-json/wp/v2/users"), s, verbose=False)
    if r and r.status_code == 200 and not is_fallback(r):
        with open("raw_rest_users.json", "w") as f:
            f.write(r.text)
        print("    [+] REST API returned 200. Raw response saved to raw_rest_users.json")
        try:
            data = r.json()
            if isinstance(data, list):
                for u in data:
                    if u.get("slug"): users.add(u["slug"])
        except: pass

    r = get(urljoin(base, "/wp-json/oembed/1.0/embed?url=" + base), s, verbose=False)
    if r and r.status_code == 200 and not is_fallback(r):
        try:
            data = r.json()
            if "author_name" in data: users.add(data["author_name"])
            if "author_url" in data:
                m = re.search(r'/author/([^/]+)', data["author_url"])
                if m: users.add(m.group(1))
        except: pass

    r = get(urljoin(base, "/?feed=rss2"), s, verbose=False)
    if r and r.status_code == 200 and not is_fallback(r):
        creators = re.findall(r'<dc:creator><!\[CDATA\[(.*?)\]\]></dc:creator>', r.text)
        for c in creators: users.add(c)

    print(f"[*] Users found: {list(users)}")
    return list(users)

def enum_plugins(base, s):
    r = get(base, s, verbose=False)
    plugins = set()
    if r: plugins = set(re.findall(r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/', r.text))
    plugin_data = {}
    for p in plugins:
        r = get(urljoin(base, f"/wp-content/plugins/{p}/readme.txt"), s, verbose=False)
        ver = "unknown"
        if r and r.status_code == 200 and not is_fallback(r):
            m = re.search(r'Stable tag:\s*([\d.]+)', r.text)
            if m: ver = m.group(1)
        plugin_data[p] = ver
    return plugin_data

def query_wpscan_api(plugins, core_version):
    if WPSCAN_API_TOKEN == "YOUR_API_TOKEN_HERE":
        print("[!] WPScan API token missing. Skipping CVE lookup.")
        return []
    
    print("[*] Querying WPScan API for CVEs...")
    headers = {"Authorization": f"Token token={WPSCAN_API_TOKEN}"}
    vulns = []

    def parse_fixed_in(fixed_in):
        if not fixed_in: return "Not patched"
        if isinstance(fixed_in, list): return ", ".join(fixed_in)
        return str(fixed_in)

    # Core CVEs
    if core_version:
        url = f"https://wpscan.com/api/v3/wordpresses/{core_version.replace('.', '')}"
        try:
            r = requests.get(url, headers=headers, verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                for v in data.get(core_version.replace('.', ''), {}).get("vulnerabilities", []):
                    cve = v.get("references", {}).get("cve", ["N/A"])[0] if v.get("references", {}).get("cve") else "N/A"
                    fixed = parse_fixed_in(v.get("fixed_in"))
                    vulns.append({"target": "core", "title": v["title"], "cve": cve, "fixed_in": fixed})
                    print(f"    [!] CORE: {v['title']} (CVE: {cve}) - Fixed in: {fixed}")
        except Exception as e:
            print(f"    [-] Core API error: {e}")

    # Plugin CVEs
    for p_name, p_ver in plugins.items():
        if p_ver == "unknown": continue
        url = f"https://wpscan.com/api/v3/plugins/{p_name}"
        try:
            r = requests.get(url, headers=headers, verify=False, timeout=10)
            if r.status_code == 200:
                data = r.json()
                if p_name in data:
                    for v in data[p_name].get("vulnerabilities", []):
                        fixed_in = v.get("fixed_in")
                        # Logic fix: Safely check if version is vulnerable
                        is_vuln = False
                        if not fixed_in:
                            is_vuln = True # No patch = vulnerable
                        elif isinstance(fixed_in, str):
                            is_vuln = p_ver < fixed_in
                        elif isinstance(fixed_in, list):
                            is_vuln = any(p_ver < f for f in fixed_in)
                        
                        if is_vuln:
                            cve = v.get("references", {}).get("cve", ["N/A"])[0] if v.get("references", {}).get("cve") else "N/A"
                            fixed_str = parse_fixed_in(fixed_in)
                            vulns.append({"target": p_name, "title": v["title"], "cve": cve, "fixed_in": fixed_str})
                            print(f"    [!] {p_name} (v{p_ver}) -> {v['title']} (CVE: {cve}) - Fixed in: {fixed_str}")
        except Exception as e:
            pass # Silently skip API errors for individual plugins

    return vulns

def main():
    ap = argparse.ArgumentParser(description="Next-Gen WordPress Vulnerability Scanner")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    
    base = a.url.rstrip("/")
    if not base.startswith("http"): base = "https://" + base

    print(f"[*] Target: {base}")
    s = requests.Session()

    check_fallback(base, s)
    core_info = detect_wp(base, s)
    users = enum_users(base, s)
    plugins = enum_plugins(base, s)
    
    print(f"[*] Plugins detected: {len(plugins)}")
    for p, v in plugins.items(): print(f"    - {p} (v{v})")

    vulns = query_wpscan_api(plugins, core_info["version"])

    if a.output:
        json.dump({"target": base, "core": core_info, "users": users, "plugins": plugins, "vulnerabilities": vulns},
                  open(a.output, "w"), indent=2)
        print(f"\n[+] Report saved to {a.output}")

if __name__ == "__main__":
    main()