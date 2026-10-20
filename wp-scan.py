import argparse, re, json, ssl, socket, requests, concurrent.futures
from urllib.parse import urljoin

requests.packages.urllib3.disable_warnings()
HEADERS = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                         "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}


def get(url, s, timeout=15, allow_redirects=True, verbose=True):
    try:
        r = s.get(url, headers=HEADERS, timeout=timeout,
                  verify=False, allow_redirects=allow_redirects)
        if verbose:
            print(f"    {r.status_code:>3}  {url}  ({len(r.content)}b)")
        return r
    except requests.exceptions.SSLError as e:
        print(f"    SSL   {url}  -> {e}")
    except requests.exceptions.ConnectTimeout:
        print(f"    TMO   {url}  -> connect timeout")
    except requests.exceptions.ReadTimeout:
        print(f"    TMO   {url}  -> read timeout")
    except requests.exceptions.ConnectionError as e:
        print(f"    CONN  {url}  -> {type(e).__name__}")
    except Exception as e:
        print(f"    ERR   {url}  -> {type(e).__name__}: {e}")
    return None


def preflight(base):
    """Check DNS + TCP + TLS before doing anything else."""
    host = base.split("://", 1)[-1].split("/")[0]
    port = 443 if base.startswith("https") else 80
    print(f"[*] preflight: {host}:{port}")
    try:
        ip = socket.gethostbyname(host)
        print(f"    DNS   -> {ip}")
    except socket.gaierror as e:
        print(f"    DNS   -> FAILED ({e})"); return False
    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.close()
        print(f"    TCP   -> open")
    except Exception as e:
        print(f"    TCP   -> FAILED ({type(e).__name__})"); return False
    if port == 443:
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((host, port), timeout=10),
                                 server_hostname=host) as ss:
                print(f"    TLS   -> {ss.version()} / {ss.cipher()[0]}")
        except Exception as e:
            print(f"    TLS   -> FAILED ({type(e).__name__}: {e})")
    return True


def detect_wp(base, s):
    info = {}
    r = get(base, s)
    if not r:
        return info
    print(f"    server={r.headers.get('Server')}  xpb={r.headers.get('X-Powered-By')}")
    print(f"    has_wp_content={'/wp-content/' in r.text}  "
          f"has_wp_json={'/wp-json/' in r.text}")
    m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)"', r.text, re.I)
    if m:
        info["version"] = m.group(1)
    r = get(urljoin(base, "/readme.html"), s)
    if r and r.status_code == 200:
        m = re.search(r'Version ([\d.]+)', r.text)
        if m:
            info.setdefault("version", m.group(1))
    return info


def enum_users(base, s):
    users = []
    r = get(urljoin(base, "/wp-json/wp/v2/users"), s)
    if r and r.status_code == 200:
        try:
            for u in r.json():
                users.append({"slug": u.get("slug"), "name": u.get("name")})
        except json.JSONDecodeError:
            print("    REST users -> not JSON")
    if not users:
        for i in range(1, 6):
            r = get(urljoin(base, f"/?author={i}"), s, allow_redirects=False)
            if r and r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                m = re.search(r'/author/([^/]+)', loc)
                if m:
                    users.append({"slug": m.group(1)})
    return users


def enum_plugins(base, s):
    r = get(base, s)
    if not r:
        return []
    return sorted(set(re.findall(r'/wp-content/plugins/([a-zA-Z0-9_\-]+)/', r.text)))


def check_paths(base, s):
    PATHS = ["/wp-json/", "/wp-json/wp/v2/users", "/xmlrpc.php", "/readme.html",
             "/wp-login.php", "/wp-sitemap.xml", "/wp-sitemap-users-1.xml",
             "/wp-content/debug.log", "/wp-config.php.bak", "/.git/config",
             "/.env", "/wp-content/uploads/", "/wp-admin/"]
    hits = []
    def probe(p):
        r = get(urljoin(base, p), s, timeout=12, verbose=False)
        if r and r.status_code in (200, 301, 302, 401, 403):
            print(f"    {r.status_code:>3}  {p}  ({len(r.content)}b)")
            return {"path": p, "status": r.status_code, "len": len(r.content)}
        return None
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for res in ex.map(probe, PATHS):
            if res:
                hits.append(res)
    return hits


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("-o", "--output")
    a = ap.parse_args()
    base = a.url.rstrip("/")
    if not base.startswith("http"):
        base = "https://" + base

    print(f"[*] target: {base}")
    if not preflight(base):
        print("[!] target unreachable — stopping")
        return

    s = requests.Session()
    print("[*] fingerprint")
    info = detect_wp(base, s)
    print(f"[*] wp version: {info.get('version', 'unknown')}")
    print("[*] users")
    users = enum_users(base, s)
    for u in users: print("   ", u)
    print("[*] plugins")
    plugins = enum_plugins(base, s)
    for p in plugins: print("   ", p)
    print("[*] paths")
    paths = check_paths(base, s)

    if a.output:
        json.dump({"target": base, "version": info, "users": users,
                   "plugins": plugins, "paths": paths},
                  open(a.output, "w"), indent=2)
        print(f"[+] saved {a.output}")


if __name__ == "__main__":
    main()