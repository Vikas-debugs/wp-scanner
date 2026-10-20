# wp-scanner

A Python-based WordPress vulnerability scanner. Built for speed, stealth, and deep enumeration.

## Features
- **WAF / Fallback Detection** — Avoids false positives from catch-all 200 OK pages.
- **Fingerprinting** — Extracts core version via readme, query strings, and static assets.
- **User Enumeration** — Uses REST API, author redirects, and sitemaps.
- **Plugin/Theme Enum** — Extracts versions from readme.txt files.
- **Sensitive Path Fuzzing** — Checks for backups, logs, .env, .git, etc.
- **Targeted Exploits** — Includes built-in payloads for known vulnerable plugins.

## Requirements
```bash
pip install requests