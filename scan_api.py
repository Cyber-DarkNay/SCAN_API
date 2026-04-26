# ==============================
#   WEB SECURITY AUDIT SCANNER
#   Author: Cyber DarkNay
# ==============================

BLUE = "\033[94m"
RESET = "\033[0m"

print(BLUE + r"""
  ⣿⣿⣿⣿⣿⣷⣿⣿⣿⡅⡹⢿⠆⠙⠋⠉⠻⠿⣿⣿⣿⣿⣿⣿⣮⠻⣦⡙⢷⡑⠘⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣌⠡⠌⠂⣙⠻⣛⠻⠷⠐⠈⠛⢱⣮⣷⣽⣿
⣿⣿⣿⣿⡇⢿⢹⣿⣶⠐⠁⠀⣀⣠⣤⠄⠀⠀⠈⠙⠻⣿⣿⣿⣦⣵⣌⠻⣷⢝⠦⠚⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢟⣻⣿⣊⡃⠀⣙⠿⣿⣿⣿⣎⢮⡀⢮⣽⣿⣿
⢿⣿⣿⣿⣧⡸⡎⡛⡩⠖⠀⣴⣿⣿⣿⠀⠀⠀⠀⠸⠇⠀⠙⢿⣿⣿⣿⣷⣌⢷⣑⢷⣄⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣫⠶⠛⠉⠀⠁⠀⠈⠈⠀⠠⠜⠻⣿⣆⢿⣼⣿⣿⣿
⢐⣿⣿⣿⣿⣧⢧⣧⢻⣦⢀⣹⣿⣿⣿⣇⠀⠄⠀⠀⠀⡀⠀⠈⢻⣿⣿⣿⣿⣷⣝⢦⡹⠷⡙⢿⣿⣿⣿⣿⣿⣿⣿⣿⠈⠁⠀⠀⠀⠁⠀⠀⠀⠱⣶⣄⡀⠀⠈⠛⠜⣿⣿⣿⣿
⠀⠊⢫⣿⣏⣿⡌⣼⣄⢫⡌⣿⣿⣿⣿⣿⣦⡈⠲⣄⣤⣤⡡⢀⣠⣿⣿⣿⣿⣿⣿⣷⣼⣍⢬⣦⡙⣿⣿⣿⣿⣿⣯⢁⡄⠀⡀⡀⠀⠄⢈⣠⢪⠀⣿⣿⣿⣦⠀⢉⢂⠹⡿⣿⣿
⠀⠀⠄⢹⢃⢻⣟⠙⣿⣦⠱⢻⣿⣿⣿⣿⣿⣿⣷⣬⣍⣭⣥⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⡙⢿⣼⡿⣿⣿⣿⣿⣿⣷⣄⠘⣱⢦⣤⡴⡿⢈⣼⣿⣿⣿⣇⣴⣶⣮⣅⢻⣿⡏
⠀⠀⠈⠹⣇⢡⢿⡆⠻⣿⣷⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣍⡻⣿⣟⣻⣿⣿⣿⣿⣷⣦⣥⣬⣤⣴⣾⣿⣿⣿⣿⣷⣿⣿⣿⣿⣷⡜⠃
⠀⠀⠀⢀⣘⠈⢂⠃⣧⡹⣿⣷⡄⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣮⣅⡙⢿⣟⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⡕⠂
⠀⠀⠀⠀⠀⠀⠛⢷⣜⢷⡌⠻⣿⣿⣦⣝⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣯⣹⣷⣦⣹⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠉⠃⠀


           Author: Cyber DarkNay
""" + RESET)

import requests
import re
import threading
import random
import base64
from queue import Queue
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# ================= CONFIG =================
THREADS = 15
TIMEOUT = 8

visited = set()
found = set()
q = Queue()
lock = threading.Lock()

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Linux; Android 10)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
]

extra_paths = [
    "api", "api/v1", "api/v2",
    ".env", "config",
    "js/app.js", "main.js"
]

# ================= PATTERNS =================
patterns = [
    r'api[_-]?key["\']?\s*[:=]\s*["\'](.*?)["\']',
    r'Bearer\s+[A-Za-z0-9\-\._]+',
    r'sk_live_[A-Za-z0-9]+',
    r'pk_live_[A-Za-z0-9]+',
    r'AIza[0-9A-Za-z\-_]{35}',
    r'AKIA[0-9A-Z]{16}',
    r'(?i)token["\']?\s*[:=]\s*["\'](.*?)["\']'
]

auth_patterns = [
    r'Authorization["\']?\s*[:=]\s*["\'](.*?)["\']',
    r'Bearer\s+[A-Za-z0-9\-\._]+',
    r'Basic\s+[A-Za-z0-9\-=]+'
]

cookie_keywords = ["session", "token", "auth", "jwt", "login", "sid"]

# ================= OUTPUT =================
def out(label, url, data):
    with lock:
        print("\n" + "=" * 60)
        print(f"[{label}]")
        print(f"URL : {url}")
        print(f"DATA: {data}")
        print("=" * 60)

# ================= REQUEST =================
def req(url):
    try:
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
        return r.text, dict(r.headers)
    except:
        return None, None

# ================= BASE64 DECODE =================
def decode(text):
    result = []
    for m in re.findall(r'[A-Za-z0-9+/=]{20,}', text):
        try:
            result.append(base64.b64decode(m, validate=False).decode("utf-8", errors="ignore"))
        except:
            pass
    return result

# ================= SCANNER =================
def scan(text, url, headers=None):

    data = [text] + decode(text)

    # API KEY
    for src in data:
        for p in patterns:
            for m in re.findall(p, src):
                if len(m) > 10 and m not in found:
                    found.add(m)
                    out("API KEY LEAK", url, m)

    # AUTH
    for p in auth_patterns:
        for m in re.findall(p, text):
            out("AUTH LEAK", url, m)

    # COOKIE
    if headers:
        cookie = headers.get("Set-Cookie")
        if cookie:
            out("COOKIE FOUND", url, cookie)

            for k in cookie_keywords:
                if k in cookie.lower():
                    out("SENSITIVE COOKIE", url, cookie)

# ================= WORKER =================
def worker():
    while True:
        try:
            url = q.get_nowait()
        except:
            return

        if url in visited:
            q.task_done()
            continue

        visited.add(url)

        text, headers = req(url)
        if not text:
            q.task_done()
            continue

        scan(text, url, headers)

        try:
            soup = BeautifulSoup(text, "html.parser")

            for s in soup.find_all("script"):
                if s.string:
                    scan(s.string, url)

            for s in soup.find_all("script"):
                src = s.get("src")
                if src:
                    q.put(urljoin(url, src))

            for a in soup.find_all("a"):
                h = a.get("href")
                if h and h.startswith("http"):
                    q.put(h)

        except:
            pass

        q.task_done()

# ================= START =================
def start(target):
    print(f"\n[SCAN START] {target}\n")

    q.put(target)

    for p in extra_paths:
        q.put(urljoin(target, p))

    threads = []
    for _ in range(THREADS):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for t in threads:
        t.join()

    print("\n[✓] SCAN COMPLETE")
    print(f"[✓] TOTAL UNIQUE FINDINGS: {len(found)}")

if __name__ == "__main__":
    start(input("Target URL: "))