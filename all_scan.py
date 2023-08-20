import re
import sys
import urllib.request
import requests
import json
from urllib.parse import urlparse

GITHUB_API_KEY = r"ghp_[a-zA-Z0-9]{36}"
TOKEN_DATA = "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"

API_KEY_PATTERNS = {
    "bevigil": r"[A-Za-z0-9]{64}",
    "binaryedge": r"[A-Za-z0-9]{32}",
    "bufferover": r"[A-Za-z0-9]{32}",
    "c99": r"[A-Za-z0-9]{32}",
    "censys": r"[A-Za-z0-9]{32}",
    "certspotter": r"[A-Za-z0-9]{32}",
    "chaos": r"[A-Za-z0-9]{32}",
    "chinaz": r"[A-Za-z0-9]{32}",
    "dnsdb": r"[A-Za-z0-9]{32}",
    "dnsrepo": r"[A-Za-z0-9]{32}",
    "fofa": r"[A-Za-z0-9]{32}",
    "fullhunt": r"[A-Za-z0-9]{32}",
    "github": r"[A-Za-z0-9]{32}",
    "hunter": r"[A-Za-z0-9]{32}",
    "intelx": r"[A-Za-z0-9]{32}",
    "leakix": r"[A-Za-z0-9]{32}",
    "passivetotal": r"[A-Za-z0-9]{32}",
    "quake": r"[A-Za-z0-9]{32}",
    "robtex": r"[A-Za-z0-9]{32}",
    "securitytrails": r"[A-Za-z0-9]{32}",
    "shodan": r"[A-Za-z0-9]{32}",
    "threatbook": r"[A-Za-z0-9]{32}",
    "virustotal": r"[A-Za-z0-9]{32}",
    "whoisxmlapi": r"[A-Za-z0-9]{32}",
    "zoomeye": r"[A-Za-z0-9]{32}",
    "zoomeyeapi": r"[A-Za-z0-9]{32}",
    "telegram": r"[0-9]{9,10}:[a-zA-Z0-9_-]{35}",
    "openai": r"sk-[a-zA-Z0-9]{20,50}"  # Updated pattern
}

def get_raw_file(file_url):
    """
    Convert GitHub blob URL to raw URL.
    """
    raw_host = "raw.githubusercontent.com"
    github_original_host = urlparse(file_url).hostname
    result = file_url.replace(github_original_host, raw_host)
    return result.replace('blob/', '')

def find_match(raw_url, pattern):
    """
    Find keys matching the provided pattern in the content of a raw URL.
    """
    resource = urllib.request.urlopen(raw_url)
    content = resource.read().decode(resource.headers.get_content_charset())
    keys = re.findall(pattern, content)
    return keys

def github_code_search(query, language, page):
    """
    Search GitHub code with a specific query and language using GitHub API.
    """
    raw_urls = []
    headers = {"Authorization": "token " + TOKEN_DATA}
    url = f'https://api.github.com/search/code?s=indexed&type=Code&o=desc&q={query} language:{language}&page={page}&per_page=100'
    r = requests.get(url, headers=headers)
    response_json = json.loads(r.content)
    
    for item in response_json['items']:
        raw_urls.append(get_raw_file(item['html_url']))
    
    return raw_urls

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Использование: python3 scan.py <-название_шаблона>")
        sys.exit(1)
    
    pattern_name = sys.argv[1][1:]
    if pattern_name not in API_KEY_PATTERNS:
        print(f"Шаблон '{pattern_name}' не найден в API_KEY_PATTERNS.")
        sys.exit(1)
    
    language = "python"
    
    print(f"--- СБОР ДАННЫХ ДЛЯ ШАБЛОНА: {pattern_name} ---")
    n = 1  # Укажите 'n' с номером желаемой страницы
    while True:
        urls = github_code_search(API_KEY_PATTERNS[pattern_name], language, n)
        if not urls:
            break
        for url in urls:
            pattern = r"sk-[a-zA-Z0-9]{20,50}"
            keys = find_match(url, pattern)
            if keys:
                print(f"{pattern_name} найден в {url}: {keys}")
        n += 1
    print(f"--- сбор данных для шаблона {pattern_name} завершен ---")
