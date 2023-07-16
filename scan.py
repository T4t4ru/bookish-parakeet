from abc import ABC, abstractmethod
import re
import urllib
import requests
import argparse
import json
from urllib.parse import urlparse

class ApiClient(ABC):
    def __init__(self, api_name, api_pattern):
        self.api_name = api_name
        self.api_pattern = api_pattern

    @abstractmethod
    def search(self, query, page, token):
        pass

    def find_keys(self, content):
        return re.findall(self.api_pattern, content)

class GithubClient(ApiClient):
    def __init__(self, api_name, api_pattern):
        super().__init__(api_name, api_pattern)

    def search(self, query, page, token):
        raw_urls = []
        headers = {"Authorization": "token " + token}
        url = f'https://api.github.com/search/code?s=indexed&type=Code&o=desc&q={query}&page={page}'
        response = requests.get(url, headers=headers)
        response_json = json.loads(response.content)
        for item in response_json['items']:
            raw_urls.append(get_raw_file(item['html_url']))
        return raw_urls

class ApiKeySearch:
    def __init__(self, token):
        self.clients = []
        self.token = token

    def register(self, client):
        self.clients.append(client)

    def search_keys(self):
        print("--- DATA COLLECTION ---")
        for client in self.clients:
            query = f"{client.api_name}_api_key" 
            raw_urls = client.search(query, 1, self.token)
            for url in raw_urls:
                with urllib.request.urlopen(url) as resource:
                    content = resource.read().decode(resource.headers.get_content_charset())
                keys = client.find_keys(content)
                if keys:
                    print(f"Found {client.api_name.upper()} API keys {keys} in file {url}")
        print("--- Data collection completed ---")

if __name__ == '__main__':
    token = "YOUR_TOKEN_HERE"

    search = ApiKeySearch(token)

    github_client = GithubClient("github", r"[A-Za-z0-9]{32}")
    search.register(github_client)

    search.search_keys()
