from abc import ABC, abstractmethod

class ApiSearch(ABC):
  @abstractmethod
  def search(self, query):
    pass

  @abstractmethod  
  def extract_keys(self, content):
    pass

class GithubSearch(ApiSearch):
  def __init__(self, token):
    self.token = token

  def search(self, query):
    response = requests.get(f"https://api.github.com/search/code?q={query}", headers={"Authorization": f"token {self.token}"})
    return [item["html_url"] for item in response.json()["items"]]
  
  def extract_keys(self, content):
    return re.findall(r"[A-Za-z0-9]{32}", content)

class SearchOrchestrator:
  def __init__(self, api_search):
    self.api_search = api_search

  def run(self, query):
    for url in self.api_search.search(query):
      content = requests.get(url.replace("github.com", "raw.githubusercontent.com")).text
      keys = self.api_search.extract_keys(content)
      if keys:
        print(f"Found keys {keys} in {url}")

if __name__ == '__main__':
  token = "TOKEN"
  search = GithubSearch(token)
  orchestrator = SearchOrchestrator(search)
  orchestrator.run("my_api_key")
