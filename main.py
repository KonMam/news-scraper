import requests
from bs4 import BeautifulSoup, ResultSet, Tag
import json

class Article:
    
    def __init__(self, title, href) -> None:
       self.title = title
       self.href = href


class ArticleList:

    def __init__(self) -> None:
        self.array: list[Article] = []
    
    def append(self, article: Article):
        self.array.append(article)

    def get_article_by_id(self, id):
        return self.array[id]

    def to_json(self):
        return json.dumps([article.__dict__ for article in self.array], indent=4)

    def write_to_file(self, file):
        with open(file, "a", encoding='utf-8') as f:
            f.write(self.to_json())


class NewsScraper:

    def __init__(self):
        self.URL = {
            "vz": "https://www.vz.lt/visos-naujienos?pageno=0",
            "15min": "https://www.15min.lt/naujienos",
            "delfi": "https://www.delfi.lt/archive/latest.php?query=&tod=31.12.2022&fromd=30.12.2022"
        }
        # self.page = page


    def _get_response(self, page: str) -> requests.Response:
        r = requests.get(url=self.URL[page])
        return r


    def _get_articles_in_page(self, r: requests.Response) -> ResultSet[Tag]:
        soup = BeautifulSoup(r.text, 'html.parser')
        result_set = soup.select('div.one-article div.txt-wr > a')
        return result_set


    def _get_article_details(self, html_tag: Tag) -> Article:
        article = Article(str(html_tag.get('title')),str(html_tag.get('href')))
        return article


    def get_article_list(self, result_set: ResultSet[Tag]) -> ArticleList:
        article_list = ArticleList()
        for html_tag in result_set:
            article_list.append(self._get_article_details(html_tag=html_tag))

        return article_list


def main():
    # vz_scraper = NewsScraper('vz')
    # articles = vz_scraper.get_article_list()
    # articles.write_to_file('results.json')
    pass

if __name__ == "__main__":
    main()
