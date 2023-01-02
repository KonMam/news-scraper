import requests
from bs4 import BeautifulSoup, ResultSet, Tag
import json


class Article:

    def __init__(self, title, href) -> None:
        self.title = title
        self.href = href


class ArticleList(list[Article]):

    def _to_json(self):
        return json.dumps(
            [article.__dict__ for article in self],
            indent=4,
            ensure_ascii=False
        )

    def write_to_file(self, file):
        with open(file, "a", encoding='utf-8') as f:
            f.write(self._to_json())


class NewsScraper:
    URL = {
        "vz": "https://www.vz.lt/visos-naujienos?pageno=0",
        # "15min": "https://www.15min.lt/naujienos",
        # "delfi": "https://www.delfi.lt/archive/latest.php?query=&tod=31.12.2022&fromd=30.12.2022"
    }

    def __init__(self, page):
        self.page = page
        self.results = ArticleList()

    def _get_response(self) -> requests.Response:
        r = requests.get(url=self.URL[self.page])
        return r

    def _get_articles_in_page(self) -> ResultSet[Tag]:
        r = self._get_response()
        soup = BeautifulSoup(r.text, 'html.parser')
        result_set = soup.select('div.one-article div.txt-wr > a')
        return result_set

    def _get_article_details(self, html_tag: Tag) -> Article:
        article = Article(str(html_tag.get('title')),
                          str(html_tag.get('href')))
        return article

    def get_article_list(self) -> ArticleList:
        result_set = self._get_articles_in_page()
        for html_tag in result_set:
            self.results.append(self._get_article_details(html_tag=html_tag))
        return self.results


def main():
    vz_scraper = NewsScraper('vz')
    results = vz_scraper.get_article_list()
    results.write_to_file('results.json')


if __name__ == "__main__":
    main()
