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

    # Add offset to 15min for date selection
    URL = {
        "vz": "https://www.vz.lt/visos-naujienos?pageno=",
        "15min": "https://www.15min.lt/naujienos",
        "delfi": "https://www.delfi.lt/archive/latest.php"
    }

    def __init__(self, page):
        self.page = page
        self.results = ArticleList()

    def _get_response(self, page_no: int) -> requests.Response:
        url = ""

        if self.page == 'vz':
            url = f"{self.URL[self.page]}{page_no}"

        if self.page in ['15min', 'delfi']:
            url = self.URL[self.page]

        r = requests.get(url=url)
        return r

    def _get_articles_in_page(self, page_no: int = 0) -> ResultSet[Tag] | None:
        r = self._get_response(page_no)
        soup = BeautifulSoup(r.text, 'html.parser')

        if self.page == 'vz':
            result_set = soup.select('div.one-article div.txt-wr > a')
            return result_set

        if self.page == '15min':
            result_set = soup.select('div.visual-list a.vl-img-container')
            return result_set

        if self.page == 'delfi':
            result_set = soup.select('a.CBarticleTitle')
            return result_set

    def _get_article_details(self, html_tag: Tag) -> Article | None:

        if self.page in ['vz', '15min']:
            article = Article(str(html_tag.get('title')),
                              str(html_tag.get('href')))
            return article

        if self.page in 'delfi':
            article = Article(html_tag.text,
                              str(html_tag.get('href')))
            return article

    def _append_results(self, result_set: ResultSet[Tag]):
        for html_tag in result_set:
            article = self._get_article_details(html_tag=html_tag)

            if isinstance(article, Article):
                self.results.append(article)

    def get_article_list(self, page_no: int | range | list[int] = 0
                         ) -> ArticleList:
        if self.page == 'vz':
            if not isinstance(page_no, int):
                for number in page_no:
                    result_set = self._get_articles_in_page(page_no=number)
                    if result_set:
                        self._append_results(result_set=result_set)
            else:
                result_set = self._get_articles_in_page(page_no=page_no)
                if result_set:
                    self._append_results(result_set=result_set)

        if self.page in ['15min', 'delfi']:
            result_set = self._get_articles_in_page()
            if result_set:
                self._append_results(result_set=result_set)

        return self.results
