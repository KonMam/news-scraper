import requests
from bs4 import BeautifulSoup, ResultSet, Tag
import json

class Article:
    
    def __init__(self, title, href) -> None:
       self.title = title
       self.href = href

    def to_dict(self):
        return Article.__dict__

    def to_json(self):
        return json.dumps(Article.__dict__, indent=4)

class ArticleList:

    def __init__(self) -> None:
        self.array: list[Article] = []
    
    def append(self, article: Article):
        self.array.append(article)

    def get_article_by_id(self, id):
        return self.array[id]

    def to_json(self):
        return json.dumps(self.array, indent=4)

class NewsScraper:

    def __init__(self):
        self.URL = {
            "vz": "https://www.vz.lt/visos-naujienos?pageno=0",
            "15min": "https://www.15min.lt/naujienos",
            "delfi": "https://www.delfi.lt/archive/latest.php?query=&tod=31.12.2022&fromd=30.12.2022"
        }
        self.data = {}


    def _get_response(self, page: str) -> requests.Response:
        r = requests.get(url=self.URL[page])
        return r


    def _get_articles_in_page(self, r: requests.Response) -> ResultSet[Tag]:
        soup = BeautifulSoup(r.text, 'html.parser')
        articles = soup.select('div.one-article div.txt-wr > a')
        return articles


    def _get_article_details(self, article: Tag) -> dict[str, str]:
        article_details = {
                'title': str(article.get('title')),
                'href': str(article.get('href'))
                }
        return article_details


    def _combine_article_details(self, articles: ResultSet[Tag], number: int):
         for count, article in enumerate(articles):
             if len(self.data) >= number:
                break
             else:
                article_details = self._get_article_details(article=article)
                self.data[count] = article_details


    def _format_data_to_json(self):
        formatted_json = json.dumps(self.data, indent=4, ensure_ascii=False)
        return formatted_json


    def _create_results_file(self, path: str):
        formatted_json = self._format_data_to_json()
        with open(path, "a", encoding='utf-8') as f:
            f.write(formatted_json)


    def _get_one_page_data(self, page: str, number: int):
        # TODO: need to check if first run or not
        r = self._get_response(page=page)
        articles = self._get_articles_in_page(r=r)
        self._combine_article_details(articles=articles, number=number)


    def get_news_articles_json(self, path: str, page: str, number: int):
        self._get_one_page_data(page=page, number=number)
        if len(self.data) < number:
            self._get_one_page_data(page=page, number=number)
            self._create_results_file(path=path)

def main():
    scraper = NewsScraper()
    scraper.get_news_articles_json(path='./results.json', page="vz", number=15)

if __name__ == "__main__":
    main()
