import requests
from bs4 import BeautifulSoup, ResultSet, Tag
import json


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


    def _combine_article_details(self, articles: ResultSet[Tag]) -> dict[int, dict]:
        for count, article in enumerate(articles):
            article_details = self._get_article_details(article=article)
            self.data[count] = article_details
        return self.data


    def _format_data_to_json(self):
        formatted_json = json.dumps(self.data, indent=4, ensure_ascii=False)
        return formatted_json


    def _create_results_file(self, formatted_json):
        with open('results.json', "a", encoding='utf-8') as f:
            f.write(formatted_json)

    def get_news_articles_output(self, path: str, page: str):
        pass

def main():
    pass    

if __name__ == "__main__":
    main()
