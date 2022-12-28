import requests
from bs4 import BeautifulSoup
import json

URL = "https://www.vz.lt/visos-naujienos?pageno="
data = {}


def get_articles(page_no):
    page_url = URL + str(page_no)
    r = requests.get(url=page_url)
    soup = BeautifulSoup(r.text, 'html.parser')
    articles = soup.select('div.one-article div.txt-wr > a')
    return articles


def create_article_dictionary(articles):
    try:
        i = int(list(data)[-1])
    except IndexError:
        i = 0

    for article in articles:
        data[i] = {
            'title': str(article.get('title')),
            'href': str(article.get('href'))
        }
        i += 1


def format_data_to_json(data):
    formatted_json = json.dumps(data, indent=4, ensure_ascii=False)
    return formatted_json


def create_results_file(formatted_json):
    if data:
        f = open('results.json', "a", encoding='utf-8')
        f.write(formatted_json)
        f.close()


def main():
    i = 0
    while i < 10:
        articles = get_articles(page_no=i)
        create_article_dictionary(articles=articles)
        i += 1

    formatted_json = format_data_to_json(data)
    create_results_file(formatted_json=formatted_json)


if __name__ == "__main__":
    main()
