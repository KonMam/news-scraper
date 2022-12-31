from main import NewsScraper
import requests
from bs4 import ResultSet

scraper = NewsScraper()

def test_get_response():
    # maybe should only pass page, and URL should be local
    assert type(scraper._get_response(page="vz")) == requests.Response
    assert type(scraper._get_response(page="15min")) == requests.Response
    assert type(scraper._get_response(page="delfi")) == requests.Response
    
    # when url type not in URL list
    assert type(scraper._get_response(page="dsfai")) == IndexError


def test_get_articles_in_page():
    # Test VZ
    r = scraper._get_response(page="vz")
    assert type(scraper._get_articles_in_page(r=r)) == ResultSet
    # Test 15min
    r = scraper._get_response(page="15min")
    assert type(scraper._get_articles_in_page(r=r)) == ResultSet
    # Test delfi
    r = scraper._get_response(page="delfi")
    assert type(scraper._get_articles_in_page(r=r)) == ResultSet


def test_get_article_details():
    r = scraper._get_response(page="vz")
    articles =scraper._get_articles_in_page(r)
    data =scraper._get_article_details(article=articles[0])

    assert type(data['title']) == str
    assert type(data['href']) == str


def test_get_news_articles_json():
    scraper = NewsScraper()
    scraper.get_news_articles_json(path='./results.json', page='vz', number=1)

    assert len(scraper.data) == 1
    assert len(scraper.data[0]) == 2
    assert scraper.data.keys() == ['title', 'href']

