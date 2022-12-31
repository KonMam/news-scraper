from main import get_response, get_articles_in_page, get_article_details, combine_article_details
import requests
from bs4 import ResultSet

URL = {
    "vz": "https://www.vz.lt/visos-naujienos?pageno=0",
    "15min": "https://www.15min.lt/naujienos",
    "delfi": "https://www.delfi.lt/archive/latest.php?query=&tod=31.12.2022&fromd=30.12.2022"
    }

def test_get_response():
    # maybe should only pass page, and URL should be local
    assert type(get_response(url=URL, page="vz")) == requests.Response
    assert type(get_response(url=URL, page="15min")) == requests.Response
    assert type(get_response(url=URL, page="delfi")) == requests.Response
    
    # when url type not in URL list
    assert type(get_response(url=URL, page="dsfai")) == IndexError


def test_get_articles_in_page():
    # Test VZ
    r = get_response(url=URL, page="vz")
    assert type(get_articles_in_page(r=r)) == ResultSet
    # Test 15min
    r = get_response(url=URL, page="15min")
    assert type(get_articles_in_page(r=r)) == ResultSet
    # Test delfi
    r = get_response(url=URL, page="delfi")
    assert type(get_articles_in_page(r=r)) == ResultSet


def test_get_article_details():
    r = get_response(url=URL, page="vz")
    articles = get_articles_in_page(r)
    data = get_article_details(article=articles[0])

    assert type(data['title']) == str
    assert type(data['href']) == str


def test_combine_article_details():
    r = get_response(url=URL, page="vz")
    articles = get_articles_in_page(r)
    data = combine_article_details(articles)

    assert type(data[0]) == dict
