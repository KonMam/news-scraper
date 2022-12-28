import unittest
from main import get_response, get_articles_in_page, get_article_details, combine_article_details
import requests
from bs4 import ResultSet

URL = "https://www.vz.lt/visos-naujienos?pageno=0"


class Tests(unittest.TestCase):

    def test_get_response(self):
        self.assertEqual(type(get_response(url=URL)), requests.Response)

    def test_get_articles_in_page(self):
        r = requests.get(url=URL)
        self.assertEqual(type(get_articles_in_page(r=r)), ResultSet)

    def test_get_article_details(self):
        r = requests.get(url=URL)
        articles = get_articles_in_page(r)
        data = get_article_details(article=articles[0])

        self.assertEqual(type(data['title']), str)
        self.assertEqual(type(data['href']), str)

    def test_combine_article_details(self):
        r = requests.get(url=URL)
        articles = get_articles_in_page(r)

        data = combine_article_details(articles)
        self.assertEqual(type(data[0]), dict)
