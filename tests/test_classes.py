from main import ArticleList, Article
import json


def test_article_class():
    article = Article('Title', 'https://link.com')

    assert type(article) == Article
    assert article.title == 'Title'
    assert article.href == 'https://link.com'

    f = open("./article.json")
    data = json.load(f)
    assert data["title"] == article.title
    assert data["href"] == article.href


def test_article_list():
    article_demo_list = [
        {
            "title": "Title",
            "href": "https://link.com"
        },
        {
            "title": "Title2",
            "href": "https://link2.com"
        },
    ]

    article = Article('Title', 'https://link.com')
    article2 = Article('Title2', 'https://link2.com')

    article_list = ArticleList()
    article_list.append(article)
    article_list.append(article2)

    assert article_list.get_article_by_id(0).title == 'Title'
    assert article_list.get_article_by_id(1).title == 'Title2'

    assert type(article_list.get_article_by_id(0)) == Article
    assert type(article_list) == ArticleList

    assert article_list.to_json() == json.dumps(article_demo_list, indent=4)
