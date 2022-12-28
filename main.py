import requests
from bs4 import BeautifulSoup
import json

URL = "https://www.vz.lt/visos-naujienos"

data = {}

r = requests.get(url=URL)

soup = BeautifulSoup(r.text, 'html.parser')
articles = soup.select('div.one-article div.txt-wr a')

i = 0
for article in articles:
    data[i] = {
        'title': str(article.get('title')),
        'href': str(article.get('href'))
    }
    i += 1

formatted_json = json.dumps(data, indent=4, ensure_ascii=False)

if data:
    f = open('results.json', "w", encoding='utf-8')
    f.write(formatted_json)
    f.close()
