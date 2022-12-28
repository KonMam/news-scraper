import requests
from bs4 import BeautifulSoup
import sys
import json

URL = "https://www.vz.lt/visos-naujienos"

data = {}

r = requests.get(url=URL)

# soup = BeautifulSoup(r.text, 'html.parser')

html_text = open('demo.txt', 'r', encoding='utf-8')
soup = BeautifulSoup(html_text, 'html.parser')

# articles = soup.find_all(
#    "div",
#    class_="one-article"
# )

# something = ""

# for article in articles
#    something += article.get_text().strip()

filtered = soup.select_one('div.one-article div.txt-wr a')

if filtered:
    data[0] = {
        'title': str(filtered.get('title')),
        'href': str(filtered.get('href'))
    }

formatted_json = json.dumps(data, indent=4, ensure_ascii=False)

if data:
    f = open('results.json', "a", encoding='utf-8')
    f.write(formatted_json)
    f.close()
