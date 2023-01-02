import requests
from bs4 import BeautifulSoup

r = requests.get(url="https://www.15min.lt/naujienos")

soup = BeautifulSoup(r.text, 'html.parser')

result_set = soup.select('div.visual-list a.vl-img-container')

with open('15min.txt', "a", encoding='utf-8') as f:
    f.write(str(result_set))
