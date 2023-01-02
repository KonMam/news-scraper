from scraper import NewsScraper


def main():
    vz_scraper = NewsScraper('delfi')
    results = vz_scraper.get_article_list()
    results.write_to_file('results_delfi.json')

    vz_scraper = NewsScraper('15min')
    results = vz_scraper.get_article_list()
    results.write_to_file('results_15min.json')

    vz_scraper = NewsScraper('vz')
    results = vz_scraper.get_article_list()
    results.write_to_file('results_vz.json')


if __name__ == "__main__":
    main()
