from scraper import DelfiScraper, MinutesScraper, VZScraper


def main():

    scraper = MinutesScraper()
    results = scraper.get_results()
    results.write_to_db('../news-api/news.db')


if __name__ == "__main__":
    main()
