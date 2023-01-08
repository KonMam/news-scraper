from scraper import DelfiScraper, MinutesScraper, VZScraper


def main():

    scraper = MinutesScraper()
    results = scraper.get_results()
    results.write('minutes_results.json')


if __name__ == "__main__":
    main()
