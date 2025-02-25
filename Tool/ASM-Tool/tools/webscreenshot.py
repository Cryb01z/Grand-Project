import os
import re
import hashlib
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from typing import Union, List
from multiprocessing.pool import ThreadPool
import threading
import requests
import urllib.parse


class DomainProbe:
    def __init__(self, domains: List[str], output_dir="result/screenshot/", threads=5):
        self.output_dir = output_dir
        self.threads = threads
        self.domains = domains
        self.data = {}
        self.lock = threading.Lock()
        self.directories = output_dir

    @staticmethod
    def chrome() -> webdriver.Chrome:
        options = Options()
        options.add_argument('--headless')
        options.add_argument('--disable-gpu')
        options.add_argument('--log-level=3')
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        driver = webdriver.Chrome(options=options)
        driver.set_window_size(1920, 1080)
        return driver

    @staticmethod
    def info(msg: str) -> None:
        print(f"\033[94m●\033[0m {msg}")

    def run(self):
        self.info("Starting domain probes...")
        pool = ThreadPool(self.threads)
        for domain in self.domains:
            if '.js' not in domain:
                pool.apply_async(self.target, args=(domain,), callback=self.add_to_data_callback)
        pool.close()
        pool.join()
        self.info("All tasks completed.")

    def target(self, domain: str):
        status_code, response_raw = self.probe(domain)
        title, screenshot_filename = self.take_screenshot(domain)
        return domain, status_code, response_raw, title, screenshot_filename

    def probe(self, domain: str) -> tuple:
        self.info(f"Probing domain: {domain}")
        try:
            url = f"http://{domain}" if not domain.startswith("http") else domain
            response = requests.head(url, allow_redirects=True, timeout=10)
            self.info(f"Status code for domain {domain}: {response.status_code}")
            return response.status_code, self.parse_to_response_template(response)
        except Exception as e:
            self.info(f"Error while probing domain {domain}: {e}")
            return None, None

    def take_screenshot(self, domain: str) -> tuple:
        self.info(f"Taking screenshot for domain: {domain}")
        url = urllib.parse.quote_plus(domain)
        screenshot_filename = f"{url}.png"
        url = f"http://{domain}" if not domain.startswith('http') else domain
        screenshot_path = os.path.join(self.directories, screenshot_filename)
        try:
            driver = self.chrome()
            driver.get(url)
            title = driver.title
            ss = driver.get_screenshot_as_png()
            with open(screenshot_path, "wb") as ss_file:
                ss_file.write(ss)
            self.info(f"Screenshot saved at {screenshot_path}")
            return title, screenshot_filename
        except Exception as e:
            self.info(f"Screenshot failed for domain {domain}: {e}")
            return None, None
        finally:
            driver.quit()

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
        return hashlib.sha256(sanitized.encode()).hexdigest() + ".png"

    def add_to_data_callback(self, result: tuple) -> None:
        domain, status_code, response_raw, title, screenshot_filename = result
        with self.lock:
            self.data[domain] = {
                'status_code': status_code,
                'response_raw': response_raw,
                'title': title,
                'screenshot': screenshot_filename
            }

    @staticmethod
    def parse_to_response_template(response):
        return {
            'headers': dict(response.headers),
            'url': response.url,
            'history': [res.url for res in response.history]
        }
        
# if __name__ == "__main__":
#     domains_to_probe = ["192.168.100.224"]
#     probe = DomainProbe(domains=domains_to_probe)
#     probe.run()
#     print(probe.data["192.168.100.224"]['screenshot'])