import requests
import tldextract
from urllib.parse import urlparse

def is_phishing_link(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    known_phishing_domains = ["example.com", "phishing.net"]
    if domain in known_phishing_domains:
        return True
    suspicious_patterns = ["login", "signin", "account", "verify"]
    if any(pattern in url for pattern in suspicious_patterns):
        return True
    shortened_domains = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    if any(short_domain in domain for short_domain in shortened_domains):
        return True
    parsed_url = urlparse(url)
    if parsed_url.port and parsed_url.port not in [80, 443]:
        return True
    if parsed_url.scheme == "http":
        return True

    return False

def check_url(url):
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            if is_phishing_link(url):
                return f"Potential phishing link detected: {url}"
            else:
                return f"The URL is safe: {url}"
        else:
            return f"The URL is not accessible: {url}"
    except requests.RequestException as e:
        return f"Error checking the URL: {e}"

if __name__ == "__main__":
    urls_to_check = [
        "https://example.com/login",
        "http://phishing.net/signin",
        "https://secure.bank.com",
        "http://short.url/12345"
    ]

    for url in urls_to_check:
        result = check_url(url)
        print(result)
        
        