# FIXTURE: vulnerable
# EXPECTED_RULES: ["MRT003"]
# EXPECTED_SEVERITY: ["HIGH"]
# DESCRIPTION: SSRF through an HTTP client held in a variable.
#   Every function below is a real SSRF. The client variable is deliberately
#   named differently each time: a name allowlist on the receiver silently
#   loses most of these, which is exactly the regression this fixture pins.

import httpx
import requests


def fetch_via_client(url: str) -> str:
    client = httpx.Client()
    return client.get(url).text


def fetch_via_session(url: str) -> str:
    session = requests.Session()
    return session.get(url).text


def fetch_via_http_client(url: str) -> str:
    http_client = httpx.Client()
    return http_client.get(url).text


def fetch_via_sess(url: str) -> str:
    sess = requests.Session()
    return sess.get(url).text


def fetch_via_single_letter(url: str) -> str:
    c = httpx.Client()
    return c.get(url).text


def fetch_via_fetcher(url: str) -> str:
    fetcher = httpx.Client()
    return fetcher.get(url).text


def post_via_web(url: str) -> str:
    web = requests.Session()
    return web.post(url, json={}).text
