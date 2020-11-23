import dns.resolver
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
from Wappalyzer import Wappalyzer, WebPage
from bs4 import BeautifulSoup
wappalyzer = Wappalyzer.latest()

def analyze_wappalyzer(domain):
    webpage = WebPage.new_from_url(domain)
    an = wappalyzer.analyze(webpage)
    return an


def check_if_live(domain):
    try:
        req = requests.get("https://" + domain, timeout=3)
        if req.status_code == 200:
            soup = BeautifulSoup(req.content)
            title = ""

            for k in soup.find_all('title', limit=1):
                title = (k.contents[0])

            return title
        else:
            return False
    except:
        return False

def takeover(domain):
    cname = ""
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            cname = rdata.target.to_text()[:-1]

        return cname
    except Exception as e:
        return ""

