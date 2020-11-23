import requests
import json
from pycrtsh import Crtsh
from pysecuritytrails import SecurityTrails, SecurityTrailsError

with open("config.json","r") as conf:
    config = json.load(conf)

def threatminer(domain):
    endpoint = "https://api.threatminer.org/v2/domain.php?q="+domain+"&api=True&rt=5"
    req = requests.get(endpoint)
    req_json = json.loads(req.content)

    return req_json['results']

def threatcrowd(domain):
    endpoint = "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain=" + domain
    req = requests.get(endpoint)
    req_json = json.loads(req.content)

    return req_json['subdomains']

def check_shodan(domain):
    subds = []
    try:
        endpoint = "https://api.shodan.io/dns/domain/"+domain+"?key=" + config['shodan_key']
        req = requests.get(endpoint)
        req_json = json.loads(req.content)

        for i in req_json['subdomains']:
            subds.append(i + "."+domain)

        return subds
    except:
        return []

def check_binaryedge(domain):
    headers= {"X-Key": config['binaryedge_key']}
    more = True
    subdomains = []
    page = 1
    while more:
        endpoint = "https://api.binaryedge.io/v2/query/domains/subdomain/" + domain +"?page=" + str(page)
        req = requests.get(endpoint, headers=headers)
        req_json = json.loads(req.content)
        for i in req_json['events']:
            subdomains.append(i)
        pages = req_json['total'] / 100
        page = page + 1
        if page > pages + 1:
            more = False

    return subdomains

def shodan_ssl(domain):
    more = True
    c = 1
    subd_ips = []
    try:
        while more:
            endpoint = "https://api.shodan.io/shodan/host/search?key="+config['shodan_key']+"&query=ssl:"+domain +"&page=" + str(c)
            req = requests.get(endpoint)
            req_json = json.loads(req.content)
            if len(req_json['matches']) > 0:
                c = c+1

            for i in req_json['matches']:
                print(i['ip_str'])
                subd_ips.append(i['ip_str'])

        return subd_ips

    except:
        return []

def securitytrails(domain):
    st = SecurityTrails(config['securitytrails_key'])
    subds = []
    try:
        st.ping()
        subdomains = st.domain_subdomains(domain)
        for subd in subdomains['subdomains']:
            subds.append(subd+"."+domain)
    except SecurityTrailsError:
        print('Ping failed')

    return subds

def crtsh(domain):
    c = Crtsh()
    certs = c.search(domain)
    subdomains = []
    for cert in certs:
        if '\n' in cert['name']:
            splitted_names = cert['name'].split("\n")
            for i in splitted_names:
                subdomains.append(i)
        else:
            subdomains.append(cert['name'].rstrip())


    return subdomains