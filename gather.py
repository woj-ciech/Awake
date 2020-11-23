import discovery
import utils
import checks
import json

ascii = """                                         88                   
                                         88                   
                                         88                   
,adPPYYba, 8b      db      d8 ,adPPYYba, 88   ,d8  ,adPPYba,  
""     `Y8 `8b    d88b    d8' ""     `Y8 88 ,a8"  a8P_____88  
,adPPPPP88  `8b  d8'`8b  d8'  ,adPPPPP88 8888[    8PP"""""""  
88,    ,88   `8bd8'  `8bd8'   88,    ,88 88`"Yba, "8b,   ,aa  
`"8bbdP"Y8     YP      YP     `"8bbdP"Y8 88   `Y8a `"Ybbd8"' Populate"""
print(ascii)

with open ("config.json") as f:
    config = json.load(f)
    doms = config['domains_to_monitor']

for domain in doms:
    print("Checking Threatcrowd")
    threat = discovery.threatcrowd(domain)
    print("Checking CRTsh")
    crtsh = discovery.crtsh(domain)
    print("Checking Shodan")
    # shodan = discovery.check_shodan(domain)
    print("Checking Binaryedge")
    # be = discovery.check_binaryedge(domain)
    print('Checking Threatminer')
    # miner = discovery.threatminer(domain)
    print("Checking SecurityTrails")
    # sectrails = discovery.securitytrails(domain)
    subdomains = threat + crtsh
    unique_subdomains = set(subdomains)
    for subdomain in unique_subdomains:
        if not utils.exists(subdomain):
            if checks.check_if_live(subdomain):
                if checks.check_if_live(subdomain):
                    live = True
                    print(subdomain + " is live")
                    utils.add(subdomain,True, cname="")
                else:
                    print(subdomain)
                    utils.add(subdomain, False,cname="")
            else:
                utils.add(subdomain, None,cname="")
                print(subdomain)


    for subdomain in unique_subdomains:
        print(subdomain)
