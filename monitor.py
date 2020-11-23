import discovery
import utils
import schedule
import time
import json
import checks

ascii = """                                         88                   
                                         88                   
                                         88                   
,adPPYYba, 8b      db      d8 ,adPPYYba, 88   ,d8  ,adPPYba,  
""     `Y8 `8b    d88b    d8' ""     `Y8 88 ,a8"  a8P_____88  
,adPPPPP88  `8b  d8'`8b  d8'  ,adPPPPP88 8888[    8PP"""""""  
88,    ,88   `8bd8'  `8bd8'   88,    ,88 88`"Yba, "8b,   ,aa  
`"8bbdP"Y8     YP      YP     `"8bbdP"Y8 88   `Y8a `"Ybbd8"' Monitor"""
print(ascii)

with open ("config.json") as f:
    config = json.load(f)
    doms = config['domains_to_monitor']

print("Monitoring following domains")
for i in doms:
    print(" - " + i)

def monitoring():
    for i in doms:
        print("Checking " + i)
        print("[*] Shodan")
        subdomains_shodan = discovery.check_shodan(i)
        new_subdomains_shodan = check_and_add(subdomains_shodan)
        print("[*] Threatminer")
        subdomains_threatminer = discovery.threatminer(i)
        new_subdomains_threatminer = check_and_add(subdomains_threatminer)
        print("[*] CRTsh")
        subdomains_crtsh = discovery.crtsh(i)
        new_subdomains_crtsh = check_and_add(subdomains_crtsh)
        print("[*] Security Trails")
        subdomains_securitytrails = discovery.securitytrails(i)
        new_subdomains_securitytrails = check_and_add(subdomains_securitytrails)
        print("[*] Binary Edge")
        subdomains_check_binaryedge = discovery.check_binaryedge(i)
        new_subdomains_check_binaryedge = check_and_add(subdomains_check_binaryedge)
        print("[*] Threatcrowd")
        subdomains_threatcrowd = discovery.threatcrowd(i)

        new_subdomains_threatcrowd = check_and_add(subdomains_threatcrowd)
        new_subdomains = {**new_subdomains_threatminer, **new_subdomains_threatcrowd, **new_subdomains_shodan, **new_subdomains_crtsh,
                          **new_subdomains_securitytrails, **new_subdomains_check_binaryedge}
        text = "Your scan for " + i + "\n"
        print(new_subdomains)
        for subdomain in new_subdomains:
            if len(new_subdomains[subdomain]['title']) > 0:
                text = text + new_subdomains[subdomain]['title'] + "\n" + new_subdomains[subdomain]['subdomain'] + "\n"
            else:
                text = text + new_subdomains[subdomain]['subdomain'] + "\n"

        if text == "Your scan for " + i + "\n":
            text = text + "\n" + "Nothing was found"

        try:
            utils.send(text)
        except:
            print("Something went wrong with sending message")


def check_and_add(subdomains):
    new_subdomains = {}
    for c,j in enumerate(subdomains):
        if not utils.exists(j):
            live = checks.check_if_live(j)
            if live:
                utils.add(j, live=True, cname="")
                new_subdomains[c] = {"subdomain":j,"title":live}
            else:
                utils.add(j, live=False, cname="")
                new_subdomains[c] = {"subdomain":j,"title":""}


    return new_subdomains

while True:
    monitoring()
    schedule.run_pending()
    print("Sleeping...")
    time.sleep(3600 * 24)
