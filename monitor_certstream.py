import requests
import certstream
from queue import Queue
import threading
from requests.adapters import HTTPAdapter
import logging
from tld import get_tld
import utils
from elasticsearch import Elasticsearch
import json
import checks

ascii = """                                         88                   
                                         88                   
                                         88                   
,adPPYYba, 8b      db      d8 ,adPPYYba, 88   ,d8  ,adPPYba,  
""     `Y8 `8b    d88b    d8' ""     `Y8 88 ,a8"  a8P_____88  
,adPPPPP88  `8b  d8'`8b  d8'  ,adPPPPP88 8888[    8PP"""""""  
88,    ,88   `8bd8'  `8bd8'   88,    ,88 88`"Yba, "8b,   ,aa  
`"8bbdP"Y8     YP      YP     `"8bbdP"Y8 88   `Y8a `"Ybbd8"' Certstream"""

with open("config.json", "r") as conf:
    config = json.load(conf)

logging.basicConfig(filename=config['log_file'],
                            filemode='a',
                            format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',
                            datefmt='%H:%M:%S',
                            level=logging.DEBUG)

logging.info("Starting...")

logger = logging.getLogger('monitor_certstream')
QUEUE_SIZE = 100
MONITOR_QUEUE = Queue(maxsize=QUEUE_SIZE)
LOCK = threading.Lock()
es = Elasticsearch()
targets = []

with open('programs.txt', 'r') as f:
    for t in f.readlines():
        targets.append(t.rstrip())

class MonitorWorker(threading.Thread):
    def __init__(self, q, *args, **kwargs):
        self.q = q
        self.session = requests.Session()
        self.session.mount("https://", HTTPAdapter(max_retries=2))

        super(MonitorWorker, self).__init__(*args, **kwargs)

    def run(self):
        while True:
            new_subdomain = self.q.get()
            try:
                exist = utils.exists(new_subdomain)
                if not exist:
                    live = checks.check_if_live(new_subdomain)
                    if isinstance(live,str):
                        wappa = checks.analyze_wappalyzer("https://" + new_subdomain)
                        wappa_string = ', '.join(wappa)
                        takeover = checks.takeover(new_subdomain)
                        utils.add(new_subdomain, live=True, cname=takeover)
                        utils.send(new_subdomain + "\n" + live + "\n " + wappa_string + "\n" + takeover)
                    else:
                        utils.add(new_subdomain, live=False, cname="")
                        utils.send(new_subdomain)

                logger.info("Domain " + new_subdomain + " has been sucessfully added")


            except Exception as e:
                logger.exception("Subdomain found but an error occured while processing: %s " % new_subdomain)
            finally:
                self.q.task_done()

def monitor(message, context):
    """certstream events callback handler"""

    all_domains = ""
    if message['message_type'] == "heartbeat":
        return

    if message["message_type"] == "certificate_update":
        all_domains = message["data"]["leaf_cert"]["all_domains"]

    for domain in set(all_domains):
        try:
            tld = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
            if tld.fld in targets and not domain.startswith("*"):
                # if not utils.exists(domain):
                    logging.info("New domain found "+ domain)
                    MONITOR_QUEUE.put(domain)

        except Exception as e:
            logger.exception("Checking domain " + domain + " failed")
            logger.exception(e)

    # t.sleep(.1)
def main():
    logging.basicConfig(format='[%(levelname)s:%(name)s] %(asctime)s - %(message)s', level=logging.INFO)
    th=config['monitor']['threads']
    for _ in range(1, th):
        thread = MonitorWorker(MONITOR_QUEUE)
        thread.setDaemon(True)
        thread.start()

    print(ascii)
    print("Checking elasticsearch...")
    # utils.check_if_online()
    print("Config:\nThreads: "+str(config['monitor']['threads'])+"\n"+"log file: " + config['log_file'])

    print("Waiting for certstream events - this could take a few minutes to queue up...")
    certstream.listen_for_events(monitor, url='wss://certstream.calidog.io/')  # this is blocking, so I added some sleep..

    print("Qutting - waiting for threads to finish up...")
    MONITOR_QUEUE.join()

if __name__ == "__main__":
    main()