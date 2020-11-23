import telegram
from datetime import datetime
from elasticsearch import Elasticsearch
import requests
import json
from bs4 import BeautifulSoup
import sys

with open("config.json","r") as conf:
    config = json.load(conf)

es = Elasticsearch()
if not es.ping():
    print("Check your Elasticsearch")
    sys.exit()
else:
    es.indices.create(index='bb', ignore=400)

def exists(query):
    req = requests.get("http://127.0.0.1:9200/bb/_search?q=subdomain:" + '\"' + query+ '\"')
    req_json = json.loads(req.content)
    if req_json['hits']['total']['value'] > 0:
        return True
    else:
        return False

def check_if_online():
    es = Elasticsearch(['http://localhost:9200/'], verify_certs=True)
    if not es.ping():
        print("Check your Elasticsearch database")
        sys.exit()
    else:
        print("Elasticsearch connection OK")

def get_last_id():
    resp = es.search(index='bb')
    last_id =  resp['hits']['total']['value']

    return last_id

def add(subdomains, live, cname):
        try:
            es.index(index='bb', body={"subdomain": subdomains, "timestamp": datetime.now(), "live":live, "cname":cname})
        except Exception as e:
                print(e)
                return False

bot = telegram.Bot(token=config['telegram']['token'])

def send(text):
    bot.send_message(chat_id=config['telegram']['channel_id'], text=text)

