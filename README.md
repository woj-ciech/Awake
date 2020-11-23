# Awake v0.1
## Bug bounty monitor + Elasticsearch + Telegram

Monitor domains via APIs and certstream

## Requirements

- Cerstream
- Telegram
- Wappalyzer
- tld
- Elasticsearch
- Security Trails py
- Certsh

```buildoutcfg
pip3 install -r requirements
```

Install Elasticsearch and edit config.json

## Gather
Initial scan and populate subdomains into Elasticsearch. Domains are taken from config file.
```
root@kali:~/PycharmProjects/bbm# python3 gather.py
                                         88                   
                                         88                   
                                         88                   
,adPPYYba, 8b      db      d8 ,adPPYYba, 88   ,d8  ,adPPYba,  
""     `Y8 `8b    d88b    d8' ""     `Y8 88 ,a8"  a8P_____88  
,adPPPPP88  `8b  d8'`8b  d8'  ,adPPPPP88 8888[    8PP"  
88,    ,88   `8bd8'  `8bd8'   88,    ,88 88`"Yba, "8b,   ,aa  
`"8bbdP"Y8     YP      YP     `"8bbdP"Y8 88   `Y8a `"Ybbd8"' Populate
[*] Checking Threatcrowd
[*] Checking CRTsh
[*] Checking Shodan
[*] Checking Binaryedge
[*] Checking Threatminer
[*] Checking SecurityTrails
b.pay.xiaomi.com
b.pay.xiaomi.com
www.ru.api.xmpush.global.xiaomi.com
mitools.pt.xiaomi.com
extranet.ap-southeast-1.miui-l7-bsp-jupiter.uvcsoawjky.elb.xiaomi.com
mitunes.game.xiaomi.com
www.video.market.xiaomi.com
extranet.ap-southeast-1.miui-l7-middle.g5jt2g7t5o.elb.xiaomi.com
www.fr.feedback.xmpush.global.xiaomi.com
www.storeconfig.mistat.intl.xiaomi.com
meihua.xiaomi.com
staging.mitools.pt.xiaomi.com
[...]
[*] Checking Threatcrowd
[*] Checking CRTsh
[*] Checking Shodan
[*] Checking Binaryedge
[*] Checking Threatminer
[*] Checking SecurityTrails
after-sales.address.oppo.com
sync.yun.oppo.com
wap.oppo.com
yihuan.oppo.com
www.account.oppo.com
image.oppo.com
email.oppo.com
dsfs.oppo.com
cloud.oppo.com
fuwu.oppo.com
otrans.oppo.com
itheme.exapi.oppo.com
gray-push-intl.oppo.com
autodiscover.oppo.com
partners.oppo.com
static.oppo.com
m.find.yun.oppo.com
eurwarranty.oppo.com
movie.oppo.com
drm.oppo.com
cloud-test.oppo.com
account.oppo.com
```
![](https://www.offensiveosint.io/content/images/2020/11/bb4.png)

## Monitor
Monitor subdomains via 
- Apis. Will query different APIs in specific interval
```
/root/PycharmProjects/bbm/venv/bin/python /root/PycharmProjects/bbm/monitor.py

                                         88                   
                                         88                   
                                         88                   
,adPPYYba, 8b      db      d8 ,adPPYYba, 88   ,d8  ,adPPYba,  
""     `Y8 `8b    d88b    d8' ""     `Y8 88 ,a8"  a8P_____88  
,adPPPPP88  `8b  d8'`8b  d8'  ,adPPPPP88 8888[    8PP"  
88,    ,88   `8bd8'  `8bd8'   88,    ,88 88`"Yba, "8b,   ,aa  
`"8bbdP"Y8     YP      YP     `"8bbdP"Y8 88   `Y8a `"Ybbd8"' Monitor
Monitoring following domains
 - exodus.io
Checking exodus.io
[*] Shodan
[*] Threatminer
[*] CRTsh
[*] Security Trails
[*] Binary Edge
[*] Threatcrowd
Your scan for exodus.io
Download the Best Crypto Wallet for Desktop & Mobile | Exodus
downloads.exodus.io
neo-mag-d.a.exodus.io
zilliqa-p.a.exodus.io
support-helpers.a.exodus.io
Elastic
[...]
```
- Certstream
```
/root/PycharmProjects/bbm/venv/bin/python /root/PycharmProjects/bbm/monitor_cerstream.py
                                         88                   
                                         88                   
                                         88                   
,adPPYYba, 8b      db      d8 ,adPPYYba, 88   ,d8  ,adPPYba,  
""     `Y8 `8b    d88b    d8' ""     `Y8 88 ,a8"  a8P_____88  
,adPPPPP88  `8b  d8'`8b  d8'  ,adPPPPP88 8888[    8PP"  
88,    ,88   `8bd8'  `8bd8'   88,    ,88 88`"Yba, "8b,   ,aa  
`"8bbdP"Y8     YP      YP     `"8bbdP"Y8 88   `Y8a `"Ybbd8"' Certstream
Checking elasticsearch...
Config:
Threads: 100
log file: bbm_log.log
Waiting for certstream events - this could take a few minutes to queue up...
Domain assets.nflxext.com has been sucessfully added
Domain codex.nflxext.com has been sucessfully added
Domain assets.nflxext.com has been sucessfully added
Domain codex.nflxext.com has been sucessfully added
```
## Notifications
![](https://www.offensiveosint.io/content/images/2020/11/bb5.png)
![](https://www.offensiveosint.io/content/images/2020/11/b6.png)

## Checks
CNAME and technology used on website
![](https://www.offensiveosint.io/content/images/2020/11/bb3.png)