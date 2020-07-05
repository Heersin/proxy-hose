# Proxy

开发中
## Socks

## Http


## 参考
[0] [Socks5 RFC(it's really useful)](https://tools.ietf.org/html/rfc1928)

[1] [Socks5协议](https://jiajunhuang.com/articles/2019_06_06-socks5.md.html)

[2] [Socks5协议注解](https://jiajunhuang.com/articles/2019_06_06-socks5.md.html)

[3] [自己写的代理介绍](./)

[4] [Socks5注解](http://zhihan.me/network/2017/09/24/socks5-protocol/)

[5] [由浅入深写代理](https://zhuanlan.zhihu.com/p/28645724)

[6] [Socks5 Demo Project](github)

[7] [Web Proxy Scanner](github)

[8] [Socks Implement Doc](https://www.giac.org/paper/gsec/2326/understanding-implementing-socks-server-guide-set-socks-environment/104018)

[9] [Socks Dummy Value(This is important because I want to figure out why the RFC suggests BND.Addr is diffrent from socks server)](https://stackoverflow.com/questions/39990056/why-server-reply-of-socks5-protocol-can-use-dummy-values)

[10] [Disscuss about UDP associate in SOCKS5](https://stackoverflow.com/questions/41967217/why-does-socks5-require-to-relay-udp-over-udp)

[11] [Sending UDP over UDP isn't work?](https://stackoverflow.com/questions/18428498/sending-udp-packets-through-socks-proxy)

[12] [UDP穿透一篇不错的转载，实在没找到原文](https://blog.csdn.net/whatday/article/details/40183555)
## BIND

socks5协议约定的命令我们最常见的是CONNECT，但还有一个bind命令有点难以理解。

这个命令这多用于FTP协议，FTP协议在某些情况下要求FTP Server主动建立到FTP Client的连接，即FTP数据流。

FTP Client – SOCKS Client – SOCKS Server – FTP Server

a. FTP Client试图建立FTP控制流。SOCKS Client向SOCKS Server发送CONNECT请求，
后者响应请求，最终FTP控制流建立。

CONNECT请求包中指明FTPSERVER.ADDR/FTPSERVER.PORT。

b. FTP Client试图建立FTP数据流。SOCKS Client建立新的到SOCKS Server的TCP连
接，并在新的TCP连接上发送BIND请求。

BIND请求包中仍然指明FTPSERVER.ADDR/FTPSERVER.PORT。SOCKS Server应该据此
进行评估。

SOCKS Server收到BIND请求，创建新套接字，侦听在AddrA/PortA上，并向SOCKS
Client发送第一个BIND响应包，包中BND.ADDR/BND.PORT即AddrA/PortA。

c. SOCKS Client收到第一个BIND响应包。FTP Client通过FTP控制流向FTP Server发
送PORT命令，通知FTP Server应该主动建立到AddrA/PortA的TCP连接。

d. FTP Server收到PORT命令，主动建立到AddrA/PortA的TCP连接，假设TCP连接相关
四元组是:

AddrB，PortB，AddrA，PortA

e. SOCKS Server收到来自FTP Server的TCP连接请求，向SOCKS Client发送第二个
BIND响应包，包中BND.ADDR/BND.PORT即AddrB/PortB。然后SOCKS Server开始转
发FTP数据流。

# CONNECT
> 协议仅仅是为了交换一些必要信息设置的，在socks内交换的主要是客户端连接到relay server的所需信息，服务端需要了解目标地址的信息。

抓包观察了Clash + 一些stackoverflow的回答，socks可以视为TCP上的一层协议，所以实际通信过程有ack，当然我们写程序只需要关注应用层即可。在socks通信过程中有如下4个对象。
* Socks Client
* Socks Server
* Relay Server
* Target Server

socks代理通信的问题可以表述为，Client想要与Target Server进行通信，但碍于种种原因无法直接与其联系，故借助Socks协议完成这一过程。
1. socks client ------TCP Handshake------- socks server  普通的tcp连接建立。
2. socks client ------Auth Request-------> socks server  socks协议协商，client告知socks版本及支持的认证方式
3. socks client <-----Auth Response------- socks server  socks协议协商，server选择一种认证方式.
4. socks client ------Auth Procedure------ socks server  socks client与server的认证过程，根据方法不同而不同
5. socks client ------Socks Command------> socks server  client发送socks指令，例如connect请求建立连接，其中携带target server的地址和端口。
6. socks client <-----Socks Response------ socks server  socks返回指令结果，relay server与 target server会建立连接，response中含有relay server绑定地址和端口。
7. socks client ------Connect With-------- relay server  relay server, 接着开始传输消息。

但是实际上的过程可能比较迷惑，这是由于一些socks的实现常把socks server和relay server合二为一，以我本机上现在挂在后台的代理为例（clash），socks5监听了7891端口，http代理监听了7890端口。下面单纯关注127.0.0.1本地的socks通信过程。（ACK略去， 命令为 proxychains curl www.google.com）
0. 54652为curl对外的端口，7891为socks5的端口，proxychains是通过插桩替换的方式进行代理的。
1. 54652 ------TCP HandShake------ 7891 握手
2. 54652 ------Auth Request------> 7891 socks协议协商，仅使用noauth的方式
3. 54652 <-----Auth Response------ 7891 socks协议协商，ok接受了noauth的方式
4. 54652 ------Command Connect---> 7891 发送Connect命令，携带的Target Server为127.0.0.1:7890。这里我怀疑是proxychains把代理转向7890Http代理地址,否则其本应为google地址,这一点我通过去掉http代理再次运行该命令验证了。
5. 54652 <-----Command Response--- 7891 响应ok，携带的绑定地址为127.0.0.1:7891, 告知客户端其向该地址发送后续请求即可。这里是因为这个socks server同时也作为relay server处理后续转发。
6. 54652 ------Http Connection---> 7891 根据响应包内的地址，客户端向该地址发送http连接请求。
7. 54652 <-----[ACK]/[PSH,ACK]---- 7891 连接ok
8. 54652 ------GET request-------> 7891 发出GET请求
9. 54652 <-----[ACK]/[PSH,ACK]---- 7891 响应结果，后续也都是响应以及最终断开连接了。

可以看到，socks5协议到第5步就终止了，后续的任务转交给relay server完成。之所以抓包看整个过程会比较迷惑，socks server与relay server在同一个程序内（clash）实现，且链式代理中加了一个http proxy<br>
总而言之，socks5协议控制到此结束了，但还是可以看看外部工作，毕竟我们刚才只关注socks client与socks server。上文说到，socks客户端的target server被设置为7890, 意味着relay server的转发目的地是本地7890号端口。接下来的这些步骤发生在6-7之间。clash打开了一个新的端口38942（无特殊含义）来完成http代理的工作，有关target server的信息在clash内部传递，如果socks server与relay server的实现是分离的并放在两个地址，那么应该还需要建立额外连接或者其他什么方式传递该信息。
1. 38942 ------TCP Handshake------ 7890 握手
2. 38942 ------HTTP Connect------> 7890 请求HTTP连接
3. 38942 <-----200 Established---- 7890 告知连接成功

连接建立的信息传递应该也是clash内部完成的，表现在数据包上就是7891随后得知连接建立成功，进行上面的第7步（发了个数据包告知socks client）。接着后面就是客户端（54652）发一个GET请求，对应的38942也向7890请求。

# UDP
关于clash的udp转发讨论https://github.com/Dreamacro/clash/issues/225


## 又一个参考
讲struct pack技术的
1. http://www.catb.org/esr/structure-packing/
2. https://blog.shengbin.me/posts/gcc-attribute-aligned-and-packed
