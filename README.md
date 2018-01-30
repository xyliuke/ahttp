# ahttp
ahttp是一个学习http client的库，完成了一些基本功能。本工程需要使用XCode或者AppCode打开，使用了libuv库和openssl库
主要包括的功能有：

- 支持HTTP和HTTPS
- HTTP/HTTPS的GET和POST请求
- 支持HTTP/HTTPS请求的管理，对于一个域名和端口号的最大连接数。大于最大连接数，则强制复用TCP链路
- 请求的优先级，默认为高优先级。当设置为低优先级时，则强制复用TCP链路
- 支持HTTP/HTTPS请求超时
- 支持HTTPS的IP直连，支持SNI指定域名的证书
- 支持代理，MAC、IOS环境下自动使用代理，其他环境下需要手动配置
- 支持HTTPS的域名校验和证书检验功能。（证书检验功能目前只有MAC、IOS环境下有效）
- 支持请求的数据统计功能，即各阶段发生的时间、客户端和服务器的IP、Port
- 一个简单的状态机实现

待实现功能：
- 重构HTTP库，使用状态机来实现，并重构管理HTTP的结构
- 实现HTTP库请求失败的详细原因
- 实现Android环境下的自动使用代理功能和证书校验功能
- 完善HTTP/1.1协议
- 支持HTTP2
- 支持WebSocket
- 支持ICMP协议，检测服务器是否在线
