#Chimney3-go

这是一个科学上网项目，已经迭代到第三代，支持TCP, UDP, KCP，quic 等协议。
chimney3 将服务端和客户端都集成在一个可执行程序中
```
服务端 ./chimney3-go -s 
客户端 ./chimney3-go
```
通过上述的方式可以启动服务端和客户端


配置在setting.json 中。

在./vpncore 目录中是android ios 的编译主目录，编译为模块。例如android为aar.

相关项目chimney-android 就是用了这个aar. 


