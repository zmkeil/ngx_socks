ngx_socks
=========

SOCKS5 proxy based on nginx

这是一个基于nginx实现的SOCKS代理服务器，目前只支持SOCKSv5,CONNECT方式。

使用很简单：
1.下载nginx或tengine包
2.修改其中的auto编译选项
3.下载本工程代码到src/socks/下
4.安装./configure --without-http --with-socks && make && make install

nginx.conf
==========
worker_process 2;
event {
  ......
}
socks {
  server {
    listen 1080;
  }
}
