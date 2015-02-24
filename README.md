ngx_socks


SOCKS5 proxy based on nginx

这是一个基于nginx实现的SOCKS代理服务器，目前只支持SOCKSv5,CONNECT方式。


1.下载nginx或tengine包

2.安装./configure --add-module=/path/to/ngx_socks/ && make && make install



nginx.conf


worker_process 2;

socks {

  server {
    listen 1080;
  }
}
