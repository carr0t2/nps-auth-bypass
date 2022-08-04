# nps-auth-bypass
nps认证绕过利用工具，使用此工具可方便地访问web控制端，或者批量获取socks5和http代理

## 利用条件
默认配置 /etc/nps/conf/nps.conf:53
```
#auth_key=test
auth_crypt_key =1234567812345678
```
* `auth_key`被注释或为空
* `auth_crypt_key`为默认值 1234567812345678


## 使用方法
### web端
```
mitmdump -s main.py -p 8000 --mode reverse:http://x.x.x.x:x/
```
浏览器访问 http://127.0.0.1:8000/

### 扫描器
```shell
usage: scan.py [-h] [-u URL] [-f FILE] [-o OUTPUT] [-p PROXY] [-v VERBOSE]

Example: python scan.py -u target_url -o txt -v
         python scan.py -f file -o csv -p http://127.0.0.1:1080

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target url, such as 127.0.0.1:8080
  -f FILE, --file FILE  Targets file path, such as xxx.txt
  -o OUTPUT, --output OUTPUT
                        Output format, such as txt, csv, json, mongodb
  -p PROXY, --proxy PROXY
                        Proxy, such as http://127.0.0.1:1080
  -v VERBOSE, --verbose VERBOSE
                        Execute in verbose mode

```

## 修复方式
* 修改`auth_key`为随机值

* 修改或注释`auth_crypt_key`


## 小问题
* 后端目前好像还不支持https

## 免责声明
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

## 效果图
![](https://user-images.githubusercontent.com/62796978/182800291-29bd912b-a06d-4069-b5d5-cc6d2e6a0b5d.png)
