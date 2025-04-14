#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     cve_scanner.py
   Description :   CVE检测模块
   Author :       sule01u
   date：          2023/10/8
"""
import threading
from utils.logging_config import configure_logger
from utils.global_thread_pool import GlobalThreadPool
from requests import Session, RequestException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.custom_headers import DEFAULT_HEADER

# 初始化日志记录
logger = configure_logger(__name__)


class CVEScanner:
    """CVE 漏洞扫描器类"""

    def __init__(self, cve_data, proxy_manager, custom_headers=None):
        """
        初始化 CVE 漏洞扫描器
        :param cve_data: 从配置文件中加载的 CVE 漏洞信息
        :param proxy_manager: 代理管理器实例
        :param custom_headers: 自定义请求头
        """
        self.cve_data = cve_data
        self.proxy = proxy_manager.get_proxy() if proxy_manager else None
        self.thread_local = threading.local()  # 创建线程本地存储
        self.headers = DEFAULT_HEADER.copy()
        if custom_headers:
            self.headers.update(custom_headers)
        self._initialize_session()  # 初始化线程本地的 Session 对象

    def _initialize_session(self):
        """初始化线程本地的 Session 对象，进行会话复用"""
        if not hasattr(self.thread_local, 'session'):
            session = Session()
            session.headers.update(self.headers)
            session.proxies = self.proxy
            session.verify = False

            # 配置 HTTPAdapter，启用 keep-alive 和连接池，设置最大重试次数
            adapter = HTTPAdapter(
                pool_connections=100,
                pool_maxsize=100,
                max_retries=Retry(total=3, backoff_factor=0.3)
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)
            self.thread_local.session = session

    def _get_session(self):
        """获取线程本地的 Session 对象，如果不存在则初始化"""
        if not hasattr(self.thread_local, 'session'):
            self._initialize_session()
        return self.thread_local.session

    def _scan_cve(self, cve_key, url, dns_domain, proxy):
        """
        对单个 CVE 进行扫描
        :param cve_key: CVE 编号
        :param url: 目标 URL
        :param dns_domain: DNS 日志域名
        :param proxy: 代理配置
        :return: 漏洞扫描结果，如果发现漏洞，返回详细信息；否则返回 None
        """
        module_name = f"scanners.cve_scanners.{cve_key}"
        try:
            cve_module = __import__(module_name, fromlist=["check"])
            is_vulnerable, details = cve_module.check(url, dns_domain, proxy, session=self._get_session())
            if is_vulnerable:
                logger.info(f"[VULNERABLE] {cve_key} detected on {url}")
                return details
        except ImportError:
            logger.error(f"No CVE scanning module found for {cve_key}", extra={"target": url})
        except Exception as e:
            logger.error(f"Error during scanning for {cve_key}. Error: {e}", extra={"target": url})
        return None

    def scan(self, url, dns_domain):
        """
        扫描指定的 URL 以寻找所有可能的 CVE 漏洞
        :param url: 目标 URL
        :param dns_domain: DNS 日志域名
        :return: 找到的所有 CVE 漏洞详细信息列表
        """
        found_cves = []

        # 使用全局线程池并行扫描所有 CVE 漏洞
        futures = {GlobalThreadPool.submit_task(self._scan_cve, cve_key, url, dns_domain, self.proxy): cve_key for
                   cve_key, cve_value in self.cve_data.items() if cve_value.get("is_poc") == "true"}

        for future in futures:
            try:
                cve_details = future.result()
                if cve_details:
                    found_cves.append(cve_details)
            except Exception as e:
                logger.error(f"Error processing CVE: {futures[future]}. Error: {e}", extra={"target": url})

        if found_cves:
            logger.info(f"Found {len(found_cves)} CVEs on {url}")
        else:
            logger.info(f"No CVEs found on {url}")

        return found_cves


if __name__ == '__main__':
    # 测试用例
    from utils.config_loader import ConfigLoader
    from managers.proxy_manager import ProxyManager

    GlobalThreadPool.initialize(max_workers=50)  # 新增：初始化全局线程池

    # 初始化代理管理器（可选）
    proxy_manager = ProxyManager()

    # 加载 CVE 配置数据
    cve_config = ConfigLoader.load_config("../config/cve.json") or {}

    # 初始化 CVE 漏洞扫描器
    cve_scanner = CVEScanner(cve_config, proxy_manager)

    # 执行扫描测试
    print(cve_scanner.scan("http://example.com", "dnslog.cn"))