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
from tqdm import tqdm

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
        # 用于进度跟踪
        self.progress_lock = threading.Lock()

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

    def _scan_cve(self, cve_key, url, dns_domain, proxy, parent_pbar=None, cve_count=0, total_cves=0):
        """
        对单个 CVE 进行扫描
        :param cve_key: CVE 编号
        :param url: 目标 URL
        :param dns_domain: DNS 日志域名
        :param proxy: 代理配置
        :param parent_pbar: 父进度条
        :param cve_count: 当前CVE计数
        :param total_cves: 总CVE数量
        :return: 漏洞扫描结果，如果发现漏洞，返回详细信息；否则返回 None
        """
        module_name = f"scanners.cve_scanners.{cve_key}"
        try:
            # 更新进度条描述，只显示CVE编号而不显示URL
            if parent_pbar:
                with self.progress_lock:
                    status_info = f"CVE扫描 {cve_key}"
                    parent_pbar.set_description(status_info)
                    parent_pbar.refresh()
                    
            # 尝试导入CVE模块
            try:
                cve_module = __import__(module_name, fromlist=["check"])
            except ImportError:
                logger.error(f"未找到CVE扫描模块: {cve_key}", extra={"target": url})
                return None
                
            # 设置CVE扫描超时
            try:
                # 使用会话级别的超时控制
                session = self._get_session()
                
                # 设置CVE扫描超时时间（10秒）- 传递给check函数而不是设置在session上
                cve_timeout = 10
                
                # 执行CVE检测
                is_vulnerable, details = cve_module.check(url, dns_domain, proxy, session=session, timeout=cve_timeout)
                
                if is_vulnerable:
                    logger.info(f"[发现漏洞] {cve_key} 在 {url}", extra={"target": url})
                    return details
                    
            except Exception as e:
                logger.error(f"执行CVE {cve_key} 扫描时出错: {e}", extra={"target": url})
                
        except Exception as e:
            logger.error(f"Error during scanning for {cve_key}. Error: {e}", extra={"target": url})
            
        return None

    def scan(self, url, dns_domain, parent_pbar=None, cve_weight=0.4, total_urls=1):
        """
        扫描指定的 URL 以寻找所有可能的 CVE 漏洞
        :param url: 目标 URL
        :param dns_domain: DNS 日志域名
        :param parent_pbar: 父进度条
        :param cve_weight: CVE扫描在总进度中的权重(0-1)
        :param total_urls: 总URL数量，用于计算每个URL的进度增量
        :return: 找到的所有 CVE 漏洞详细信息列表
        """
        found_cves = []
        
        # 获取需要扫描的CVE列表
        active_cves = {cve_key: cve_value for cve_key, cve_value in self.cve_data.items() 
                       if cve_value.get("is_poc") == "true"}
        total_cves = len(active_cves)
        
        if total_cves == 0:
            logger.info(f"No CVEs configured for scanning on {url}")
            return found_cves
            
        # 初始化进度追踪
        if parent_pbar:
            with self.progress_lock:
                status_info = f"CVE扫描 (0/{total_cves})"
                parent_pbar.set_description(status_info)
                parent_pbar.refresh()

        # 跟踪已完成的CVE数量
        completed_cves = 0

        # 使用全局线程池并行扫描所有 CVE 漏洞
        futures = {GlobalThreadPool.submit_task(self._scan_cve, cve_key, url, dns_domain, self.proxy, 
                                               parent_pbar, i+1, total_cves): cve_key 
                  for i, (cve_key, cve_value) in enumerate(active_cves.items())}

        # 计算每个CVE完成对应的进度增量
        # CVE扫描总共占cve_weight的进度，平均分配给每个CVE
        if total_cves > 0 and parent_pbar:
            cve_increment = (cve_weight / total_urls) / total_cves
        else:
            cve_increment = 0

        for future in futures:
            try:
                cve_details = future.result()
                if cve_details:
                    found_cves.append(cve_details)
                
                # 更新完成计数和进度条
                with self.progress_lock:
                    completed_cves += 1
                    # 更新主进度条
                    if parent_pbar:
                        # 简化状态信息，只显示完成数量和总数
                        status_info = f"CVE扫描 ({completed_cves}/{total_cves})"
                        parent_pbar.set_description(status_info)
                        # 直接更新进度值
                        # 检查进度是否已经达到或超过100%
                        if parent_pbar.n + cve_increment <= parent_pbar.total:
                            parent_pbar.update(cve_increment)
                        parent_pbar.refresh()
                        
            except Exception as e:
                logger.error(f"Error processing CVE: {futures[future]}. Error: {e}", extra={"target": url})
                with self.progress_lock:
                    completed_cves += 1
                    # 错误也更新进度
                    if parent_pbar:
                        # 检查进度是否已经达到或超过100%
                        if parent_pbar.n + cve_increment <= parent_pbar.total:
                            parent_pbar.update(cve_increment)
                        parent_pbar.refresh()

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