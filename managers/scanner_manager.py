#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     scanner_manager.py
   Description :   扫描管理器
   Author :       sule01u
   date：          2023/10/8
"""
from tqdm import tqdm
from scanners.path_detector import PathDetector, close_sessions
from scanners.cve_scanner import CVEScanner
from scanners.fingerprint_detector import FingerprintDetector
from utils.config_loader import ConfigLoader
from utils.reporter import ReportGenerator
from utils.logging_config import configure_logger
from utils.global_thread_pool import GlobalThreadPool  # 引入全局线程池管理

logger = configure_logger(__name__)


class ScannerManager:
    def __init__(self, target_urls, mode, proxy_manager, dns_domain, max_threads, fingerprint_filter=False,
                 quiet=False, custom_headers=None):
        self.target_urls = target_urls
        self.mode = mode
        self.proxy_manager = proxy_manager
        self.dns_domain = dns_domain
        self.max_threads = max_threads
        self.quiet = quiet
        self.fingerprint_filter = fingerprint_filter
        self.custom_headers = custom_headers or {}

        # 创建Path扫描器的实例，并使用全局会话复用
        paths_config = ConfigLoader.load_config("config/path.json")
        self.path_detector = PathDetector(paths_config, self.proxy_manager, self.custom_headers)

        # 创建CVE扫描器的实例，并使用全局会话复用
        cve_config = ConfigLoader.load_config("config/cve.json") or {}
        self.cve_scanner = CVEScanner(cve_config, self.proxy_manager, self.custom_headers)

        # 指纹检测器
        self.fingerprint_detector = FingerprintDetector(self.proxy_manager, self.custom_headers)

    def _perform_fingerprint_detection(self, url):
        """指纹检测"""
        if not self.fingerprint_filter:
            return None

        is_spring = self.fingerprint_detector.is_spring_app(url)
        if not is_spring:
            self.reporter.generate(url, is_spring, [], [])
            logger.debug("Non-Spring application detected, skipping further scans", extra={"target": url})
        return is_spring

    def _perform_path_scan(self, url):
        """路径检测"""
        if self.mode not in ['all', 'path']:
            return []

        detected_paths = self.path_detector.detect(url)
        if detected_paths:
            logger.info(f"Detected {len(detected_paths)} sensitive paths", extra={"target": url})
        close_sessions(self.path_detector)  # 优化：在检测结束后关闭所有线程会话
        return detected_paths

    def _perform_cve_scan(self, url):
        """CVE检测"""
        if self.mode not in ['all', 'cve']:
            return []

        found_cves = self.cve_scanner.scan(url, self.dns_domain)
        if found_cves:
            logger.info("CVE vulnerabilities detected", extra={"target": url})
        return found_cves

    def start_scanning(self):
        """启动扫描任务"""
        try:
            # 进度条设置
            pbar = tqdm(total=len(self.target_urls), desc="Start Scanning: ", ncols=100)
            self.reporter = ReportGenerator(quiet=self.quiet, pbar=pbar)

            # 使用全局线程池执行任务，提升整体效率
            GlobalThreadPool.execute_tasks(self.scan_url, self.target_urls, pbar)

            pbar.close()
            return self.reporter.get_report_data()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            pbar.close()
            logger.error(f"Error during scanning: {e}")
            raise

    def scan_url(self, url, pbar=None):
        """单个URL扫描的具体流程"""
        logger.debug("Starting scan target", extra={"target": url})
        try:
            # 进行指纹检测
            is_spring = self._perform_fingerprint_detection(url)
            if is_spring is False:
                if pbar:
                    pbar.update(1)
                    pbar.refresh()
                return

            # 进行路径检测
            detected_paths = self._perform_path_scan(url)
            # 进行CVE检测
            found_cves = self._perform_cve_scan(url)

            # 记录检测结果
            self.reporter.generate(url, is_spring, detected_paths, found_cves)
            if pbar:
                pbar.update(1)
                pbar.refresh()
        except Exception as e:
            logger.error(f"Error processing URL: {e}", extra={"target": url})
            if pbar:
                pbar.update(1)
                pbar.refresh()