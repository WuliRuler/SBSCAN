#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     scanner_manager.py
   Description :   扫描管理器
   Author :       sule01u
   date：          2023/10/8
"""
from tqdm import tqdm
import time
import threading
from concurrent.futures import TimeoutError
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
                 quiet=False, custom_headers=None, scan_timeout=300):
        self.target_urls = target_urls
        self.mode = mode
        self.proxy_manager = proxy_manager
        self.dns_domain = dns_domain
        self.max_threads = max_threads
        self.quiet = quiet
        self.fingerprint_filter = fingerprint_filter
        self.custom_headers = custom_headers or {}
        self.scan_timeout = scan_timeout  # 每个URL的扫描超时时间（秒）

        # 创建Path扫描器的实例，并使用全局会话复用
        paths_config = ConfigLoader.load_config("config/path.json")
        self.path_detector = PathDetector(paths_config, self.proxy_manager, self.custom_headers)

        # 创建CVE扫描器的实例，并使用全局会话复用
        cve_config = ConfigLoader.load_config("config/cve.json") or {}
        self.cve_scanner = CVEScanner(cve_config, self.proxy_manager, self.custom_headers)

        # 指纹检测器
        self.fingerprint_detector = FingerprintDetector(self.proxy_manager, self.custom_headers)
        
        # 进度锁
        self.progress_lock = threading.Lock()
        self.total_tasks = 0
        self.completed_tasks = 0
        
        # 根据模式设置进度权重
        self._set_progress_weights(mode)
        
        # 超时控制
        self.timeout_events = {}

    def _set_progress_weights(self, mode):
        """根据扫描模式设置各阶段进度权重"""
        self.fingerprint_weight = 0.2  # 指纹检测始终占20%
        
        if mode == 'path':
            # 只扫描路径时，路径扫描占80%
            self.path_weight = 0.8
            self.cve_weight = 0
        elif mode == 'cve':
            # 只扫描CVE时，CVE扫描占80%
            self.path_weight = 0
            self.cve_weight = 0.8
        else:  # 'all' 或其他情况
            # 默认路径和CVE各占40%
            self.path_weight = 0.4
            self.cve_weight = 0.4
            
        logger.debug(f"进度权重分配 - 指纹: {self.fingerprint_weight}, 路径: {self.path_weight}, CVE: {self.cve_weight}")
        
    def _set_timeout_event(self, url):
        """设置URL超时控制事件 - 使用时间戳实现超时控制"""
        # 使用字典记录开始时间，而不是使用Event
        current_time = time.time()
        self.timeout_events[url] = current_time
        logger.debug(f"记录扫描开始时间: {url}, 时间戳: {current_time}, 超时阈值: {self.scan_timeout}秒")
        return current_time
    
    def _clear_timeout_event(self, url):
        """清除URL超时控制事件"""
        if url in self.timeout_events:
            logger.debug(f"清除超时记录: {url}")
            del self.timeout_events[url]  # 从字典中移除
    
    def _check_timeout(self, url):
        """检查URL是否超时 - 基于时间戳检查"""
        if url in self.timeout_events:
            start_time = self.timeout_events[url]
            elapsed = time.time() - start_time
            # 如果已经超过了超时时间，则返回True
            if elapsed > self.scan_timeout:
                logger.warning(f"URL已超时: {url}, 已用时: {elapsed:.2f}秒, 超过设定的 {self.scan_timeout}秒")
                return True
            # 否则定期记录已用时间并返回False
            if int(elapsed) % 10 == 0:  # 每10秒记录一次
                logger.debug(f"URL未超时: {url}, 已用时: {elapsed:.2f}秒, 剩余: {self.scan_timeout - elapsed:.2f}秒")
        return False

    def _perform_fingerprint_detection(self, url, pbar=None):
        """指纹检测"""
        if not self.fingerprint_filter:
            # 如果不启用指纹过滤，直接返回True表示允许继续扫描
            logger.debug("Fingerprint detection disabled, proceeding with scan", extra={"target": url})
            return True

        # 执行实际的指纹检测
        is_spring = self.fingerprint_detector.is_spring_app(url)
        if not is_spring:
            self.reporter.generate(url, is_spring, [], [])
            logger.debug("Non-Spring application detected, skipping further scans", extra={"target": url})
            
        self._update_progress(pbar, 0.2, f"完成指纹检测: {url}")
        return is_spring

    def _perform_path_scan(self, url, pbar=None):
        """路径检测"""
        if self.mode not in ['all', 'path']:
            return []

        # 传递路径扫描权重给扫描器
        detected_paths = self.path_detector.detect(url, pbar, self.path_weight, len(self.target_urls))
        if detected_paths:
            logger.info(f"Detected {len(detected_paths)} sensitive paths", extra={"target": url})
        close_sessions(self.path_detector)  # 优化：在检测结束后关闭所有线程会话
        
        self._update_progress(pbar, 0, f"完成路径扫描: {url}")
        return detected_paths

    def _perform_cve_scan(self, url, pbar=None):
        """CVE检测"""
        if self.mode not in ['all', 'cve']:
            return []

        # 传递CVE扫描权重给扫描器
        found_cves = self.cve_scanner.scan(url, self.dns_domain, pbar, self.cve_weight, len(self.target_urls))
        if found_cves:
            logger.info("CVE vulnerabilities detected", extra={"target": url})
            
        self._update_progress(pbar, 0, f"完成CVE扫描: {url}")
        return found_cves
        
    def _update_progress(self, pbar, increment, message=""):
        """更新进度条，increment是完成的任务比例，每个URL总计为1"""
        if pbar:
            with self.progress_lock:  # 使用锁确保线程安全
                # 提取状态信息，不显示URL
                if ":" in message:
                    parts = message.split(":", 1)
                    status_info = parts[0].strip()
                else:
                    status_info = message
                
                # 设置进度条描述，位于第二行的进度条不显示详细状态信息
                # 仅显示"扫描进度"，详细状态信息由scan_url方法决定是否更新status_bar
                pbar.set_description("扫描进度")
                
                # 只有在指纹检测阶段才更新进度值(20%)
                if "指纹检测" in message:
                    # 指纹检测按权重更新进度
                    small_increment = self.fingerprint_weight / len(self.target_urls)
                    # 检查进度是否已经达到或超过100%
                    if pbar.n + small_increment <= pbar.total:
                        pbar.update(small_increment)
                pbar.refresh()  # 强制刷新进度条显示

    def scan_url(self, url, pbar=None):
        """单个URL扫描的具体流程"""
        logger.debug(f"Starting scan target: {url}", extra={"target": url})
        start_time = time.time()
        timeout_event = None
        
        try:
            # 更新开始扫描的状态
            self._update_progress(pbar, 0, f"开始扫描: {url}")
            logger.info(f"开始扫描URL: {url}")
            
            # 尝试获取status_bar（第一行状态栏）
            status_bar = None
            if pbar and hasattr(pbar, 'pos') and pbar.pos == 1:  # 如果当前是第二行进度条
                # 查找位置0的进度条（状态栏）
                for manager in tqdm._instances:
                    if hasattr(manager, 'pos') and manager.pos == 0:
                        status_bar = manager
                        break
            
            # 如果找到状态栏，更新当前URL状态
            if status_bar:
                status_bar.set_description_str(f"正在扫描: {url}")
            
            # 设置超时控制 - 只有在实际开始扫描时才启动超时计时器
            timeout_event = self._set_timeout_event(url)
            logger.debug(f"设置超时控制器，时间: {self.scan_timeout}秒")
            
            # 给超时线程一些时间来启动
            time.sleep(0.1)
            
            # 进行指纹检测
            logger.debug(f"执行指纹检测: {url}")
            is_spring = self._perform_fingerprint_detection(url, pbar)
            logger.debug(f"指纹检测结果: {is_spring}")
            
            # 检查是否超时
            if self._check_timeout(url):
                logger.warning(f"指纹检测后检测到超时: {url}")
                raise TimeoutError(f"URL扫描超时: {url}")
                
            if is_spring is False:
                # 即使跳过也要更新进度条
                if pbar:
                    with self.progress_lock:
                        status_info = f"跳过(非Spring应用)"
                        pbar.set_description(status_info)
                        pbar.update(1)
                        pbar.refresh()
                self._clear_timeout_event(url)  # 清除超时事件
                return

            # 进行路径检测
            logger.debug(f"开始执行路径检测: {url}")
            detected_paths = self._perform_path_scan(url, pbar)
            logger.debug(f"路径检测完成: {url}, 发现 {len(detected_paths)} 个敏感路径")
            
            # 检查是否超时
            if self._check_timeout(url):
                logger.warning(f"路径检测后检测到超时: {url}")
                raise TimeoutError(f"URL扫描超时: {url}")
                
            # 进行CVE检测
            logger.debug(f"开始执行CVE检测: {url}")
            found_cves = self._perform_cve_scan(url, pbar)
            logger.debug(f"CVE检测完成: {url}, 发现 {len(found_cves)} 个CVE漏洞")
            
            # 检查是否超时
            if self._check_timeout(url):
                logger.warning(f"CVE检测后检测到超时: {url}")
                raise TimeoutError(f"URL扫描超时: {url}")

            # 记录检测结果
            self.reporter.generate(url, is_spring, detected_paths, found_cves)
            
            # 完成此URL的所有任务，确保进度到达100%
            if pbar:
                with self.progress_lock:
                    # 简化显示，如果有发现才显示数量
                    found_info = []
                    if detected_paths:
                        found_info.append(f"路径:{len(detected_paths)}")
                    if found_cves:
                        found_info.append(f"CVE:{len(found_cves)}")
                    
                    if found_info:
                        status_info = f"完成 ({', '.join(found_info)})"
                    else:
                        status_info = "完成"
                        
                    pbar.set_description(status_info)
                    
                    # 计算已完成的进度总和
                    completed_progress = self.fingerprint_weight
                    if self.mode in ['all', 'path']:
                        completed_progress += self.path_weight
                    if self.mode in ['all', 'cve']:
                        completed_progress += self.cve_weight
                    
                    # 计算剩余需要更新的进度
                    remaining = 1 - completed_progress
                    
                    # 修复：确保进度不超过100%
                    # 首先计算当前进度的百分比
                    current_progress_percentage = pbar.n / pbar.total
                    
                    # 计算还需要增加的进度增量
                    needed_increment = (1.0 / len(self.target_urls)) - current_progress_percentage
                    
                    # 直接将进度更新到当前URL对应的完成进度（不超过100%）
                    if needed_increment > 0:  # 防止负值
                        pbar.update(needed_increment)
                    
                    # 确保进度不会超过100%
                    if pbar.n > pbar.total:
                        pbar.n = pbar.total
                    
                    pbar.refresh()
            
            # 如果找到状态栏，更新完成状态
            if status_bar and url == self.target_urls[-1]:  # 如果是最后一个URL
                status_bar.set_description_str(f"扫描完成 - 最后目标: {url}")
            
            elapsed = time.time() - start_time
            logger.debug(f"URL扫描完成: {url}, 耗时: {elapsed:.2f}秒")
            self._clear_timeout_event(url)  # 清除超时事件
                    
        except TimeoutError as e:
            logger.error(f"扫描超时: {url}")
            if pbar:
                with self.progress_lock:
                    status_info = f"超时 (>{self.scan_timeout}秒)"
                    pbar.set_description(status_info)
                    pbar.update(1)  # 超时也算完成
                    pbar.refresh()
            # 确保清除超时事件
            if timeout_event:
                self._clear_timeout_event(url)
        except Exception as e:
            logger.error(f"Error processing URL: {e}", extra={"target": url})
            if pbar:
                with self.progress_lock:
                    status_info = f"错误: {str(e)[:30]}"
                    pbar.set_description(status_info)
                    pbar.update(1)  # 出错也算完成
                    pbar.refresh()
            # 确保清除超时事件
            if timeout_event:
                self._clear_timeout_event(url)

    def start_scanning(self):
        """启动扫描任务"""
        try:
            # 记录扫描开始时间
            scan_start_time = time.time()
            
            # 进度条设置，使用更清晰简洁的格式
            total_steps = len(self.target_urls)
            
            # 使用更友好的双行进度条，状态信息和进度条分开显示
            # 第一行显示当前状态，第二行显示总体进度
            status_bar = tqdm(total=0, position=0, bar_format="{desc}", leave=True)
            status_bar.set_description_str(f"准备扫描 {total_steps} 个目标...")
            
            # 第二行显示进度条
            pbar = tqdm(total=total_steps, 
                        position=1,
                        desc="扫描进度", 
                        ncols=80, 
                        mininterval=0.5,  # 增加更新间隔，减少闪烁
                        bar_format="{percentage:3.0f}% |{bar}| {n}/{total} [预计: {remaining}]",
                        leave=True)
                        
            self.reporter = ReportGenerator(quiet=self.quiet, pbar=pbar)

            # 更新状态信息
            status_bar.set_description_str(f"开始扫描 {total_steps} 个目标，模式: {self.mode}，最大线程: {self.max_threads}")
            
            # 使用全局线程池执行任务，提升整体效率
            GlobalThreadPool.execute_tasks(self.scan_url, self.target_urls, pbar)
            
            # 确保进度条达到100%
            if pbar:
                pbar.n = pbar.total
                pbar.refresh()
            
            # 完成扫描，更新状态信息
            scan_end_time = time.time()
            total_scan_time = scan_end_time - scan_start_time
            status_bar.set_description_str(f"扫描完成，总目标: {total_steps}，总耗时: {total_scan_time:.2f}秒")
            pbar.close()
            status_bar.close()
            
            # 如果有未清理的超时事件，记录详细信息
            if self.timeout_events:
                logger.warning(f"扫描结束时还有{len(self.timeout_events)}个未清理的超时事件")
                for url in list(self.timeout_events.keys()):
                    self._clear_timeout_event(url)
            
            return self.reporter.get_report_data()
        except KeyboardInterrupt:
            # 清除所有超时事件
            for url in list(self.timeout_events.keys()):
                self._clear_timeout_event(url)
            status_bar.set_description_str("用户中断扫描")
            status_bar.close()
            pbar.close()
            raise
        except Exception as e:
            # 清除所有超时事件
            for url in list(self.timeout_events.keys()):
                self._clear_timeout_event(url)
            status_bar.set_description_str(f"扫描发生错误: {str(e)}")
            status_bar.close()
            pbar.close()
            logger.error(f"Error during scanning: {e}")
            raise