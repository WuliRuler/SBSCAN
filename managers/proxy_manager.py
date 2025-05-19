#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     proxy_manager.py
   Description :   代理管理模块，引入代理池和动态代理切换机制
   Author :       sule01u
   date：          2023/10/8
"""
import random
import requests
from itertools import cycle
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from utils.logging_config import configure_logger
from utils.global_thread_pool import GlobalThreadPool
import threading
import time
from concurrent.futures import as_completed
from tqdm import tqdm
from colorama import Fore

# 常量配置
TEST_URL = "https://www.baidu.com/"  # 用于测试代理可用性的 URL
DEFAULT_TIMEOUT = 5  # 代理可用性测试的默认超时时间
MAX_RETRY = 2  # 代理可用性验证的最大重试次数

# 初始化日志记录
logger = configure_logger(__name__)
requests.packages.urllib3.disable_warnings()


class ProxyManager:
    """代理管理类，支持多代理池和动态代理切换"""
    def __init__(self, proxies=None, verify_on_init=True):
        """
        初始化代理管理器
        :param proxies: 可选的代理列表或单个代理配置，格式如：
                        {"http": "http://user:password@host:port", "https": "http://user:password@host:port"}
                        或 ["http://user:password@host:port", "http://user:password@host:port"]
        :param verify_on_init: 是否在初始化时验证所有代理，默认为True
        """
        # 初始化代理池
        self.proxy_pool = self._init_proxy_pool(proxies or [])
        
        # 可用代理池
        self.available_proxies = []
        
        # 代理状态锁
        self.proxy_lock = threading.Lock()
        
        # 在初始化时验证所有代理（如果指定且有代理）
        if verify_on_init and self.proxy_pool and len(self.proxy_pool) > 0:
            self.available_proxies = self._verify_all_proxies(self.proxy_pool)
            if not self.available_proxies:
                logger.warning("No available proxies found. Continuing without proxy.")
            else:
                logger.info(f"Found {len(self.available_proxies)} available proxies out of {len(self.proxy_pool)} total.")
                self.proxy_pool = self.available_proxies  # 更新代理池，只保留可用代理
        
        # 创建代理轮询器
        self.proxy_cycle = cycle(self.proxy_pool) if self.proxy_pool else None
        self.current_proxy = None

        # 初始化第一个可用代理（仅在代理池不为空时）
        if self.proxy_pool and len(self.proxy_pool) > 0:
            self.current_proxy = self._get_next_proxy()
            
        # 最后一次代理健康检查时间
        self.last_health_check = time.time()

    def _verify_all_proxies(self, proxies, show_progress=True):
        """
        并行验证所有代理的可用性
        :param proxies: 代理列表
        :param show_progress: 是否显示进度条
        :return: 可用代理列表
        """
        if not proxies:
            return []
            
        available_proxies = []
        
        # 创建进度条（仅当代理数量大于1且允许显示进度条时）
        total_proxies = len(proxies)
        pbar = None
        if show_progress and total_proxies > 1:
            pbar = tqdm(total=total_proxies, desc=f"验证代理可用性", ncols=80)
        
        try:
            # 并行验证所有代理
            futures = {GlobalThreadPool.submit_task(self._verify_proxy_with_retry, proxy): proxy for proxy in proxies}
            
            for future in as_completed(futures):
                proxy = futures[future]
                try:
                    is_available = future.result()
                    if is_available:
                        available_proxies.append(proxy)
                        if pbar:
                            pbar.write(f"{Fore.GREEN}[+] 代理可用: {proxy}{Fore.RESET}")
                    else:
                        if pbar:
                            pbar.write(f"{Fore.RED}[-] 代理不可用: {proxy}{Fore.RESET}")
                except Exception as e:
                    logger.error(f"Error verifying proxy {proxy}: {e}")
                
                if pbar:
                    pbar.update(1)
                    
        finally:
            if pbar:
                pbar.close()
                
        return available_proxies
        
    def _verify_proxy_with_retry(self, proxy, max_retry=MAX_RETRY):
        """
        带重试的代理验证
        :param proxy: 要验证的代理
        :param max_retry: 最大重试次数
        :return: 代理是否可用
        """
        for attempt in range(max_retry):
            try:
                if self._is_proxy_working(proxy):
                    return True
                time.sleep(0.5)  # 重试前短暂等待
            except Exception as e:
                logger.debug(f"Proxy verification attempt {attempt+1} failed: {e}")
        return False

    def _init_proxy_pool(self, proxies):
        """
        初始化代理池
        :param proxies: 传入的代理列表或单个代理配置
        :return: 格式化后的代理池列表
        """
        if not proxies:
            return []

        # 如果传入的是字典格式的单一代理，转换为列表
        if isinstance(proxies, dict):
            proxies = [proxies]

        # 如果传入的是字符串格式的代理地址，转换为标准的代理格式
        formatted_proxies = []
        for proxy in proxies:
            formatted_proxy = self._format_proxy(proxy)
            if formatted_proxy:
                formatted_proxies.append(formatted_proxy)
        return formatted_proxies

    @staticmethod
    def _format_proxy(proxy):
        """
        格式化单个代理配置为 requests 可用的代理格式
        :param proxy: 代理地址字符串或字典格式
        :return: 格式化后的代理字典
        """
        if isinstance(proxy, str):
            # 如果是字符串格式的代理地址，统一转换为字典格式
            return {"http": proxy, "https": proxy}
        elif isinstance(proxy, dict):
            return proxy
        return None

    def _get_next_proxy(self):
        """
        获取下一个可用代理
        :return: 下一个可用代理的字典格式
        """
        if not self.proxy_cycle:
            return None

        with self.proxy_lock:
            for _ in range(len(self.proxy_pool)):
                proxy = next(self.proxy_cycle)
                if self._is_proxy_working(proxy):
                    logger.info(f"Switched to new working proxy: {proxy}")
                    return proxy
            logger.warning("No available proxy in the pool.")
            return None

    def _is_proxy_working(self, proxy):
        """
        检测代理是否可用
        :param proxy: 待检测的代理配置
        :return: True - 代理可用, False - 代理不可用
        """
        try:
            response = requests.get(TEST_URL, headers=DEFAULT_HEADER, proxies=proxy, timeout=DEFAULT_TIMEOUT, verify=False)
            if response.status_code == 200:
                return True
        except requests.RequestException:
            logger.debug(f"Proxy {proxy} is not available.")
        return False
        
    def check_proxy_health(self, force=False):
        """
        检查当前代理的健康状态，如果超过一定时间则重新验证
        :param force: 是否强制检查，忽略上次检查的时间
        :return: None
        """
        # 每隔30秒检查一次代理健康状态
        current_time = time.time()
        if not force and current_time - self.last_health_check < 30:
            return
            
        self.last_health_check = current_time
        
        # 如果没有当前代理，则尝试获取一个
        if not self.current_proxy:
            self.current_proxy = self._get_next_proxy()
            return
            
        # 验证当前代理是否仍然可用
        if not self._is_proxy_working(self.current_proxy):
            logger.warning(f"Current proxy {self.current_proxy} is no longer available. Switching...")
            self.current_proxy = self._get_next_proxy()

    def get_proxy(self):
        """
        获取当前可用的代理配置
        :return: 当前可用代理的字典格式，如果代理池为空，则返回 None
        """
        # 如果代理池为空，则返回 None，不做任何代理切换
        if not self.proxy_pool:
            return None

        # 检查代理健康状态
        self.check_proxy_health()
        
        # 如果当前没有代理或代理不可用，切换到下一个
        if not self.current_proxy:
            self.current_proxy = self._get_next_proxy()
            
        return self.current_proxy

    def get_random_proxy(self):
        """
        随机获取一个可用代理（从代理池中随机选择）
        :return: 随机选择的代理配置
        """
        if not self.proxy_pool:
            return None
            
        # 从可用代理池中随机选择
        with self.proxy_lock:
            # 如果可用代理池为空，则重新验证所有代理
            if not self.available_proxies:
                self.available_proxies = self._verify_all_proxies(self.proxy_pool, show_progress=False)
                
            if self.available_proxies:
                return random.choice(self.available_proxies)
            else:
                # 如果没有可用代理，则随机选择一个代理并验证
                random_proxy = random.choice(self.proxy_pool)
                if self._is_proxy_working(random_proxy):
                    self.available_proxies.append(random_proxy)
                    return random_proxy
                
        return None


if __name__ == '__main__':
    # 测试用例
    proxies = [
        "http://127.0.0.1:1080",
        "http://127.0.0.1:7890",
        {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
    ]
    proxy_manager = ProxyManager(proxies)
    print("Current Proxy:", proxy_manager.get_proxy())  # 获取当前可用代理
    print("Random Proxy:", proxy_manager.get_random_proxy())  # 获取随机代理