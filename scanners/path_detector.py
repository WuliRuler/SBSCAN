#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     path_detector.py
   Description :   优化路径检测模块，提高路径探测速度和效率，增加 SSL 错误处理与重试机制
   Author :       sule01u
   date：          2023/10/8
"""

import time
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.custom_headers import TIMEOUT, DEFAULT_HEADER
from colorama import Fore
from utils.logging_config import configure_logger
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import threading
import ssl
from urllib3.exceptions import InsecureRequestWarning
import warnings
import hashlib

# 禁用urllib3中的不安全请求警告
warnings.simplefilter('ignore', InsecureRequestWarning)

# 初始化日志记录
logger = configure_logger(__name__)

class SSLAdapter(HTTPAdapter):
    """自定义 SSL 适配器，指定 SSL/TLS 版本"""
    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_version'] = self.ssl_version
        super().init_poolmanager(*args, **kwargs)

    def proxy_manager_for(self, *args, **kwargs):
        kwargs['ssl_version'] = self.ssl_version
        return super().proxy_manager_for(*args, **kwargs)

class PathDetector:
    """路径探测类"""
    MAX_FAILED_COUNT = 80
    MAX_SUCCESS_COUNT = 50
    CHUNK_SIZE = 1024
    SSE_MAX_SIZE = 5120  # 5KB
    MAX_RESPONSE_LENGTH = 102400  # 100KB
    PATH_THREAD_COUNT = 3  # 使用独立的3个线程池进行路径探测
    HASH_THRESHOLD = 5  # 哈希值重复次数阈值

    def __init__(self, paths, proxy_manager, custom_headers=None):
        self.paths = paths
        self.proxy = proxy_manager.get_proxy()
        self.thread_local = threading.local()  # 创建线程本地存储
        self.hash_counter = {}  # 哈希值计数器
        self.lock = threading.Lock()  # 用于线程安全的锁
        self.headers = DEFAULT_HEADER.copy()
        if custom_headers:
            self.headers.update(custom_headers)

    def detect(self, url):
        """检测指定URL的敏感路径"""
        path_failed_count = 0
        path_success_count = 0
        detected_paths = []

        # 重置哈希值计数器
        self.hash_counter = {}

        # 使用独立的线程池进行路径探测，并指定最大线程数为3
        with ThreadPoolExecutor(max_workers=self.PATH_THREAD_COUNT) as executor:
            futures = {executor.submit(self._detect_path, url, path, signature): path for path, signature in self.paths.items()}

            for future in as_completed(futures):
                path = futures[future]
                try:
                    result = future.result()
                    if result:
                        detected_paths.append(result)
                        path_success_count += 1

                    if path_success_count > self.MAX_SUCCESS_COUNT:
                        logger.info(f"Exceeded maximum success count of {self.MAX_SUCCESS_COUNT}, stopping path detection for {url}")
                        break

                except Exception as e:
                    path_failed_count += 1
                    logger.error(f"Error detecting path: {path} - {e}", extra={"target": url})

                if path_failed_count > self.MAX_FAILED_COUNT:
                    logger.info(f"Exceeded maximum failed count of {self.MAX_FAILED_COUNT}, stopping path detection for {url}")
                    break
                time.sleep(0.05)  # 防止过快请求导致目标被封禁

        return detected_paths

    def _detect_path(self, url, path, signature):
        """探测单个路径是否存在"""
        full_url = urljoin(url, path)
        response_content = self._make_request(full_url)
        if response_content and signature.lower() in response_content.lower():
            return full_url
        return None

    def _make_request(self, url):
        """发起请求并返回响应内容"""
        session = self._get_session()  # 获取线程本地的 Session 对象
        try:
            with session.get(url, stream=True, allow_redirects=False) as res:
                if "text/event-stream" in res.headers.get("Content-Type", ""):
                    # SSE 流式传输处理
                    content = b""
                    for chunk in res.iter_content(self.CHUNK_SIZE):
                        content += chunk
                        if len(content) > self.SSE_MAX_SIZE:
                            break
                    response_content = content.decode("utf-8", errors="ignore")
                elif res.status_code == 200:
                    # ANSI 控制字符实现闪动效果
                    blinking_effect = "\033[5m"
                    # 修改logger.info调用，输出红色闪动的成功消息
                    logger.info(f"{blinking_effect}{Fore.RED} [{res.status_code}] [Content-Length: {res.headers.get('Content-Length', 0)}] {Fore.CYAN}<-- [Success] {Fore.RESET}", extra={"target": url})
                    # 返回前 MAX_RESPONSE_LENGTH 的内容
                    response_content = res.text[:self.MAX_RESPONSE_LENGTH]
                else:
                    logger.info(f"[{res.status_code}] [Content-Length: {res.headers.get('Content-Length', 0)}]", extra={"target": url})
                    return None

                # 计算响应内容的哈希值
                response_hash = hashlib.md5(response_content.encode()).hexdigest()

                # 更新哈希值计数器
                with self.lock:
                    if response_hash in self.hash_counter:
                        self.hash_counter[response_hash] += 1
                    else:
                        self.hash_counter[response_hash] = 1

                    # 如果哈希值重复次数达到阈值，丢弃该路径
                    if self.hash_counter[response_hash] >= self.HASH_THRESHOLD:
                        logger.info(f"Hash {response_hash} repeated {self.HASH_THRESHOLD} times, discarding path: {url}")
                        return None

                return response_content

        except requests.exceptions.SSLError as ssl_error:
            logger.error(f"SSL error occurred for {url}: {ssl_error}", extra={"target": url})
            return self._retry_with_different_ssl_version(session, url)  # 使用不同的 SSL/TLS 版本重新连接
        except requests.RequestException as e:
            logger.debug(f"Request error: {e}", extra={"target": url})
        except Exception as e:
            logger.error(f"An unexpected error occurred during path detection: {e}", extra={"target": url})
        return None

    def _retry_with_different_ssl_version(self, session, url):
        """尝试使用不同的 SSL/TLS 版本重新发起请求"""
        ssl_versions = [ssl.PROTOCOL_TLSv1, ssl.PROTOCOL_TLSv1_1, ssl.PROTOCOL_TLSv1_2]
        for version in ssl_versions:
            try:
                # 使用不同的 SSL 版本进行重试
                ssl_adapter = SSLAdapter(ssl_version=version)
                session.mount('https://', ssl_adapter)
                with session.get(url, stream=True, allow_redirects=False) as res:
                    if res.status_code == 200:
                        logger.info(f"Successfully connected using SSL version: {version}", extra={"target": url})
                        return res.text[:self.MAX_RESPONSE_LENGTH]
            except requests.exceptions.SSLError as ssl_error:
                logger.warning(f"Retry with SSL version {version} failed: {ssl_error}", extra={"target": url})
            except Exception as e:
                logger.error(f"An unexpected error occurred during SSL retry: {e}", extra={"target": url})
        return None

    def _get_session(self):
        """获取线程本地的 Session 对象，如果不存在则创建"""
        if not hasattr(self.thread_local, 'session'):
            session = requests.Session()
            session.headers.update(self.headers)
            session.verify = False
            session.proxies = self.proxy
            session.timeout = TIMEOUT
            session.max_redirects = 3

            # 配置自定义 SSL 适配器
            ssl_adapter = SSLAdapter(ssl_version=ssl.PROTOCOL_TLSv1_2)  # 默认使用 TLSv1.2
            session.mount('https://', ssl_adapter)

            # 配置 HTTPAdapter，启用 keep-alive 和连接池
            adapter = HTTPAdapter(
                pool_connections=200,
                pool_maxsize=200,
                max_retries=Retry(total=3, backoff_factor=0.3)  # 启用重试机制
            )
            session.mount('http://', adapter)

            self.thread_local.session = session
        return self.thread_local.session

    def __del__(self):
        """析构函数：关闭所有线程本地的 Session 对象"""
        if hasattr(self.thread_local, 'session'):
            self.thread_local.session.close()


def close_sessions(detector_instance):
    """显式关闭所有线程的 Session 对象"""
    if hasattr(detector_instance.thread_local, 'session'):
        detector_instance.thread_local.session.close()


if __name__ == '__main__':
    # 测试用例
    from managers.proxy_manager import ProxyManager
    proxy_manager = ProxyManager()
    paths = {"actuator": "_links", "actuator/beans": "beans"}
    path_d = PathDetector(paths, proxy_manager)
    print(path_d.detect("http://192.168.1.13:8080/"))
    print(path_d.detect("http://192.168.1.13:8083/"))
