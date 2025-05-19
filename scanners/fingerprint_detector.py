#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     fingerprint_detector.py
   Description :   指纹检测模块
   Author :       sule01u
   date：          2023/10/8
"""
import hashlib
import requests
from urllib.parse import urljoin
import threading
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from utils.custom_headers import DEFAULT_HEADER, TIMEOUT
from utils.logging_config import configure_logger
from utils.global_thread_pool import GlobalThreadPool  # 引入全局线程池管理

# 初始化日志记录
logger = configure_logger(__name__)


class FingerprintDetector:
    """指纹检测类"""
    SPRING_FAVICON_HASH = "0488faca4c19046b94d07c3ee83cf9d6"
    PATHS = ["/favicon.ico", "/"]

    def __init__(self, proxy_manager, custom_headers=None):
        self.proxy = proxy_manager.get_proxy()
        self.thread_local = threading.local()  # 创建线程本地存储
        self.headers = DEFAULT_HEADER.copy()
        if custom_headers:
            self.headers.update(custom_headers)

    def is_spring_app(self, url):
        """检测目标站点是否使用Spring框架"""
        logger.debug(f"开始检测目标是否为Spring应用: {url}")
        
        # 使用全局线程池并发检测所有预定义路径
        futures = {GlobalThreadPool.submit_task(self._make_request, urljoin(url, path)): path for path in self.PATHS}
        
        for future in futures:
            try:
                path = futures[future]
                logger.debug(f"检测路径: {urljoin(url, path)}")
                response = future.result()
                
                if response:
                    # 检查各种识别方法
                    is_spring_favicon = self._is_spring_by_favicon(response)
                    is_spring_content = self._is_spring_by_content(response)
                    is_spring_header = self._is_spring_by_header(response)
                    
                    logger.debug(f"指纹检测结果 - Favicon: {is_spring_favicon}, 内容: {is_spring_content}, 头信息: {is_spring_header}")
                    
                    if is_spring_favicon or is_spring_content or is_spring_header:
                        logger.info(f"目标是Spring应用", extra={"target": url})
                        return True
            except Exception as e:
                logger.error(f"Spring指纹检测发生错误: {e}", extra={"target": url})
                
        logger.info(f"目标不是Spring应用", extra={"target": url})
        return False

    @staticmethod
    def _is_spring_by_favicon(response):
        """通过favicon判断是否为Spring应用"""
        content_type = response.headers.get("Content-Type", "")
        if "image" in content_type or "octet-stream" in content_type:
            favicon_hash = hashlib.md5(response.content).hexdigest()
            return favicon_hash == FingerprintDetector.SPRING_FAVICON_HASH
        return False

    @staticmethod
    def _is_spring_by_content(response):
        """通过内容判断是否为Spring应用"""
        return 'Whitelabel Error Page' in response.text

    @staticmethod
    def _is_spring_by_header(response):
        """通过响应头判断是否为Spring应用"""
        return "X-Application-Context" in response.headers

    def _make_request(self, url):
        """向指定的URL发起请求并返回响应"""
        session = self._get_session()  # 获取线程本地的 Session 对象
        try:
            logger.debug(f"发送请求: {url}")
            response = session.get(url, headers=self.headers, proxies=self.proxy, timeout=TIMEOUT, verify=False)
            if response.content:
                logger.debug(f"请求成功: {url}, 状态码: {response.status_code}, 内容长度: {len(response.content)}")
                return response
            else:
                logger.debug(f"请求成功但无内容: {url}, 状态码: {response.status_code}")
        except requests.exceptions.ConnectTimeout as e:
            logger.debug(f"连接超时: {url}, 错误: {str(e)}", extra={"target": url})
        except requests.exceptions.ReadTimeout as e:
            logger.debug(f"读取超时: {url}, 错误: {str(e)}", extra={"target": url})
        except requests.exceptions.ConnectionError as e:
            logger.debug(f"连接错误: {url}, 错误: {str(e)}", extra={"target": url})
        except requests.RequestException as e:
            logger.debug(f"请求错误: {url}, 错误: {str(e)}", extra={"target": url})
        except Exception as e:
            logger.error(f"指纹检测中发生意外错误: {url}, 错误: {str(e)}", extra={"target": url})
        return None

    def _get_session(self):
        """获取线程本地的 Session 对象，如果不存在则创建"""
        if not hasattr(self.thread_local, 'session'):
            session = requests.Session()
            session.headers.update(self.headers)
            session.verify = False
            session.proxies = self.proxy
            session.timeout = TIMEOUT

            # 配置 HTTPAdapter，启用 keep-alive 和连接池
            adapter = HTTPAdapter(
                pool_connections=100,
                pool_maxsize=100,
                max_retries=Retry(total=3, backoff_factor=0.3)
            )
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            self.thread_local.session = session
        return self.thread_local.session

    def __del__(self):
        """析构函数：关闭所有线程本地的 Session 对象"""
        if hasattr(self, 'thread_local') and hasattr(self.thread_local, 'session'):
            self.thread_local.session.close()


if __name__ == '__main__':
    from managers.proxy_manager import ProxyManager

    # 初始化全局线程池
    GlobalThreadPool.initialize(max_workers=50)  # 新增：初始化全局线程池

    # 测试用例
    proxy_manager = ProxyManager()
    finger_d = FingerprintDetector(proxy_manager)
    print(finger_d.is_spring_app("http://localhost:9000/"))