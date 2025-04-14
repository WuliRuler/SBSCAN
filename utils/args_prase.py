#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     args_prase.py
   Description :   参数解析模块，负责代理解析、URL验证、配置管理
   Author :       sule01u
   date：          2023/10/9
"""
import click
from typing import List, Dict, Optional, Union
from utils.format_utils import FormatterUtils
from utils.logging_config import configure_logger
from utils.global_thread_pool import GlobalThreadPool
from utils.custom_headers import DEFAULT_HEADER
import os

# 初始化日志记录
logger = configure_logger(__name__)


class ArgumentParser:
    def __init__(self, url: Optional[str], file: Optional[str], proxy: Optional[str], header: Optional[str], threads: int):
        self.url = url
        self.file = file
        self.proxy = proxy
        self.header = header
        self.threads = threads
        self.format_util = FormatterUtils()

        # 初始化全局线程池（用于并行处理 URL 和代理验证）
        GlobalThreadPool.initialize(max_workers=self.threads)

    @staticmethod
    def raise_value_error(message: str) -> None:
        """抛出值错误并记录日志"""
        logger.error(message)
        raise ValueError(message)

    def validate_url_file(self) -> None:
        """
        验证URL和文件参数是否有效。
        现在支持同时指定 `--url` 和 `--file`，并合并处理。
        """
        if not self.url and not self.file:
            self.raise_value_error("No URL or file provided. Usage: python3 sbscan.py -h/--help")

    def parse_headers(self) -> Dict[str, str]:
        """
        解析自定义请求头
        :return: 合并后的请求头字典
        """
        headers = DEFAULT_HEADER.copy()
        
        if not self.header:
            return headers
            
        try:
            # 分割多个请求头
            custom_headers = self.header.split(',')
            for header in custom_headers:
                if ':' not in header:
                    logger.warning(f"Invalid header format: {header}, skipping...")
                    continue
                    
                name, value = header.split(':', 1)
                name = name.strip()
                value = value.strip()
                
                if name and value:
                    headers[name] = value
                else:
                    logger.warning(f"Empty header name or value: {header}, skipping...")
                    
            return headers
        except Exception as e:
            logger.error(f"Error parsing headers: {e}")
            return headers

    def get_formatted_proxy(self) -> List[Dict[str, str]]:
        """
        获取格式化后的代理信息，支持多代理配置
        :return: 代理配置列表（多个代理配置）
        """
        if not self.proxy:
            logger.debug("Unspecified proxy")
            return []

        # 如果是文件格式的代理配置，读取文件内容
        if os.path.isfile(self.proxy):
            logger.info(f"Loading proxy list from file: {self.proxy}")
            return self._load_proxies_from_file(self.proxy)

        # 如果是逗号分隔的代理列表，分割为多个代理
        if "," in self.proxy:
            logger.info(f"Loading proxy list from comma-separated values: {self.proxy}")
            proxy_list = self.proxy.split(",")
            return [self.format_util.format_proxy(proxy.strip()) for proxy in proxy_list if proxy.strip()]

        # 单个代理配置，转换为列表
        formatted_proxy = self.format_util.format_proxy(self.proxy)
        if formatted_proxy:
            return [formatted_proxy]
        else:
            self.raise_value_error("Invalid Proxy provided. Exiting...")

    def _load_proxies_from_file(self, file_path: str) -> List[Dict[str, str]]:
        """
        从文件中加载代理配置，并格式化
        :param file_path: 代理文件路径
        :return: 格式化后的代理配置列表
        """
        proxies = []
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    proxy = line.strip()
                    if proxy:
                        formatted_proxy = self.format_util.format_proxy(proxy)
                        if formatted_proxy:
                            proxies.append(formatted_proxy)
            return proxies
        except Exception as e:
            logger.error(f"Failed to read proxy file: {file_path}. Error: {e}")
            raise ValueError(f"Failed to read proxy file: {file_path}. Error: {e}")

    @staticmethod
    def extract_urls_from_file(file_path: str) -> List[str]:
        """从文件中提取URLs"""
        try:
            with open(file_path, 'r') as file:
                return [line.strip() for line in file if line.strip()]
        except Exception as e:
            logger.error(f"Failed to read URL file: {file_path}. Error: {e}")
            raise ValueError(f"Failed to read URL file: {file_path}. Error: {e}")

    def validate_and_format_urls(self, raw_urls: List[str]) -> List[str]:
        """验证并格式化一系列URLs"""
        valid_urls = []
        invalid_urls = []

        # 使用全局线程池并行验证 URL
        futures = {GlobalThreadPool.submit_task(self.format_util.format_url, url): url for url in raw_urls}
        for future in futures:
            try:
                formatted_url = future.result()
                if formatted_url:
                    valid_urls.append(formatted_url)
                else:
                    invalid_urls.append(futures[future])
            except Exception as e:
                logger.error(f"Failed to format URL: {futures[future]}. Error: {e}")
                invalid_urls.append(futures[future])

        # 记录并打印无效的URL
        if invalid_urls:
            logger.warning(f"Invalid URLs detected: {invalid_urls}")
            click.secho("[-] 以下URLs无效[The following URLs are in invalid format]:", fg='yellow')
            for invalid_url in invalid_urls:
                click.secho(invalid_url, fg='yellow')

        if not valid_urls:
            logger.error("No valid URLs provided to scan. Exiting...")
            raise ValueError("No valid URLs provided to scan. Exiting...")

        return valid_urls

    def extract_and_validate_urls(self) -> List[str]:
        """从URL或文件中提取并验证URLs"""
        raw_urls = []

        if self.url:
            raw_urls.append(self.url)

        if self.file:
            raw_urls.extend(self.extract_urls_from_file(self.file))

        return self.validate_and_format_urls(raw_urls)

    def parse_and_validate(self) -> Dict[str, Union[List[str], List[Dict[str, str]], int, Dict[str, str]]]:
        """
        解析和验证所有参数，并返回格式化后的结果
        :return: 包含 'urls', 'proxy', 'threads' 和 'headers' 的字典
        """
        self.validate_url_file()
        formatted_proxy = self.get_formatted_proxy()  # 支持多代理解析
        urls = self.extract_and_validate_urls()
        headers = self.parse_headers()  # 解析自定义请求头

        logger.info(f"Validated arguments: URLs={len(urls)}, Proxies={len(formatted_proxy)}, Threads={self.threads}, Headers={len(headers)}")

        return {
            "urls": urls,
            "proxy": formatted_proxy,
            "threads": self.threads,
            "headers": headers
        }


if __name__ == '__main__':
    # 测试用例
    c1 = ArgumentParser("", "../url.txt", "http://user:password@host1:port1,http://user:password@host2:port2", None, 5)
    c2 = ArgumentParser("https://example.com", "", None, None, 5)
    print(c1.parse_and_validate())  # 返回解析后的代理池和 URL 列表
    print(c2.parse_and_validate())  # 无代理情况下的解析