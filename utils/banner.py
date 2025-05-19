#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     banner.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import random
from rich.console import Console
console = Console()

help_info_en = """
python3 sbscan.py [OPTIONS]

    -u  --url: Scan a single URL
    -f  --file: Read URLs from a file for scanning
    -m  --mode: Scan mode selection: [path/cve/all], default is 'all'
    -p  --proxy: Specify HTTP proxy. Supports various formats:
         - Single proxy: http://127.0.0.1:8080
         - Multiple proxies separated by commas: http://proxy1:8080,http://proxy2:8080
         - Proxy file path: /path/to/proxy.txt or file:///path/to/proxy.txt
    -H  --header: Specify custom HTTP headers, format: 'Name:Value', multiple headers separated by commas
    -t  --threads: Number of concurrent threads, default is 10 threads
    -ff  --fingerprint_filter: Scan only websites with a Spring fingerprint
    -d  --dnslog: Specify a dnslog domain
    -q  --quiet: Quiet mode, only outputs the results
    -to --timeout: Timeout in seconds for scanning a single URL, default is 60 seconds
    -h  --help: Show this help information
"""

help_info_zh = """
python3 sbscan.py [OPTIONS]

    -u  --url: 对单个URL进行扫描
    -f  --file: 从文件读取URL进行扫描
    -m  --mode: 扫描模式选择: [path/cve/all], 默认为'all'
    -p  --proxy: 指定HTTP代理。支持多种格式:
         - 单个代理: http://127.0.0.1:8080
         - 多个代理(逗号分隔): http://代理1:8080,http://代理2:8080
         - 代理文件路径: /path/to/proxy.txt 或 file:///path/to/proxy.txt
    -H  --header: 指定自定义HTTP请求头，格式：'Name:Value'，多个请求头用逗号分隔
    -t  --threads: 并发线程数, 默认10个线程
    -ff  --fingerprint_filter: 只对存在Spring指纹的网站进行扫描
    -d  --dnslog: 指定dnslog域名
    -q  --quiet: 纯净版输出，仅输出命中的结果
    -to --timeout: 单个URL扫描超时时间(秒), 默认60秒
    -h  --help: 显示帮助信息
"""


def banner():
    colors = ["red", "green", "yellow", "blue", "magenta", "cyan", "white"]

    LOGO = [
        r"             _",
        r"_   _ _ __ | | ___ __   _____      ___ __        ___  ___  ___",
        r"| | | | '_ \| |/ / '_ \ / _ \ \ /\ / / '_ \ _____/ __|/ _ \/ __|",
        r"| |_| | | | |   <| | | | (_) \ V  V /| | | |_____\__ \  __/ (__",
        r"\__,_|_| |_|_|\_\_| |_|\___/ \_/\_/ |_| |_|     |___/\___|\___|",
        "",
        r"name: SBSCAN",
        r"author: sule01u",
        r"from: [underline]https://github.com/sule01u/SBSCAN[/underline]",
        r"desc: springboot information leak scanner && spring vulnerability scanner",
        r"" 
        ""
    ]

    for line in LOGO:
        color = random.choice(colors)
        console.print(line, style=f"{color}")
