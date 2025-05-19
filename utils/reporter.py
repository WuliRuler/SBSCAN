#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     repoter.py
   Description :
   Author :       sule01u
   date：          2023/10/8
"""
import os
import threading
import json
from pathlib import Path
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.box import ROUNDED
from io import StringIO
from utils.logging_config import configure_logger
logger = configure_logger(__name__)


class ReportGenerator:
    def __init__(self, output_folder='reports', quiet=False, pbar=None):
        self.quiet = quiet
        self.report_data = []
        self.output_folder = output_folder
        self.console = Console()
        self.pbar = pbar  # tqdm对象
        if not os.path.exists(self.output_folder):
            os.makedirs(self.output_folder)
        self.lock = threading.Lock()

    def generate(self, url, is_spring, detected_paths, found_cves):
        """生成 报告文件 && 控制台输出信息"""
        report_entry = {
            'url': url,
            'is_spring': is_spring,
            'detected_paths': detected_paths,
            'found_cves': found_cves
        }
        if (self.quiet and (detected_paths or found_cves)) or not self.quiet:
            self._display_report(url, is_spring, detected_paths, found_cves)
            if detected_paths or found_cves:
                with self.lock:  # 添加数据到共享列表时上锁
                    self.report_data.append(report_entry)

    def _display_report(self, url, is_spring, paths, cves):
        table = Table(show_header=True, header_style="bold magenta", box=ROUNDED)
        table.add_column("URL", style="cyan")
        table.add_column("IS_SPRING", style="cyan")
        table.add_column("Detected Paths", style="green")
        table.add_column("Detected CVEs", style="red")

        # 处理CVE格式和显示
        if cves:
            cve_str = "\n".join([f"{cve.get('CVE_ID', 'N/A')}: {cve.get('Details', '未知')}".strip() for cve in cves])
        else:
            cve_str = "None"
            
        # 处理路径格式和显示
        path_str = "\n".join(paths) if paths else "None"

        # 确保URL字符串的格式
        url_str = str(url).strip() if url else "N/A"
        
        # 确保is_spring的显示格式
        spring_str = str(is_spring)

        # 表格添加行时处理可能的异常
        try:
            table.add_row(url_str, spring_str, path_str, cve_str)
        except Exception as e:
            # 如果添加行失败，尝试使用简化的显示
            logger.error(f"表格显示错误: {e}")
            # 使用简化的内容再次尝试
            simple_path_str = f"{len(paths)} 个路径" if paths else "None"
            simple_cve_str = f"{len(cves)} 个CVE" if cves else "None"
            table.add_row(url_str, spring_str, simple_path_str, simple_cve_str)

        # 创建一个新的控制台对象和一个字符串IO对象
        buffer = StringIO()
        console = Console(file=buffer, force_terminal=True, width=120)  # 确保表格有足够的宽度

        # 使用新的控制台对象输出表格
        try:
            console.print(table)
            # 获取字符串IO对象的内容
            output = buffer.getvalue()
        except Exception as e:
            logger.error(f"控制台输出错误: {e}")
            output = f"扫描结果 - URL: {url_str}, Spring: {spring_str}, 路径: {len(paths) if paths else 0}, CVE: {len(cves) if cves else 0}"

        # 如果有 tqdm 对象，使用 tqdm.write 方法
        if self.pbar:
            self.pbar.write(output)
        else:
            # 如果输出失败，使用简单的文本输出
            try:
                self.console.print(output)
            except:
                print(f"扫描结果 - URL: {url_str}, Spring: {spring_str}, 路径: {len(paths) if paths else 0}, CVE: {len(cves) if cves else 0}")

        buffer.close()  # 关闭字符串IO对象

    def save_report_to_file(self):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M')
        filename = Path(self.output_folder) / f'report_{timestamp}.json'

        with self.lock:  # 读取共享数据时上锁
            if not self.report_data:
                logger.warning("没有命中任何检测规则，未生成报告。[No detection rule was matched and no report was generated.]")
                return
            report_data_copy = self.report_data.copy()  # 为了安全地在锁外部使用

        with open(filename, 'w', encoding='utf-8') as file:
            json.dump(report_data_copy, file, indent=4, ensure_ascii=False)

        self.console.print(f"[cyan][+] 报告已保存到[The report was saved to]: [bold yellow]{filename}[/bold yellow]")

    def get_report_data(self):
        with self.lock:  # 读取共享数据时上锁
            return self.report_data.copy()

