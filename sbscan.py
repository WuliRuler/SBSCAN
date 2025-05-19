#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     sbscan.py
   Description :  main process
   Author :       sule01u
   date：          2023/10/8
"""
import sys
import locale
import click
from managers.proxy_manager import ProxyManager
from managers.scanner_manager import ScannerManager
from utils.logging_config import configure_logger
from utils.args_prase import ArgumentParser
from utils.banner import banner, help_info_en, help_info_zh
from utils.global_thread_pool import GlobalThreadPool  # 确保全局线程池已初始化

# 初始化日志记录
logger = configure_logger(__name__)

# 检测系统语言
system_lang = locale.getlocale()[0]


@click.command(add_help_option=False)
@click.option("-u", "--url", type=str, help="对单个URL进行扫描")
@click.option("-f", "--file", help="读取文件中的url进行扫描", type=click.Path(exists=True))
@click.option("-m", "--mode", type=str, help="扫描模式选择: [path/cve/all], 默认all", default="all")
@click.option("-p", "--proxy", type=str, help="指定HTTP代理，支持单个代理、逗号分隔的多个代理或代理文件")
@click.option("-H", "--header", type=str, help="指定Header，格式为'Name:Value'，多个请求头用逗号分隔")
@click.option("-t", "--threads", type=int, help="并发线程数, 默认10个线程", default=10)
@click.option("-ff", "--fingerprint_filter", is_flag=True, help="只对存在spring指纹的网站开始扫描")
@click.option("-d", "--dnslog", type=str, help="指定dnslog域名", default="")
@click.option("-q", "--quiet", is_flag=True, help="纯净版输出，仅输出命中的结果")
@click.option("-to", "--timeout", type=int, help="单个URL扫描超时时间(秒), 默认60秒", default=60)
@click.option("-h", "--help", is_flag=True, callback=lambda ctx, param, value: ctx.exit(
    click.secho(help_info_zh if system_lang and system_lang.startswith("zh_CN") else help_info_en,
                fg='cyan') or 0) if value else None, expose_value=False, help="显示帮助信息")
def main(url, file, mode, proxy, header, dnslog, threads, fingerprint_filter, quiet, timeout):
    try:
        # 参数解析与验证
        args_parser = ArgumentParser(url, file, proxy, header, threads)
        args_data = args_parser.parse_and_validate()  # 解析后的代理列表为 List[Dict[str, str]]
        logger.debug(args_data)

        # 代理管理
        if args_data["proxy"] and len(args_data["proxy"]) > 0:
            click.secho(f"[*] 检测到 {len(args_data['proxy'])} 个代理配置，正在验证代理可用性...", fg='cyan')
        proxy_manager = ProxyManager(args_data["proxy"])  # 初始化时传入代理列表并验证可用性

        # 初始化全局线程池管理，并根据传入的线程数设置最大并发数
        GlobalThreadPool.initialize(max_workers=args_data["threads"])

        # 扫描管理
        manager = ScannerManager(args_data["urls"], mode, proxy_manager, dnslog, args_data["threads"],
                                 fingerprint_filter, quiet, args_data.get("headers", {}), 
                                 scan_timeout=timeout)
        click.secho("[+] 扫描时间部分情况下可能稍长，请耐心等待扫描结果[Please wait for the scan results]:", fg='green',
                    bold=True)
        logger.info("Starting scan for target URLs")

        # 启动扫描
        report_data = manager.start_scanning()

        logger.info("Scan completed for target URLs")

        # 报告处理
        if quiet and not report_data:
            click.secho("[-] 目标未命中任何检测规则 [No sensitive paths or CVEs detected for the provided URLs]",
                        fg="yellow")

        # 保存扫描报告
        manager.reporter.save_report_to_file()
    except KeyboardInterrupt:
        click.secho("[-] 用户终止扫描 [User aborted the scan]", fg="yellow")
        sys.exit()
    except Exception as e:
        logger.error(e, extra={'url': "target_url"})
        sys.exit()


if __name__ == "__main__":
    # 打印程序启动Banner
    banner()
    # 启动啦
    main()