#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
"""
   File Name：     global_thread_pool.py
   Description :   全局线程池管理类，提升了多线程执行效率
   Author :       sule01u
   date：          2023/10/8
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.logging_config import configure_logger
import concurrent.futures
import time  # 添加time模块导入

# 初始化日志记录
logger = configure_logger(__name__)


class GlobalThreadPool:
    """
    全局线程池管理类，提供线程池的全局实例，以便在整个程序中共享同一个线程池。
    """
    _executor = None

    @classmethod
    def initialize(cls, max_workers=50):
        """初始化全局线程池"""
        if cls._executor is None:
            cls._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix='GlobalPool')
            logger.info(f"Initialized global thread pool with {max_workers} threads.")

    @classmethod
    def get_executor(cls):
        """获取全局线程池实例"""
        if cls._executor is None:
            raise RuntimeError("GlobalThreadPool not initialized. Call 'initialize' first.")
        return cls._executor

    @classmethod
    def submit_task(cls, func, *args, **kwargs):
        """提交任务到全局线程池执行"""
        executor = cls.get_executor()
        return executor.submit(func, *args, **kwargs)

    @classmethod
    def execute_tasks(cls, task_func, urls, pbar=None):
        """
        提交一组任务到全局线程池，并等待所有任务完成。

        :param task_func: 任务函数
        :param urls: 待处理的URL列表
        :param pbar: tqdm进度条对象
        """
        executor = cls.get_executor()
        max_workers = executor._max_workers  # 获取线程池最大线程数
        
        # 控制同时提交到线程池的任务数量，避免所有URL同时启动超时计时
        # 使用滑动窗口提交任务并处理结果
        active_futures = {}  # 当前活跃的futures
        results = []
        url_index = 0
        url_count = len(urls)
        
        # 初始填充活跃任务队列 - 一次只提交一个URL，避免并发引起的问题
        # 最多同时处理线程池大小的1/3，确保资源合理分配
        initial_batch = min(max(1, max_workers // 3), url_count)
        logger.info(f"开始处理初始批次，共 {initial_batch} 个任务")
        for i in range(initial_batch):
            url = urls[url_index]
            logger.info(f"提交任务: {url}")
            future = executor.submit(task_func, url, pbar)
            active_futures[future] = url
            url_index += 1
            # 添加短暂延迟，确保任务不会同时启动
            time.sleep(1.0)  # 每个初始任务间隔1秒提交
        
        # 处理任务完成和提交新任务
        while active_futures:
            # 等待任一任务完成
            done, _ = concurrent.futures.wait(
                active_futures.keys(),
                return_when=concurrent.futures.FIRST_COMPLETED,
                timeout=60  # 增加超时值，避免无限等待
            )
            
            # 如果没有任务完成，记录活跃任务信息并继续等待
            if not done:
                active_urls = [active_futures[f] for f in active_futures]
                logger.warning(f"超过60秒未完成任何任务，当前活跃任务: {active_urls}")
                continue
            
            # 处理已完成的任务
            for future in done:
                url = active_futures.pop(future)
                try:
                    result = future.result()
                    results.append(result)
                    logger.info(f"任务完成: {url}")
                except Exception as e:
                    logger.error(f"任务异常: {url}, 错误: {e}", extra={"target": url})
                
                # 如果还有未提交的任务，提交新任务
                if url_index < url_count:
                    # 短暂等待，避免同时提交太多任务
                    time.sleep(0.5)
                    
                    url = urls[url_index]
                    logger.info(f"提交新任务: {url}")
                    new_future = executor.submit(task_func, url, pbar)
                    active_futures[new_future] = url
                    url_index += 1
                    
                    # 记录进度日志
                    if url_index % 5 == 0 or url_index == url_count:
                        logger.info(f"已提交 {url_index}/{url_count} 个任务")
        
        return results

    @classmethod
    def shutdown(cls, wait=True):
        """关闭全局线程池"""
        if cls._executor:
            logger.info("Shutting down global thread pool.")
            cls._executor.shutdown(wait=wait)
            cls._executor = None