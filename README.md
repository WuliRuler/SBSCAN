- [English README](https://github.com/sule01u/SBSCAN/blob/master/README_en.md)
- [常见问题解答](https://github.com/sule01u/SBSCAN/wiki)

# ✈️ 一、工具概述

## SBSCAN：（spring框架渗透，这一个工具就够了，点个star🌟不迷路）
**SBSCAN是一款专注于spring框架的渗透测试工具，可以对指定站点进行springboot未授权扫描/敏感信息扫描以及进行spring相关漏洞的扫描与验证。**

- **最全的敏感路径字典**：最全的springboot站点敏感路径字典，帮你全面检测站点是否存在敏感信息泄漏
- **支持指纹检测**：
  - 支持spring站点指纹匹配：支持启用指纹识别，只有存在spring指纹的站点才进行下一步扫描，节约资源与时间 (无特征的站点会漏报，客官自行决策是否启用)
  - 支持敏感路径页面关键词指纹匹配：通过维护敏感路径包含的关键词特征，对检出的页面进行指纹匹配，大大提升了工具检出的准确率，减少了人工去确认敏感页面真实性投入的时间
- **支持指定模块发起检测：** 不想跑漏洞，只想检测敏感路径？ 或者只想检测漏洞？ 都可以，通过 `-m` 参数指定即可
- **最全的spring漏洞检测POC：** spring相关cve漏洞的检测poc全部给你集成到这款工具里，同类型最全
- **无回显漏洞解决：** 无回显漏洞检测扫描器光看响应状态码不太靠谱？支持--dnslog参数指定dnslog域名，看到dnslog记录才是真的成功验证漏洞存在
- **降噪输出结果：** 可通过指定`-q`参数只显示成功的检测结果
- **友好的可扩展性：** 项目设计初期就考虑了用户的自定义扩展需求，整个项目尽量采用高内聚低耦合模块化的编程方式， 你可轻松的加上自己的poc、日常积累的敏感路径、绕过语句，轻松优化检测逻辑，具体见下文的“自定义扩展”
- **其他一些常规支持**：单个url扫描/ url文件扫描 / 扫描模块选择 / 支持指定代理 / 支持多线程 / 扫描报告生成

## 🏂 安装使用

**MacOS && linux**

```Bash
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ python3 -m venv sbscan         # 创建虚拟环境
$ source sbscan/bin/activate     # 激活虚拟环境
$ pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple   # -i 指定pip源安装依赖,可选；
$ python3 sbscan.py --help
```
**Windows**

```bash
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ python3 -m venv sbscan         # 创建虚拟环境
$ .\sbscan\Scripts\activate        # 激活虚拟环境
$ pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple   # -i 指定pip源安装依赖,可选；
$ python3 sbscan.py --help
```

> 检测效果图, 使用彩色表格打印更直观显示检测结果，**检测报告**保存位置将会在扫描结束后控制台显示

![](https://p.ipic.vip/1j9o3a.png)

> **检测时**可使用 `tail -f logs/sbscan.log` 实时查看详细的检测情况 

![image-20231025144656039](https://p.ipic.vip/95mhnq.png)

## 🐳 Docker

> 自行构建 docker 进行

```Bash
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ docker build -t sbscan .
$ alias sbscan='docker run --rm -it -v "$(pwd)":/SBSCAN sbscan'
```

> 使用现有镜像

```Bash
$ alias sbscan='docker run --rm -it -v "$(pwd)":/SBSCAN milusuleo/sbscan'
```

> 使用

```bash
sbscan [参数]
```

## 🎡 Options

```Bash
-u, --url                              对单个URL进行扫描
-f, --file                             读取文件中的url目标进行扫描
-m, --mode                             指定扫描模式[path/cve/all],默认all
-p, --proxy                            指定HTTP代理
-H  --header                           指定自定义HTTP请求头，格式：'Name:Value'，多个请求头用逗号分隔
-t, --threads                          指定线程数量
-q, --quiet                            启用纯净输出,只输出命中的敏感路径信息
-ff, --fingerprint_filter              启用指纹检测,只扫描命中指纹的站点(可能有漏报，结合实际情况选择是否启用)
-d, --dnslog                           指定DNSLog域名,用于检测到无回显漏洞时可接收被攻击主机的dns请求
--help                                 显示帮助信息
```

## 🎨 Examples
```Bash
# 指定目标站点url进行扫描
$ python3 sbscan.py -u http://test.com
# 指定url文件路径扫描，启用指纹检测，未检测到指纹的无需进行路径以及CVE扫描
$ python3 sbscan.py -f url.txt --ff
# 仅对目标进行漏洞扫描并且只输出命中的cve
$ python3 sbscan.py -f url.txt -m cve --quiet
# 指定目标站点url、代理、线程数量
$ python3 sbscan.py -u http://test.com -p 1.1.1.1:8888 -t 10
# 指定目标站点url、启用纯净输出，只输出命中敏感路径或cve的目标、启用指纹检测，只有命中指纹的才继续扫描
$ python3 sbscan.py -u http://test.com --quiet -ff
# 指定url文件路径、指定dnslog域名、使用10个线程进行并发扫描并启用纯净输出
$ python3 sbscan.py -f url.txt -t 4 -d 5pugcrp1.eyes.sh --quiet
```

## 🧾 已支持检测CVE列表
- CVE-2018-1273
- CVE-2019-3799
- CVE-2020-5410
- CVE-2022-22947
- CVE-2022-22963
- CVE-2022-22965
- JeeSpringCloud_2023_uploadfile

## 🧩 自定义扩展
- 新增漏洞检测：在scanner/cve_scanners 目录下按照其他cve的格式编写检测逻辑，注意函数命名、参数接收、返回格式统一即可，然后在config/cve.json按格式增加配置即可
- 新增路径检测：在config/path.json 中按照字典格式配置路径 以及 该路径页面的特征字符串(没有可保持空)

## ⛪ Discussion
* Bug 反馈或新功能建议[点我](https://github.com/sule01u/SBSCAN/issues)
* WeChat: 扫码关注**不懂安全**
* 欢迎pr
<p>
    <img alt="QR-code" src="https://github.com/sule01u/BigTree975.github.io/blob/master/img/mine.png" width="30%" height="30%" style="max-width:100%;">
</p>

## 📑 Licenses

在原有协议[LICENSE](https://github.com/sule01u/SBSCAN/blob/master/LICENSE)中追加以下免责声明。若与原有协议冲突均以免责声明为准。

本工具禁止进行未授权测试，禁止二次开发后进行未授权测试。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。

在使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。
