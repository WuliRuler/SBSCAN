# ✈️ 1. Tool Overview

## SBSCAN: (If you think this project is good, then click 🌟 🤩)

**SBSCAN is a penetration testing tool specifically designed for the Spring framework, capable of scanning specified sites for Spring Boot sensitive information and verifying related Spring vulnerabilities.**

- **Most Comprehensive Dictionary for Sensitive Paths**:
  - The most exhaustive dictionary for sensitive paths in Spring Boot sites, assisting you in thoroughly detecting potential sensitive information leaks.
- **Fingerprint Detection Support**:
  - **Detect Spring Sites**: Features fingerprint recognition; only sites with Spring fingerprints proceed to the next scanning phase, saving resources and time.
  - **Sensitive Path Page Fingerprint Detection**: Maximized reduction of false positives, achieving the highest accuracy in its class. No more manual checks to differentiate genuine sensitive pages from home pages or other redirecting pages.
- **Most Comprehensive Spring Vulnerability POCs**:
  - All detection POCs for Spring-related CVE vulnerabilities are integrated into this tool, making it the most comprehensive in its class.
- **Addressing Non-reflective Vulnerabilities**:
  - Unsure about vulnerabilities that don't have a direct echo just by looking at the response code? Supports the `--dnslog` parameter to specify the DNSLog domain. A successful DNSLog record confirms the existence of the vulnerability.
- **Other Conventional Features**:
  - Single URL scanning, URL file scanning, proxy specification support, and multithreading support.

## 🏂 Run

**MacOS && Linux**

```shell
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ python3 -m venv sbscan
$ source sbscan/bin/activate
$ pip3 install -r requirements.txt
$ python3 sbscan.py --help
```

**windows**

```bash
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ python3 -m venv sbscan
$ .\sbscan\Scripts\activate
$ pip3 install -r requirements.txt
$ python3 sbscan.py --help
```

> Test effect drawing, using color form printing more intuitive display of test results

![img](https://p.ipic.vip/1j9o3a.png)

> **Before detection** You can run `tail -f logs/sbscan.log` to view the detailed detection in real time

![image-20231025144650471](https://p.ipic.vip/uf51sp.png)

## 🐳 Docker

> Build your own Docker image

```Bash
$ git clone https://github.com/sule01u/SBSCAN.git
$ cd SBSCAN
$ docker build -t sbscan .
$ alias sbscan='docker run --rm -it -v "$(pwd)":/SBSCAN sbscan'
```

> Pull an existing image in the docker hub

```bash
$ alias sbscan='docker run --rm -it -v "$(pwd)":/SBSCAN milusuleo/sbscan'
```

> How to use

```
sbscan [option]
```

## 🎡 Options

```bash
BashCopy code
-u, --url                              Scan a single URL
-f, --file                             Scan targets from a file containing URLs
-m, --mode                             Specify the scanner mode[path/cve/all],default all
-p, --proxy                            Specify an HTTP proxy
-t, --threads                          Specify the number of threads
-q, --quiet                            Enable clean output, only display sensitive path hits
-ff, --fingerprint_filter              Enable fingerprint detection, only the sites that detect spring fingerprints will be scanned in the next step (it may cause missing reports, please select whether to enable it according to the actual situation
--dnslog                               Specify an DNSLog domain
--help                                 Display help information
```

## 🎨 Examples

```bash
BashCopy code
# Scan a specific target URL
$ python3 sbscan.py -u http://test.com
# Scan files, and URLs that do not match the fingerprint will skip the next step of detection
$ python3 sbscan.py -f url.txt --ff
# Only perform vulnerability scanning on the target and only output the hit CVEs
$ python3 sbscan.py -f url.txt -m cve --quiet
# Specify target URL, proxy, and thread count
$ python3 sbscan.py -u http://test.com -p 1.1.1.1:8888 -t 10
# Specify target URL, enable quiet output, display only hit sensitive paths or CVEs, enable fingerprint detection for scanning matching fingerprint sites
$ python3 sbscan.py -u http://test.com --quiet -ff
# Specify url file path, specify dnslog domain name, use 10 threads for concurrent scanning, and enable clean output
$ python3 sbscan.py -f url.txt -t 4 -d 5pugcrp1.eyes.sh --quiet
```

## 🧩 Custom extension
- Added vulnerability detection: scan the scanner/cve_scanners directory and program the detection logic according to other cve formats. Pay attention to the consistent format of function naming, parameter receiving, and return, and then add parameters in the config/cve.json format
- Added path detection: in config/ Path. json, configure the path and the characteristic string of the path page in dictionary format (none can be left empty).

## ⛪ Discussion

- For bug reports or feature requests, [click here](https://github.com/sule01u/SBSCAN/issues)
- WeChat: Scan the code below to follow **Unknown Security**
- Pull requests are welcome

<p>     <img alt="QR-code" src="https://github.com/sule01u/BigTree975.github.io/blob/master/img/mine.png" width="20%" height="20%" style="max-width:100%;"> </p>

## 📑 Licenses

In addition to the original [LICENSE](https://github.com/sule01u/SBSCAN/blob/master/LICENSE), the following disclaimer is added. If there's a conflict between the two, the disclaimer will prevail.

This tool is prohibited from unauthorized testing and from being used for unauthorized tests after secondary development.

When using this tool, you should ensure that your actions comply with local laws and regulations and that you have received sufficient authorization.

If you engage in any illegal activities while using this tool, you must bear the consequences yourself. We will not assume any legal or joint liabilities.

Before using this tool, please carefully read and fully understand the terms. Limitation and exemption clauses or other clauses concerning your vital rights may be presented in bold or underlined to draw your attention. Unless you have read, fully understood, and accepted all terms of this agreement, please refrain from using this tool. Your use or any explicit or implicit indication of acceptance of this agreement will be deemed as your acceptance to be bound by this agreement.
