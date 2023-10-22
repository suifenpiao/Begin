# Begin



> 渗透测试初期工具，运行环境: `python >= 3.10`



文件结构:

```bash
.
├── begin.py(源文件)
├── readme.md
├── service.txt(端口对应服务的字典)
├── sub.txt(子域名字典)
├── bak_dic.txt(备份文件字典)
├── modules/(文件用到的模块，目前只有图标哈希计算模块)
│   ├── ico_hash.py
├── config/(包含导出用到的模板html文件)
│   ├── vuln.html(文件url路径扫描导出文件)
│   ├── port.html(url端口扫描导出文件)
│   ├── subdomain.html(url子域名扫描导出文件)
│   ├── bak.html(url备份文件扫描导出文件)
│   └── origin.html(原始文件)
├──requirements.txt(脚本所用到的库)
├──logic_vuln.txt(收集脆弱功能点)
├──fofa导出结果.xlsx(供测试用excel文件)
└── ip.txt(供测试用IP文件)
```



## Usage

> 计算图标哈希:

`python begin.py -i http://xxx.com`

> 导出excel文件的 Host 列 到 `fofa.txt`

`python begin.py -e`

>  文件敏感目录扫描(同时演示其他参数):

`python begin.py -f ip.txt(文件名)`

扫描并导出

`python begin.py -f ip.txt(文件名) -h`

扫描并指定线程

`python begin.py -f ip.txt(文件名) -t 10`

指定线程并导出

`python begin.py -f ip.txt(文件名) -t 10 -h`

> 存活(功能点)探测

`python begin.py -f ip.txt(文件名) -a`

> 子域名扫描

`python begin.py -s http://xx.com`

> 备份扫描

`python begin.py -b http://xxx.com`

> 端口扫描

`python begin.py -p 123.12.123.12(ip)`



## 原理

除端口扫描外，其他扫描均采用requests库+多线程实现，涉及文件操作使用锁保证了文件操作的唯一性

端口扫描使用socket建立与目标端口的连接，返回数据说明端口开放，目前暂未使用socket发送数据探测对应服务，而是使用端口对应字典进行探测

## 使用场景

### 新出漏洞验证

当网上发现新出的漏洞时，漏洞总会存在一个漏洞路径用于验证。为了我们能够迅速快捷地进行漏洞验证，同时避免fofa批量获取的url很多无法访问的尴尬，本脚本的-f参数应运而生：我们可以通过本脚本与fofa语句找到对应漏洞的批量url，输入敏感的路径，本脚本会自动筛选互联网可能存在漏洞的可访问url，帮助白帽子快速进行漏洞验证并**增加白帽子对页面出现的漏洞可能会有什么样的场景的经验**(这种经验在后期渗透中可以起到事半功倍的效果)

### 渗透初期信息收集

当我们拿到一个目标后，对目标的常规初期信息收集往往需要在几个工具之间进行切换。大型扫描器虽然功能齐全，但是流量特征很容易被waf拦截；本工具集成了初期信息收集常用的几个模块，做到`all info collection in one`的 效果