import pandas as pd
import requests
import os
import warnings 
import ctypes,sys
from bs4 import BeautifulSoup
import datetime
import click
import threading
from modules.ico_hash import hashico
from fake_headers import Headers
import socket
from colorama import init, Fore,Style,Back
import shutil
from urllib.parse import urlparse, urlunparse
import concurrent.futures



ban_list =["不存在","非法","已拦截","禁止访问","不合法","权限不足","未提供","不可见","无权限","已隐藏","被禁止"]

warnings.filterwarnings ("ignore")

global_data = {
    'ip': '',
    'domain': '',
    'title': '',
    'open_ports': [],
    'backup_files': [],
    'sensitive_paths': []
}

ip = global_data['ip'] 
domain = global_data['domain']
title = global_data['title']
open_ports = global_data['open_ports']
backup_files = global_data['backup_files']
sensitive_paths = global_data['sensitive_paths']

def data_check(url,response,bfile,spath,func_type,port=""):
    if (url.count(".")>=3 and url.count("/") == 2) or (url.count(".")>=3 and url.count("/") == 0):
        index_url = url.find("/") + 2
        end_url = url[index_url:]
        ip = end_url
    else:
        #print("==--==="+url)
        ip = get_ip_address(url)
    domain = url
    title=""
    if func_type != 3:
        if response is not None:
            soup=BeautifulSoup(response.content,"html.parser")
            if soup.title is not None:
                soup_title = soup.title.string
                title = soup_title.strip()
            else:
                title = "None"
    open_ports = port
    #print(bfile+"===")
    backup_files = bfile.strip()
    sensitive_paths = spath
    return ip,domain,title,open_ports,backup_files,sensitive_paths
# def url_alive(file):

#     url_list=read_url(file)

#     session = requests.Session()
#     for line in url_list:
#         try:
#             response=session.get(line,verify=False,timeout=3)
#             response.raise_for_status()
#             soup=BeautifulSoup(response.content,"html.parser")
#             title = soup.title.string
#             code=response.status_code
#             if code==200:
#                 print(Fore.GREEN+"[ 200 ]"+"[ "+title+" ] "+line+ Style.RESET_ALL)
#         except Exception as e:
#             #print(Fore.RED+"[x] " + line + " (Error: " + str(e) + ")"+ Style.RESET_ALL+"\n")
#             pass
#         else:
#             if response.status_code == 403:
#             #etc
#                 print(Fore.BLUE+"[ 403 ] "+line+ Style.RESET_ALL+"\n")
#             # elif response.status_code == 404:
#             # #etc
#             #     print(Fore.RED+"[ 404 ] "+line+ Style.RESET_ALL)
#             elif response.status_code == 302:
#             #etc
#                 print(Fore.BLUE+"[ 302 ] "+line+ Style.RESET_ALL+"\n")
#             elif response.status_code in (500,502,501):
#             #etc
#                 print(Fore.BLUE+"[ 500|502|501 ] "+line+ Style.RESET_ALL+"\n")
def logic_vuln(response):
    with open("./logic_vuln.txt","r") as logicV:
        result = ""
        for logic in logicV:
            logic=logic.strip()
            if logic in response.text:
                result =  result+" | " + logic
        if result != "":
            resultn = result.replace("|", "", 1)
            return "[" + resultn +" ]"
        else:
            return ""
def url_alive(file):

    url_list = read_url(file)
    print(Fore.YELLOW+"[*] 当前线程数:" + str(global_thread) + Style.RESET_ALL)
    def check_url(line):
        try:
            session = requests.Session()
            response = session.get(line, verify=False, timeout=3)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, "html.parser")
            title = soup.title.string
            code = response.status_code
            lvuln = logic_vuln(response)

            if code == 200:
                print(Fore.GREEN + lvuln+"[ 200 ]" + "[ " + title + " ] " + line + Style.RESET_ALL)
        except Exception as e:
            # print(Fore.RED + "[x] " + line + " (Error: " + str(e) + ")" + Style.RESET_ALL + "\n")
        #     pass
        # else:
            if response.status_code == 403:
                # etc
                print(Fore.BLUE + "[ 403 ] " + line + Style.RESET_ALL)
            # elif response.status_code == 404:
            #     # etc
            #     print(Fore.RED + "[ 404 ] " + line + Style.RESET_ALL)
            elif response.status_code == 302:
                # etc
                print(Fore.BLUE + "[ 302 ] " + line + Style.RESET_ALL)
            elif response.status_code in (500, 502, 501):
                # etc
                print(Fore.BLUE + "[ 500|502|501 ] " + line + Style.RESET_ALL)
            else:
                print(Fore.RED + "[x] " + line + " (Error: " + str(e) + ")" + Style.RESET_ALL)

    with concurrent.futures.ThreadPoolExecutor(max_workers=int(global_thread)) as executor:
        executor.map(check_url, url_list)
    print(Fore.YELLOW + "[√] zf says: All seem ok"+ Style.RESET_ALL)


input_excel_file=""
column_name=""
output_txt_file=""
        

def export_column_to_txt(input_excel_file, column_name, output_txt_file):
        # 输入参数
    #对excel做处理
    print(Fore.YELLOW+"[*] make sure the scripts on same path with target xlsx and fofa txt file"+Style.RESET_ALL)
    try:
        print(Fore.YELLOW+"[*] Please hold your target index on excel top lines."+ Style.RESET_ALL)
        print(Fore.YELLOW+"[*] file default export coloumn Host and were saved as fofa.txt"+ Style.RESET_ALL)
        input_excel_file = input(Fore.CYAN+"[?] Enter excel name such as xxx.xlsx:"+ Style.RESET_ALL)  # 输入的Excel文件名
        column_name = "Host"  # 要导出的列名
        
        current_time = datetime.datetime.now()
        time_string = current_time.strftime("%m-%d_%H-%M-%S")
        output_filename = "excel_report_"+time_string+".txt"
        output_txt_file = "fofa.txt"  # 输出的txt文件名
        # 读取Excel文件
        df = pd.read_excel(input_excel_file)

        # 获取指定列的数据
        column_data = df[column_name]
        # 将列数据导出到txt文件
        with open(output_txt_file, "w") as txt_file:
            for value in column_data:
                txt_file.write(str(value) + "\n")

        print(Fore.GREEN+"[√] Column "+column_name+" exported to "+output_txt_file+" successfully."+ Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED+"[x] Error occurred:"+str(e)+ Style.RESET_ALL)
        exit()

def request_body():
    predefined_headers = {
    "Host": "",
    "Content-Type": "application/json",
    "User-Agent": "Mozilla/5.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Referer": "",
    "Authorization": "",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",  # Do Not Track
    "X-Forwarded-For": "",  # Client IP address when accessed through a proxy
    "X-Requested-With": "",  # Ajax request indicator
    "Origin": "",  # Originating website URL
    "If-Modified-Since": "",  # Conditional GET header for caching
    "If-None-Match": "",  # Conditional GET header for caching
    "Upgrade-Insecure-Requests": "1",  # Request HTTPS version of the page
    "Pragma": "no-cache"  # Cache control directive
    }

    custom_headers = {}
    datas = ""
    select_headers = {}
    while True:
        print("请选择要设置的请求头：")
        i = 1
        for key in predefined_headers:
            print(f"{i}. {key}: {predefined_headers[key]}")
            i += 1
        print("-1. 自定义新请求头")
        print("0. 完成设置并退出")

        choice = input(Fore.CYAN+"[?] 请输入选项数字："+ Style.RESET_ALL)
        if choice == "0":
            break
        elif choice.isdigit() and int(choice) in range(1, i):
            header_name = list(predefined_headers.keys())[int(choice) - 1]
            header_value = input(Fore.CYAN+"[?] 请输入"+header_name+" 值："+ Style.RESET_ALL)
            select_headers[header_name] = header_value
        elif choice == "-1":
            header_name = input(Fore.CYAN+"[?] 请输入自定义请求头名称："+ Style.RESET_ALL)
            header_value = input(Fore.CYAN+"[?] 请输入自定义请求头值："+ Style.RESET_ALL)
            custom_headers[header_name] = header_value

    headers = {**select_headers, **custom_headers}

    print(Fore.CYAN+"[?] 请输入请求数据（回车后按Ctrl+Z结束输入）："+ Style.RESET_ALL)
    try:
        while True:
            line = input()
            datas += line + "\n"
    except EOFError:
        pass

    return headers, datas

def get_ip_address(url):
    ip=""
    if url.startswith("http") or url.startswith("https"):
        index_url = url.find("/") + 2
        #print(index_url)  # 查找斜杠的位置，并加2跳过斜杠和下一个字符
        end_url = url[index_url:]
        #print(end_url+"===end===")
    try:
        ip = socket.gethostbyname(end_url)
    except Exception as e:
        pass
    return ip

header = Headers(
        browser="chrome",
        os="win",
        headers=True
    )

def bak_scan(bak, flag):
    func_type = 3
    print(Fore.YELLOW+"[*] 当前线程数:" + global_thread + Style.RESET_ALL)
    with open("./bak_dic.txt", "r") as bakfile:
        backups = [bak + "/" + bakS.strip() for bakS in bakfile]

    def check_backup(backup):
        r = requests.get(backup, verify=False, timeout=10, headers=header.generate(), stream=True)
        if ('html' not in r.headers.get('Content-Type')) and \
           ('image' not in r.headers.get('Content-Type')) and \
           ('xml' not in r.headers.get('Content-Type')) and \
           ('text' not in r.headers.get('Content-Type')) and \
           ('json' not in r.headers.get('Content-Type')) and \
           ('javascript' not in r.headers.get('Content-Type')) and \
           ('text' not in r.headers.get('Content-Type')):
            print(Fore.GREEN + "[+] bak found:" + backup + Style.RESET_ALL)
            if flag:
                ip, domain, title, open_ports, backup_files, sensitive_paths = data_check(bak, r, "", backup,func_type)
                #print(backup)
                export_bak_html(ip, backup_files, sensitive_paths)

    with concurrent.futures.ThreadPoolExecutor(max_workers=int(global_thread)) as executor:
        executor.map(check_backup, backups)

    print(Fore.YELLOW + "[√] zf says: All seem ok"+ Style.RESET_ALL)

def subdomain_url(url, flag):
    print(Fore.YELLOW+"[*] 当前线程数:" + global_thread + Style.RESET_ALL)
    func_type = 0
    with open("./sub.txt", "r") as subfile:
        subdomains = subfile.read().splitlines()

    def check_subdomain(subdomain):
        parts = url.split("//")
        if url.count(".") < 3 and (url.startswith("http") or url.startswith("https")):
            index_url = url.find("/") + 2
            header_url = url[:index_url]
            end_url = url[index_url:]
            now_url = header_url + subdomain + "." + end_url

            try:
                r = requests.get(now_url, verify=False, timeout=10, headers=header.generate())

                if r.status_code == 200:
                    print(Fore.GREEN + "[+] find subdomain: " + now_url + Style.RESET_ALL)
                    if flag:
                        ip, domain, title, open_ports, backup_files, sensitive_paths = data_check(url, r, "", now_url,func_type)
                        export_subdomain_html(ip, title, sensitive_paths)
            except requests.RequestException:
                pass

    with concurrent.futures.ThreadPoolExecutor(max_workers=int(global_thread)) as executor:
        executor.map(check_subdomain, subdomains)

    print(Fore.YELLOW + "[√] zf says: All seem ok"+ Style.RESET_ALL)

def read_url(file):
    lines = []
    with open(file, 'r') as file:
        for line in file:
            # 去除行尾的换行符
            line = line.rstrip('\n')
            if (not line.startswith("http://")) and (not line.startswith("https://")):
                line1 = "http://" + line
                line2 = "https://" + line
                lines.append(line1)
                lines.append(line2)
            else:
                lines.append(line)
    return lines

def add_surffix(file):
    url_addsur=[]
    url_append = input(Fore.CYAN+"[?] Enter your url_append (such as '/xxx'): "+ Style.RESET_ALL)
    if not url_append.startswith("/"):
        url_append = "/" + url_append
    # 添加输入验证
    #filename = "fofa.txt" 
    url = read_url(file)
    for line in url:
        url_addsur.append(line.strip() + url_append)
    return url_addsur

def port_scan(target_host,flag):
    # target_host = "localhost"
    func_type=0
    start_port = int(input(Fore.CYAN+"[?] 请输入扫描开始范围"+ Style.RESET_ALL))
    end_port = int(input(Fore.CYAN+"[?] 请输入扫描结束范围"+ Style.RESET_ALL))
    print(Fore.YELLOW+"[*] 当前线程数:" + global_thread + Style.RESET_ALL)
    # 锁对象用于线程间的同步
    lock = threading.Lock()

    # 线程执行的函数
    def scan_port(port):
        # 创建套接字对象
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        service_dict={}

        try:
            with open('services.txt', 'r') as file:
                for line in file:
                    port_number, service_name = line.strip().split(':')
                    service_dict[int(port_number)] = service_name
            # 尝试连接到目标主机的指定端口
            result = sock.connect_ex((target_host, port))
            with lock:
                if result == 0:
                    print(Fore.GREEN+"Port "+str(port)+" is open"+ Style.RESET_ALL)
                    if port in service_dict:
                        print(Fore.GREEN+"[+] Service:" + service_dict[port]+ Style.RESET_ALL)
                    if flag == True:
                        ip,domain,title,open_ports,backup_files,sensitive_paths=data_check(target_host,None,service_dict[port],"",str(port),func_type)
                        export_port_html(ip,open_ports,backup_files)
        except Exception as e:
            with lock:
                print(Fore.RED+"Error occurred while scanning port "+str(port)+str(e)+ Style.RESET_ALL)
        
        # 关闭套接字连接
        sock.close()

    # 创建线程并扫描端口
    threads = []
    for port in range(start_port, end_port+ 1):
        thread = threading.Thread(target=scan_port, args=(port,))
        thread.start()
        threads.append(thread)
        if len(threads) >= int(global_thread):
            for t in threads:
                t.join
            threads.clear()
    # 等待所有线程完成
    for thread in threads:
        thread.join()
    print(Fore.YELLOW + "[√] zf says: All seem ok"+ Style.RESET_ALL)




file_lock = threading.Lock()

def process_url(url, args):
    func_type=0
    output = ""
    try:
        session = requests.Session()
        if len(args) == 4:
            response = session.post(url, verify=False, timeout=2, headers=args[1], data=args[2])
        else:
            response = session.get(url, verify=False, timeout=2)
        
        response.raise_for_status()
        found_in_ban_list = False

        origin_url = urlparse(url)
        origin_url = origin_url._replace(path="")

        modified_url = urlunparse(origin_url)
        if response.status_code == 200:
            for i in ban_list:
                if i in response.text:
                    print(Fore.RED + "[ban] " + url + Style.RESET_ALL)
                    found_in_ban_list = True
                    break
            if not found_in_ban_list:
                output = "[++]" + url + "\n"
                print(Fore.GREEN + "[++] " + url + Style.RESET_ALL)
                if len(args) == 4 and args[3] == True:
                    ip, domain, title, open_ports, backup_files, sensitive_paths = data_check(modified_url.strip(), response, "", url,func_type)
                    export_vuln_html(ip, title, sensitive_paths)
                elif len(args) == 2 and args[1] == True:
                    ip, domain, title, open_ports, backup_files, sensitive_paths = data_check(modified_url.strip(), response, "", url,func_type)
                    export_vuln_html(ip, title, sensitive_paths)
                

    except Exception as e:
        pass

    return output

def url_scan(*args):
    try:
        url_list = add_surffix(args[0])
        current_time = datetime.datetime.now()
        time_string = current_time.strftime("%m-%d_%H-%M-%S")
        output_filename = time_string + "_result.txt"

        with open(output_filename, "w") as output_file:
            # 加锁，确保文件写入的线程安全
            file_lock.acquire()
            print(Fore.YELLOW+"[*] 当前线程数:" + global_thread + Style.RESET_ALL)
            with concurrent.futures.ThreadPoolExecutor(max_workers=int(global_thread)) as executor:
                results = []
                for url in url_list:
                    results.append(executor.submit(process_url, url, args))
                
                for future in concurrent.futures.as_completed(results):
                    output = future.result()
                    # 加锁，确保文件写入的线程安全
                    output_file.write(output)
                    
                    if output_file.tell() == len(output):
                        file_lock.release()
                        print(Fore.YELLOW + "[√] zf says: All seem ok"+ Style.RESET_ALL)
                        break

    except Exception as e:
        print(str(e))

def export_vuln_html(ip,title,sensitive_paths):
    if not os.path.exists("./vuln.html"):
        copy_file_to_current_folder("vuln.html")
    with open("./vuln.html","a",encoding="utf-8") as html:
        html.write(f'<script>add_table("{ip}","{title}","{sensitive_paths}");</script>')

def copy_file_to_current_folder(filename):
    current_folder = os.getcwd()
    target_file = os.path.join(current_folder, filename)

    if not os.path.exists(target_file):
        config_folder = os.path.join(current_folder, 'config')
        config_file = os.path.join(config_folder, filename)
        
        if os.path.exists(config_file):
            shutil.copy(config_file, target_file)
            print(f"{filename} file copied successfully.")
        else:
            print(f"{filename} file does not exist in the config folder.")
    else:
        print(f"{filename} file already exists in the current folder.")


def export_subdomain_html(ip,title,sensitive_paths):
    if not os.path.exists("./subdomain.html"):
        copy_file_to_current_folder("subdomain.html")
    with open("./subdomain.html","a",encoding="utf-8") as html:
        html.write(f'<script>add_table("{ip}","{title}","{sensitive_paths}");</script>')
    

def export_bak_html(ip,backup_files,sensitive_paths):
    if not os.path.exists("./bak.html"):
        copy_file_to_current_folder("bak.html")
    with open("./bak.html","a",encoding="utf-8") as html:
        html.write(f'<script>add_table("{ip}","{backup_files}","{sensitive_paths}");</script>')
    

def export_port_html(ip,open_ports,backup_files):
    if not os.path.exists("./port.html"):
        copy_file_to_current_folder("port.html")
    with open("./port.html","a",encoding="utf-8") as html:
        html.write(f'<script>add_table("{ip}","{open_ports}","{backup_files}");</script>')
    
@click.command()
@click.version_option(version='1.0.0')
@click.option("-f", "--file",help="目标url文件", metavar='[文件]', is_flag=False)
@click.option("-e", "--excel",help="从Excel加载url列表",metavar='[excel文件]', is_flag=True)
@click.option("-b", "--bak", help="备份文件扫描", metavar='[URL]',is_flag=False)
@click.option("-a", "--alive", help="url文件存活探测", metavar='[文件]',is_flag=True)
@click.option("-i", "--icohash", help="单个目标图标hash值计算",metavar='[URL]', is_flag=False)
@click.option("-s", "--subdomain", help="目标子域名扫描", metavar='[URL]',is_flag=False)
@click.option("-p", "--port", type=str,help="目标开放端口扫描",metavar='[URL]', is_flag=False)
@click.option("-c", "--custom", help="自定义访问数据包", is_flag=True)
@click.option("-h", "--html", help="导出为html文件", is_flag=True)
@click.option("-t", "--thread", default="10",help="指定扫描线程(默认10)", metavar='[数字]',is_flag=False)



def main(excel,file , bak,alive,icohash,subdomain,port,custom,html,thread):
    art = Fore.GREEN+"""

            ██████╗ ███████╗ ██████╗ ██╗███╗   ██╗
            ██╔══██╗██╔════╝██╔════╝ ██║████╗  ██║
            ██████╔╝█████╗  ██║  ███╗██║██╔██╗ ██║
            ██╔══██╗██╔══╝  ██║   ██║██║██║╚██╗██║
            ██████╔╝███████╗╚██████╔╝██║██║ ╚████║
            ╚═════╝ ╚══════╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝

                                    --version 2.1
"""+Style.BRIGHT+ Style.RESET_ALL
    
    print(art)

    global global_thread
    flag = False
    try:
        if html:
            flag = True

        if excel and bak and file:
            print(Fore.RED+"[x] 请不要输入冲突参数！"+ Style.RESET_ALL)
            sys.exit()

        if thread:
            global_thread = thread
        if excel:
            export_column_to_txt(excel, column_name, output_txt_file) #导入excel数据
        elif file!=None and os.path.exists(file): #输入了-f
            urllist = read_url(file) # 读取格式化后的url列表
            if alive: #如果存在-a参数，进行存活扫描
                url_alive(file)
            elif alive==False: #不存在时
                if custom: # 如果存在-c参数，进行自定义数据包
                    header,data = request_body()
                    url_scan(file,header,data,flag)
                else: # -c参数也不存在，直接进行特定路径扫描
                    url_scan(file,flag)
            else: # 没找到文件
                print(Fore.RED+"[x] no file input or file not found!"+ Style.RESET_ALL)
                sys.exit();

        if icohash: #存在-i参数，计算图标hash值
            print(Fore.YELLOW+"[*] 请输入目标主页网址形如http://xxx.com"+ Style.RESET_ALL)
            hashico(icohash)

        if bak: #存在-b 参数，进行单个目标备份文件扫描
            bak_scan(bak,flag)

        if subdomain: # 存在-s 参数，进行单体子域名扫描
            subdomain_url(subdomain,flag)

        if port: # 存在 -p 参数，进行端口扫描
            port_scan(port,flag)
    except KeyboardInterrupt:
        print(Fore.YELLOW+"[o.0] good luck for you")

# 调用main函数
main()