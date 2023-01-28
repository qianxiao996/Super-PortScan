#!/usr/bin/env python
# -*- coding: utf-8 -*-
import html,shutil
import threading  # 导入线程相关模块
import queue, os, requests
import re, sys
from colorama import init, Fore
import click
import eventlet

from tqdm import tqdm
import ipaddr
from modules import host_scan
from modules import port_scan


requests.packages.urllib3.disable_warnings()
init(autoreset=True)  # 初始化，并且设置颜色设置自动恢复
lock = threading.Lock()  # 申请一个锁

class Portscan:
    def __init__(self):
        self.portQueue = queue.Queue()
        self.flag = 0  # 是否显示过程
        self.jp_flag = 0  # 跳过主机发现
        self.out_txt = ''  # 输出txt文件
        self.out_html = ''
        self.all_remove_port = []  # 排除的端口
        self.all_port_list = [21, 22, 23, 25, 53, 53, 80, 81, 110, 111, 123, 123, 135, 137, 139, 161, 389, 443, 445,
                              465,
                              500, 515, 520, 523, 548, 623, 636, 873, 902, 1080, 1099, 1433, 1521, 1604, 1645, 1701,
                              1883,
                              1900, 2049, 2181, 2375, 2379, 2425, 3128, 3306, 3389, 4730, 5060, 5222, 5351, 5353, 5432,
                              5555,
                              5601, 5672, 5683, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 8001, 8002, 8003, 8004, 8005,
                              8006,
                              8007, 8008, 8009, 8010, 8080, 8081, 8443, 8545, 8686, 9000, 9042, 9092, 9100, 9200, 9418,
                              9999,
                              11211, 15210, 27017, 37777, 33899, 33889, 50000, 50070]
        self.ip_1_list = []  # 存放存活的ip
        self.ip_2_list = []  # ip:port 模式存放列表

    def chuli_canshu(self, ip, file, port, port_file, remove_port, ip_port, jump_port, timeout, verbose, threads, txt,
                     html):
        try:
            if verbose:
                self.flag = 1
            if jump_port:
                self.jp_flag = 1
            if txt:
                self.out_txt = txt
                f = open(self.out_txt, "a")
                f.write("IP地址\t端口\t开放情况\t服务\t标题\tBanner\n")
                f.close()
            if html:
                self.out_html = html
            if timeout:
                timeout = int(timeout)
            else:
                timeout = 1
            if remove_port:
                remove_port_temp = (remove_port).split(",")
                # print(type(remove_port_temp))
                self.all_remove_port.extend(remove_port_temp)
            if port:
                self.all_port_list = self.get_port_list(port)
            elif port_file:
                self.all_port_list = self.get_port_file_list(port_file)
            else:
                self.all_port_list = self.diff_of_two_list(self.all_port_list, self.all_remove_port)

            ip_list = []
            if ip and file:
                click.echo(Fore.RED + "[E] 不能同时输入IP和文件参数！")
                sys.exit()
            if (port and ip_port) or (port_file and ip_port):
                click.echo(Fore.RED + "[E] IP对应端口探测模式不允许指定-p参数！")
                sys.exit()
            # ip:port模式
            if ip_port:
                if ip:
                    self.ip_2_list.append(ip)
                elif file:
                    if os.path.exists(file):
                        try:
                            all_list = []
                            file = open(file, 'r', encoding='utf-8')
                            for line in file:
                                port_list_temp = []
                                ip_list_temp= []
                                line = line.split(":")
                                if '/' in line[0] or '-' in line[0]:
                                    ip_list_temp = self.get_ip_d_list(line[0])
                                else:
                                    ip_list_temp = [line[0].strip()]
                                if len(line)==2:
                                    # print(line[1])
                                    if '-' in line[1]:
                                        port_list_temp = self.get_port_list(line[1].strip())
                                    else:
                                        port_list_temp = [line[1].strip()]
                                else:
                                    port_list_temp = [80]
                                # print(ip_list_temp)
                                # print(port_list_temp)
                                for ip_v in ip_list_temp:
                                    for port_v in port_list_temp:
                                        temp_ip_port = ip_v+":"+port_v.strip()
                                        all_list.append(temp_ip_port.strip())
                            file.close()
                            self.ip_2_list = list(filter(None, all_list))  # 去除 none 和 空字符
                            # print(self.ip_2_list)

                        except:
                            print(Fore.RED + 'Error:文件读取错误！')
                            sys.exit()
                    else:
                        print(Fore.RED + 'Error:文件不存在')
                        sys.exit()
                # print(self.ip_1_list)
                if len(self.ip_2_list) > 0:
                    self.ip_port_scan(int(threads), timeout)
                else:
                    print(Fore.YELLOW + "[*] NO IP")

            else:
                if ip:
                    if len(ip.split(":")) == 2:
                        self.ip_2_list.append(ip)
                        if len(self.ip_2_list) > 0:
                            self.ip_port_scan(int(threads), timeout)
                        else:
                            print(Fore.YELLOW + "[*] NO IP")
                        sys.exit()
                    else:
                        print(Fore.BLUE + "[*] GET IP...")
                        ip_list = self.get_ip_d_list(ip)
                        # print(ip_list)
                        print(Fore.BLUE + "[*] IP Num:%s" % len(ip_list))
                elif file:
                    ip_list = self.get_ip_f_list(file)
                else:
                    return
                if (self.jp_flag == 1):
                    self.ip_1_list = ip_list
                else:
                    try:
                        print(Fore.BLUE + "[*] Start survival detection")
                        host_scan.ip_main(ip_list,threads)
                        ip_flag=1
                        while(ip_flag):
                            if host_scan.cunhuo_ip_list:
                                for i in  host_scan.cunhuo_ip_list:
                                    if i!='End|End|End':
                                        i_list = i.split("|")
                                        if i_list[2]=='1':
                                            self.ip_1_list.append(i_list[1])
                                            print(Fore.YELLOW + "[*] ["+i_list[0]+"]IP:" + i_list[1] + " is alive\n", end="")
                                    else:
                                        ip_flag=0

                                # 开始扫描
                    except KeyboardInterrupt:
                        # self.ipQueue.queue.clear()
                        print(Fore.RED + "用户中途退出！")
                        sys.exit()
                # print(self.ip_1_list)
                if len(self.ip_1_list) > 0:
                    self.scan(int(threads), timeout)
                else:
                    print(Fore.YELLOW + "[*] NO IP is alive")

        except KeyboardInterrupt:
            print(Fore.RED + "用户中途退出！")
            return
        except Exception as e:
            print(Fore.RED + str(e) + str(e.__traceback__.tb_lineno) + '行')
            print(Fore.RED + '参数输入错误！')

    # 得到-d中的ip列表
    def get_ip_d_list(self, ip):
        ip_list = []
        # 127.0.0.1/24匹配
        remath_1 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$'
        re_result1 = re.search(remath_1, ip, re.I | re.M)
        # 127.0.0.1-222匹配
        remath_2 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])$'
        re_result2 = re.search(remath_2, ip, re.I | re.M)
        # remath_3 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
        # re_result3 =  re.search(remath_3,ip)
        if re_result1:
            try:
                ipNet = ipaddr.IPv4Network(re_result1.group())
                for ip in ipNet:
                    ip_list.append(str(ip))
                    # print(isinstance(ip, ipaddr.IPv4Address))
                    # print (str(ip))
                ip_list = ip_list[1:-1]

            except:
                print(Fore.RED + 'Error:IP段设置错误！')
                return
            # print(ip_list)
            # ip = ip.replace('/24','')
            # for i in range(1,255):
            #     ip_list.append(ip[:ip.rfind('.')]+'.'+str(i))
        elif re_result2:
            ip_addr = re_result2.group()
            ip_start = ip_addr.split('.')[-1].split('-')[0]
            ip_end = ip_addr.split('.')[-1].split('-')[1]
            # print(ip_start,ip_end)
            if int(ip_start) > int(ip_end):
                numff = ip_start
                ip_start = ip_end
                ip_end = numff
            for i in range(int(ip_start), int(ip_end) + 1):
                ip_list.append(ip[:ip.rfind('.')] + '.' + str(i))
        else:
            ip_list = ip.split()
            # ip_list.append(re_result3.group())
        # 列表去重
        # new_lis = list(set(ip_list))
        # new_lis.sort(key=ip_list.index)
        # return new_lis
        # all_list = []
        # for i in ip_list:
        #     if i not in all_list:
        #         all_list.append(i)
        return list(filter(None, ip_list))  # 去除 none 和 空字符

    # 得到文件中的ip列表
    def get_ip_f_list(self, file):
        all_list = []
        if os.path.exists(file):
            try:
                file = open(file, 'r', encoding='utf-8')
                for line in file:
                    all_list = all_list + self.get_ip_d_list(line)
                file.close()
                # all_list2 = []
                # for i in all_list:
                #     if i not in all_list2:
                #         all_list2.append(i)
                return list(filter(None, all_list))  # 去除 none 和 空字符
            except:
                print(Fore.RED + 'Error:文件读取错误！')
                sys.exit()
        else:
            print(Fore.RED + 'Error:文件不存在')
            sys.exit()

    # 得到端口列表
    def get_port_list(self, port):
        port_list = []
        if ',' in port and '-' not in port:
            port_list = port.strip().split(',')
        elif ',' not in port and '-' in port:
            port_start = port.split('-')[0]
            port_end = port.split('-')[1]
            if int(port_start) > int(port_end):
                numff = port_start
                port_start = port_end
                port_end = numff
            for i in range(int(port_start), int(port_end) + 1):
                port_list.append(str(i).strip())
        elif ',' in port and '-' in port:
            port_list = port.split(',')
            for i in port_list:
                port_list.remove(i)
                port_start = i.split('-')[0]
                port_end = i.split('-')[1]
                if int(port_start) > int(port_end):
                    numff = port_start
                    port_start = port_end
                    port_end = numff
                for i in range(int(port_start), int(port_end) + 1):
                    port_list.append(str(i).strip())
        else:
            port_list = port.split()
        for i in port_list:
            if int(i) > 65535:
                port_list.remove(i)
        port_list = self.diff_of_two_list(port_list, self.all_remove_port)
        # print(port_list)
        return port_list

    def get_port_file_list(self, port_file_path):

        try:
            if os.path.exists(port_file_path):
                file_cls = open(port_file_path, 'r', encoding='utf-8')
                data = file_cls.read()
                file_cls.close()
                port_list = []
                try:
                    port_list = data.split(',')
                    for i in port_list:
                        try:
                            if int(i) > 65535:
                                port_list.remove(i)
                        except:
                            port_list.remove(i)
                    port_list = self.diff_of_two_list(port_list, self.all_remove_port)
                except:
                    print(Fore.RED + 'Error:端口文件读取错误！')
                return port_list
            else:
                print(Fore.RED + 'Error:端口文件不存在！')
        except:
            print(Fore.RED + 'Error:文件读取错误！')

    # 从list1排除list2
    def diff_of_two_list(self, list1, list2):
        for value in list2:
            try:
                value = int(value)
                if value in list1:
                    list1.remove(value)
            except:
                pass
        return list1
        # print(type(list1[0]))
        # print(type(value))
        # return list(set(list1)-set(list2))

    def portScanner(self, timeout, pbar, list_type):
        while True:
            try:
                # tqdm.write(str(self.portQueue.qsize()))
                if self.portQueue.qsize() == 0 and list_type == '1' and len(self.ip_1_list) > 0:
                    for i in self.all_port_list:
                        # print(port_list)
                        self.portQueue.put(self.ip_1_list[0] + ':' + str(i))
                    del (self.ip_1_list[0])
                elif self.portQueue.qsize() == 0 and list_type == '2' and len(self.ip_2_list) > 0:
                    self.portQueue.put(self.ip_2_list[0])
                    del (self.ip_2_list[0])
                else:
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(60, False):
                        if self.portQueue.empty():  # 队列空就结束
                            break
                        ip_port = self.portQueue.get().split(":")  # 从队列中取出
                        if len(ip_port) == 2:
                            host = ip_port[0]
                            port = ip_port[1]
                        else:
                            host = ip_port[0]
                            port = 80
                        pbar.set_description(Fore.BLUE + '[*] Scanning:' + host + ' ' + str(port))  # 修改进度条描述
                        pbar.update(1)
                        # print(host,port)
                        try:
                            port_scan_result  = port_scan.port_scan(host,port,int(timeout))

                            # host, port, status, service, Banner, title
                            # print(port_scan_result)
                            # self.out_result(host, port, 'Opened', 'Unknown', 'None', '')
                            # self.out_result(port_scan_result)
                            self.out_result(port_scan_result[0],str(port_scan_result[1]),port_scan_result[2],port_scan_result[3],port_scan_result[4],port_scan_result[5])
                        except Exception as e:
                            # print(str(e))
                            self.out_result(host, port, 'Closed', 'Unknown', 'None', '')
                            continue

                    continue
            except Exception as e:
                print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

                continue

    # host, port, status, service, banner, title
    def out_result(self, host, port, zhuangtai,service='Unknown', Banner='None', title=''):
        lock.acquire()  # 加锁
        if len(Banner) > 60:
            Banner = Banner[:60]
        Banner = (Banner.replace('\r','').replace('\n','')).strip().replace('\r\n','')
        title = (title.replace('\r', '').replace('\n', '')).strip()
        # Banner = "".join(str(Banner).split())
        # title = "".join(str(title).split())
        # print(zhuangtai)
        if self.flag:
            #没有文件保存
            if self.out_txt == '' and  self.out_html == '':
                if  zhuangtai == 'Opened':
                    tqdm.write(
                        Fore.GREEN + '[-] ' +host.ljust(20, ' ')  + port.ljust(8, ' ') + zhuangtai.ljust(
                            10, ' ') +  service.ljust(10, ' ') +title.ljust(20,' ') +  Banner.ljust(20, ' '))
                else:
                    tqdm.write(
                        Fore.MAGENTA + '[-] ' +host.ljust(20, ' ')  + port.ljust(8, ' ') + zhuangtai.ljust(
                            10, ' ') +  service.ljust(10, ' ') +title.ljust(20,' ') +  Banner.ljust(20, ' '))
            #有文件保存
            else:
                if zhuangtai == 'Opened':
                    tqdm.write(
                        Fore.GREEN + '[-] ' +host.ljust(20, ' ')  + port.ljust(8, ' ') + zhuangtai.ljust(
                            10, ' ') +  service.ljust(10, ' ') +title.ljust(20,' ') +  Banner.ljust(20, ' '))
                self.save_file(host,port,zhuangtai,service,title,Banner)
        elif zhuangtai == 'Opened':
            tqdm.write(
                Fore.GREEN + '[+] ' +host.ljust(20, ' ')  + port.ljust(8, ' ') + 'Opened'.ljust(
                    10, ' ') +  service.ljust(10, ' ') +title.ljust(20,' ') +  Banner.ljust(20, ' '))
            self.save_file(host,port,zhuangtai,service,title,Banner)

        lock.release()  # 执行完 ，释放锁
    def save_file(self,host,port,zhuangtai,service,title,Banner):
        try:
            if self.out_txt != '':
                f = open(self.out_txt, "a")
                f.write(host + '\t' + port + '\t' + zhuangtai + '\t' + service + "\t" + title + "\t" + Banner + '\n')
                f.close()
            if self.out_html != '':
                # print(Banner)
                if title:
                    Banner = ((title.strip()).encode(encoding='gbk', errors='ignore')).decode("gbk", errors='ignore')
                else:
                    Banner = ((Banner.strip()).encode(encoding='gbk', errors='ignore')).decode("gbk", errors='ignore')
                if service in ['http', 'https', "HTTP", "HTTPS"]:
                    url_address = service + "://" + host + ":" + port
                else:
                    url_address = ''
                Banner = html.escape(Banner)
                out_str = '<script>add_table("' + host + '","' + port + '","' + zhuangtai + '","' + service + '","' + Banner + '","' + url_address + '");</script>'

                if os.path.exists(self.out_html):
                    f2 = open(self.out_html, "a", encoding='utf-8')
                    f2.write(out_str)
                    f2.close()

                else:
                    shutil.copyfile('conf/html.html', self.out_html)
                    f2 = open(self.out_html, "a", encoding='utf-8')
                    f2.write(out_str)
                    f2.close()

        except Exception as e:
            print(Fore.RED + '文件写入出错！' + str(e))
    # ip:port 单端口扫描
    def ip_port_scan(self, threadNum, timeout):
        if (threadNum < len(self.ip_2_list)):
            threadNum = threadNum
        else:
            threadNum = len(self.ip_2_list)
        print(Fore.CYAN + '[*] 共扫描%s个IP,线程:%s,请稍后..' % (len(self.ip_2_list), threadNum))
        print(Fore.YELLOW + '[*] The PortScan is Start')
        count = len(self.ip_2_list)
        try:
            with tqdm(total=count, ncols=100) as pbar:
                tqdm.write(
                    Fore.CYAN + '[*] ' + 'Host'.ljust(20, ' ') + 'Port'.ljust(8, ' ') + 'Status'.ljust(
                        10, ' ') +  'Service'.ljust(10, ' ') + 'Title'.ljust(20, ' ') + 'Banner'.ljust(20, ' '))

                self.portQueue.queue.clear()
                kkk = int(threadNum / len(self.ip_2_list)) + 1
                try:
                    if kkk > len(self.ip_2_list):
                        kkk = len(self.ip_2_list)
                    for i in range(0, kkk):
                        self.portQueue.put(self.ip_2_list[i])
                        self.ip_2_list.remove(self.ip_2_list[i])
                except:
                    pass
                if self.portQueue.qsize() > 0:
                    try:
                        threads = []  # 线程列表
                        for i in range(threadNum):
                            i = threading.Thread(target=self.portScanner, args=(timeout, pbar, '2'))
                            threads.append(i)
                        for t in threads:  # 启动线程
                            t.start()
                        for t in threads:  # 阻塞线程，等待线程结束
                            t.join()

                    except KeyboardInterrupt:
                        self.portQueue.queue.clear()
                        print(Fore.RED + "用户中途退出！")
                        return

                tqdm.write(Fore.YELLOW + '[*] The Scan is Complete!')
                pbar.set_description(Fore.BLUE + '[*] Scan Complete!')  # 修改进度条描述
                pbar.close()
        except KeyboardInterrupt:
            print(Fore.RED + "用户中途退出！")
            pass

    def scan(self, threadNum, timeout):
        if threadNum < len(self.ip_1_list)*len(self.all_port_list):
            threadNum = threadNum
        else:
            threadNum = len(self.ip_1_list)*len(self.all_port_list)
        print(Fore.CYAN + '[*] 共扫描%s个IP,%s种端口,排除%s种端口,线程:%s,请稍后..' % (
        len(self.ip_1_list), len(self.all_port_list), len(self.all_remove_port), threadNum))
        print(Fore.YELLOW + '[*] The PortScan is Start')
        count = len(self.all_port_list) * len(self.ip_1_list)
        try:
            with tqdm(total=count, ncols=100) as pbar:
                tqdm.write(
                    Fore.CYAN + '[*] ' + 'Host'.ljust(20, ' ') + 'Port'.ljust(8, ' ') +  'Status'.ljust(
                        10, ' ') +  'Service'.ljust(10, ' ')  + 'Title'.ljust(20, ' ')+  'Banner'.ljust(20, ' '))

                self.portQueue.queue.clear()
                kkk = int(threadNum / len(self.all_port_list)) + 1
                try:
                    if kkk > len(self.ip_1_list):
                        kkk = len(self.ip_1_list)
                    for i in range(0, kkk):
                        for port in self.all_port_list:
                            self.portQueue.put(self.ip_1_list[0] + ':' + str(port))
                        self.ip_1_list.remove(self.ip_1_list[0])
                    if self.portQueue.qsize() > 0:
                        try:
                            threads = []  # 线程列表
                            for i in range(threadNum):
                                i = threading.Thread(target=self.portScanner, args=(timeout, pbar, '1'))
                                threads.append(i)
                            for t in threads:  # 启动线程
                                t.start()

                            for t in threads:  # 阻塞线程，等待线程结束
                                t.join()

                        except KeyboardInterrupt:
                            self.portQueue.queue.clear()
                            print(Fore.RED + "用户中途退出！")
                            return

                    tqdm.write(Fore.YELLOW + '[*] The Scan is Complete!')
                    pbar.set_description(Fore.BLUE + '[*] Scan Complete!')  # 修改进度条描述
                    pbar.close()
                except Exception as e:
                    print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
        except KeyboardInterrupt:
            print(Fore.RED + "用户中途退出！")
            pass


@click.command()
@click.version_option(version='1.4.2')
@click.option("-i", "--ip", help="输入ip，例如：192.168.1.1、192.168.1.1/24、192.168.1.1-99", default='', is_eager=True)
@click.option("-f", "--file", help="从文件加载ip列表", default='')
@click.option("-p", "--port", help="定义扫描的端口，例如:80、80,8080、80-8000", default='', is_eager=True)
@click.option("-pf", "--port_file", help="从文件加载端口列表，使用逗号分隔", default='')
@click.option("-rp", "--remove_port", help="定义排除的端口，例如:25,110", default='25,110')
@click.option("--ip_port", help="对特定的IP及端口进行测试，从文件加载，格式为:IP:端口", is_flag=True)
@click.option("-jp", "--jump_port", help="跳过主机发现", is_flag=True)
@click.option("-to", "--timeout", help="设置超时时间", default=1, show_default=True)
@click.option("-v", "--verbose", is_flag=True, help="显示详细信息")
@click.option("-t", "--threads", show_default=True, default=400, help="定义扫描的线程")
@click.option("--txt", help="定义输出文本文件", default='')
@click.option("--html", help="定义输出html文件", default='')
def click_main(ip, file, port, port_file, remove_port, ip_port, jump_port, timeout, verbose, threads, txt, html):
    click.echo(Fore.CYAN + '''
      _____                         _____           _    _____   
     / ____|                       |  __ \         | |  / ____|                
    | (___  _   _ _ __   ___ _ __  | |__) |__  _ __| |_| (___   ___ __ _ _ __  
     \___ \| | | | '_ \ / _ \ '__| |  ___/ _ \| '__| __|\___ \ / __/ _` | '_ \ 
     ____) | |_| | |_) |  __/ |    | |  | (_) | |  | |_ ____) | (_| (_| | | | |
    |_____/ \__,_| .__/ \___|_|    |_|   \___/|_|   \__|_____/ \___\__,_|_| |_|
                | |                                                           
                |_|                                       
                          Github: https://github.com/qianxiao996/Super-PortScan''')
    portscan = Portscan()
    # portscan.chuli_canshu('',file='C:\\Users\\qianxiao996\\Desktop\\1.txt',port='',port_file='',remove_port='25,110',ip_port=1,jump_port=1,timeout=3,verbose='1',threads=400,txt='aaw.txt',html='')

    portscan.chuli_canshu(ip, file, port, port_file, remove_port, ip_port, jump_port, timeout, verbose, threads, txt, html)


if __name__ == '__main__':
    click_main()








