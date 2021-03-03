#!/usr/bin/env python
# -*- coding: utf-8 -*-
from socket import *
import threading      #导入线程相关模块
import queue,os
import argparse,time
from color import *


html_head='''
<html>
<head>
    <title>Super-PortScan Sacn Result</title>
    <style type="text/css">
        /*表格样式*/			
        table {
            table-layout: fixed;
            word-break:break-all;
            width: 100%;
            background: #ccc;
            margin: 10px auto;
            border-collapse: collapse;
        }				
        th,td {
            text-align: center;
            border: 1px solid #ccc;
        }		
        th {
            background: #eee;
            font-weight: normal;
        }		
        tr {
            background: #fff;
        }		
        tr:hover {
            background: #cc0;
        }		
        td a {
            color: #06f;
            text-decoration: none;
        }		
        td a:hover {
            color: #06f;
            text-decoration: underline;
        }
    </style>
</head>
<body>
    <h2 align="center">Super-PortScan Sacn Result</h2>
    <table align="center">
    <thead>
        <tr>
            <th>IP地址</th>
            <th>端口</th>
            <th>状态</th>
            <th>Banner</th>
            <th>URL地址</th>
        </tr>
    </thead>
    <tbody>'''

def get_system():
    if os.name == 'nt':
        return 'n'
    else:
        return 'c'
#探测主机存活
def startPing(ip_str):
    # print(ip_str)
    a=0
    shell = ['ping','-{op}'.format(op=get_system()),'2',ip_str]
    output = os.popen(' '.join(shell)).readlines()
    for line in list(output):
        if not line:
            continue
        if str(line).upper().find('TTL') >= 0:
            # print("ip: %s is ok " % ip_str)
            a=1
            return a
        else:
            continue
    return a


#得到-d中的ip列表
def get_ip_d_list(ip):
    ip_list=[]
    if '/24' in ip:
        ip = ip.replace('/24','')
        for i in range(1,255):
            ip_list.append(ip[:ip.rfind('.')]+'.'+str(i))
    elif '-' in ip:
        ip_start = ip.split('.')[-1].split('-')[0]
        ip_end = ip.split('.')[-1].split('-')[1]
        if int(ip_start)>int(ip_end):
            numff =ip_start
            ip_start= ip_end
            ip_end = numff
        for i in range(int(ip_start), int(ip_end)+1):
            ip_list.append(ip[:ip.rfind('.')] + '.' + str(i))
    else:
        ip_list = ip.split()
    # 列表去重
    all_list = []
    for i in ip_list:
        if i not in all_list:
            all_list.append(i)
    return list(filter(None, all_list))  # 去除 none 和 空字符
#得到文件中的ip列表
def get_ip_f_list(file):
    all_list =[]
    if os.path.exists(file):
        try:
            file = open(file,'r',encoding= 'utf-8')
            for line in file:
                all_list =all_list+ get_ip_d_list(line)
            file.close()
            all_list2 = []
            for i in all_list:
                if i not in all_list2:
                    all_list2.append(i)
            return list(filter(None, all_list2))  # 去除 none 和 空字符
        except:
            printRed('Error:文件读取错误！')
    else:
        printRed('Error:文件不存在')
        exit()
#得到端口列表
def get_port_list(port):
    port_list=[]
    if ',' in port and '-' not in port:
        port_list = port.split(',').strip()
    elif ',' not in port and '-' in port:
        port_start = port.split('-')[0]
        port_end = port.split('-')[1]
        if int(port_start)>int(port_end):
            numff =port_start
            port_start= port_end
            port_end = numff
        for i in range(int(port_start), int(port_end)+1):
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
        if  int(i) > 65535:
            port_list.remove(i)
    port_list = diff_of_two_list(port_list,remove_port)
    # print(port_list)
    return port_list
#从list1排除list2
def diff_of_two_list(list1,list2):
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

def portScanner(portQueue,timeout):
    while True:
        if portQueue.empty():  # 队列空就结束
            break
        ip_port = portQueue.get()  # 从队列中取出
        host = ip_port.split(':')[0]
        port = ip_port.split(':')[1]
        # print(host,port)
        try:
            tcp = socket(AF_INET, SOCK_STREAM)
            tcp.settimeout(timeout)  # 如果设置太小，检测不精确，设置太大，检测太慢
            result = tcp.connect_ex((host, int(port)))  # 效率比connect高，成功时返回0，失败时返回错误码
            if result == 0:
                tcp.send("test".encode(encoding='utf-8'))
                try:
                    Banner = tcp.recv(60).decode("raw_unicode_escape")
                    # print(Banner)
                    # Banner = (str(Banner).strip('b\'').strip('\\n').strip('\\r').replace('"', '').strip('\''))
                except:
                    Banner = 'unknow'
                out_result(host,port,'opened',Banner)
                # printGreen(('[-] '+'%s\t%s\t')%(host.ljust(15, ' '),port.ljust(6, ' '))+('opened'.ljust(6, ' '))+('\t\t%s') % ( Banner.ljust(20, ' ')))
            else:
                if  flag:
                    out_result(host,port,'close',"None")
        except:
            if  flag:
                    out_result(host,port,'close',"None")
            continue
        finally:
            try:
                tcp.close()
            except:
                pass
def out_result(host,port,zhuangtai,Banner='None'):
    if out_txt!='':
        f=open(out_txt,"a")
        f.write(host+' '+port+' opened '+Banner+'\n')
        f.close
    if out_html !='':
        url_address = "http://"+host+':'+port
        if os.path.exists(out_html):
            f=open(out_html,"a")



            f.write('<tr><td>'+host+'</td><td>'+port+'</td><td>'+zhuangtai+'</td><td>'+Banner+'</td><td><a href="'+url_address+'" target="_blank">'+url_address+'</a></td></tr>\n')
            f.close
        else:
            # print(out_html)
            f2=open(out_html,"a")
            f2.write(html_head)
            # f2.write(host+' '+port+' opened '+Banner+'\n')
            f2.write('<tr><td>'+host+'</td><td>'+port+'</td><td>'+zhuangtai+'</td><td>'+Banner+'</td><td>'+url_address+'</td></tr>\n')
            f2.close
    if zhuangtai=='opened':
        printGreen(('[-] '+'%s\t%s\t')%(host.ljust(15, ' '),port.ljust(6, ' '))+('opened'.ljust(6, ' '))+('\t\t%s') % ( Banner.ljust(20, ' ')))
    else:
        printDarkGray(('[-] '+'%s\t%s\t')%(host.ljust(15, ' '),port.ljust(6, ' '))+('close'.ljust(6, ' '))+('\t\t%s') % ( "None".ljust(20, ' ')))


    #创建线程
def createThread(num,portQueue,timeout,threads):
    for i in range(num):
        i= threading.Thread(target=portScanner, args=(portQueue,timeout))
        threads.append(i)
def  scan(ip_list,port_list,threadNum):
    # print(port_list)
    # ip_list=['192.168.1.1','192.168.1.2']
    # port_list = [80, 25, 110]
    printSkyBlue('[*] 共扫描%s个IP,%s种端口,排除%s种端口,请稍后..'%(len(ip_list),len(port_list),len(remove_port)))
    printYellow('[*] The Scan is Start')
    for ip in ip_list:
        if(jp_flag==1):
            printYellow('[*] The '+ip+' is Start!')
            printSkyBlue('[*] '+'Host'.ljust(15,' ')+'\t'+'Port'.ljust(6,' ')+'\t'+'Status'.ljust(6,' ')+'\t\t'+'Banner'.ljust(20,' '))
            threads=[]#线程列表
            portQueue = queue.Queue()  # 待检测端口队列，会在《Python常用操作》一文中更新用法
            portQueue.queue.clear()
            for i in port_list:
                # print(port_list)
                portQueue.put(ip+':'+str(i))
            # print(portQueue.qsize())
            createThread(threadNum, portQueue,timeout,threads)
            # print(threads)
            for t in threads:#启动线程
                t.start()
            for t in threads:#阻塞线程，等待线程结束
                t.join()
                threads=[]
            printYellow('[*] The '+ip+' is complete!')
        else:
            if(startPing(ip)):
                printSkyBlue('[*] The '+ip+' is Up!')
                printSkyBlue('[*] '+'Host'.ljust(15,' ')+'\t'+'Port'.ljust(6,' ')+'\t'+'Status'.ljust(6,' ')+'\t\t'+'Banner'.ljust(20,' '))
                threads=[]#线程列表
                portQueue = queue.Queue()  # 待检测端口队列，会在《Python常用操作》一文中更新用法
                portQueue.queue.clear()
                for i in port_list:
                    # print(port_list)
                    portQueue.put(ip+':'+str(i))
                # print(portQueue.qsize())
                createThread(threadNum, portQueue,timeout,threads)
                # print(threads)
                for t in threads:#启动线程
                    t.start()
                for t in threads:#阻塞线程，等待线程结束
                    t.join()
                    threads=[]
                printYellow('[*] The '+ip+' is complete!')
            else:
                printDarkGray('[*] '+ip+' is down!')

       
    printYellow('[*] The Scan is complete!')


if __name__ == '__main__':
    printDarkSkyBlue('''
   _____                         _____           _    _____   
  / ____|                       |  __ \         | |  / ____|                
 | (___  _   _ _ __   ___ _ __  | |__) |__  _ __| |_| (___   ___ __ _ _ __  
  \___ \| | | | '_ \ / _ \ '__| |  ___/ _ \| '__| __|\___ \ / __/ _` | '_ \ 
  ____) | |_| | |_) |  __/ |    | |  | (_) | |  | |_ ____) | (_| (_| | | | |
 |_____/ \__,_| .__/ \___|_|    |_|   \___/|_|   \__|_____/ \___\__,_|_| |_|
             | |                                                           
             |_|                                       
                       github: https://github.com/qianxiao996/Super-PortScan''')
    flag = 0  # 是否显示过程
    jp_flag=0 #跳过主机发现
    remove_port=[25,110] #排除的端口
    out_txt=''#输出txt文件
    out_html=''
    all_port_list = [21,22,23,25,53,53,80,81,110,111,123,123,135,137,139,161,389,443,445,465,500,515,520,523,548,623,636,873,902,1080,1099,1433,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,7001,7077,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8080,8081,8443,8545,8686,9000,9042,9092,9100,9200,9418,9999,11211,15210,27017,37777,33899,33889,50000,50070,61616]
    parser = argparse.ArgumentParser(usage='\n\tpython3 Super-PortScan.py -i 192.168.1.1 -p 80\n\tpython3 Super-PortScan.py -f ip.txt -p 80')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--ip" ,help="输入一个或一段ip，例如：192.168.1.1、192.168.1.1/24、192.168.1.1-99")
    group.add_argument("-f", "--file",help="从文件加载ip列表")
    parser.add_argument("-p", "--port", help="定义扫描的端口，例如:80、80,8080、80-8000")
    parser.add_argument("-rp",help="定义排除的端口，例如:25,110")
    parser.add_argument("-jp",action="store_true",help="跳过主机发现")
    parser.add_argument("-ts",help="设置超时时间，默认0.5s")
    parser.add_argument("-v", action="store_true",help="显示所有扫描结果")
    parser.add_argument("-t", "--threads", help="定义扫描的线程，默认为3000")
    parser.add_argument("--txt", help="定义输出文本文件")
    parser.add_argument("--html",help="定义输出html文件")
    
    args = parser.parse_args()
    if args.v:
        flag=1
    if args.jp:
        jp_flag=1
    if args.txt:
        out_txt=args.txt
    if args.html:
        out_html=args.html

    if args.ts:
        timeout=int(args.ts)
    else:
        timeout=0.5
    if args.rp:
        remove_port_temp = (args.rp).split(",")
        remove_port.extend(remove_port_temp)
        # print(remove_port)
    if args.ip:
        if  args.port :
            port_list = get_port_list(args.port)
        if not args.port:
            port_list = diff_of_two_list(all_port_list,remove_port)
        ip_list =  get_ip_d_list(args.ip)
        if args.threads:
            scan(ip_list,port_list,int(args.threads))
        else:
            scan(ip_list,port_list,30)
        # for i in ip_list:
        #     scan(i, port_list, threadNum)
    if args.file:
        if  args.port :
            port_list = get_port_list(args.port)
        if not args.port:
            port_list = diff_of_two_list(all_port_list,remove_port)
        ip_list =  get_ip_f_list(args.file)
        if args.threads:
            scan(ip_list,port_list,int(args.threads))
        else:
            scan(ip_list, port_list, 3000)

