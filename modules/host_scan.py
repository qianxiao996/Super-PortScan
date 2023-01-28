import os
import queue
import threading
from random import randint

from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.l2 import Ether, ARP
from scapy.all import *

ipQueue = queue.Queue()
#返回结果格式 探测方式|IP地址|存活1 不存活0
cunhuo_ip_list=[]
def ip_main(ip_list,threads):
    for ip in ip_list:
        ipQueue.put(ip)
    ip_threads = []
    if threads > ipQueue.qsize():
        ip_threads_num = ipQueue.qsize()
    else:
        ip_threads_num = threads
    for i in range(int(ip_threads_num)):
        i = threading.Thread(target=ipScanner, args=())
        ip_threads.append(i)
    for i in ip_threads:
        i.start()
    for j in ip_threads:
        j.join()
    cunhuo_ip_list.append('End|End|End')
    return  cunhuo_ip_list

def ipScanner():
    while True:
        if ipQueue.empty():  # 队列空就结束
            break
        ip = ipQueue.get()  # 从队列中取出
        try:
            if ip[:2]=='10.' or ip[:3]=='172.' or ip[:3]=='192.':
                scapy_arp_scan(ip)
            else:
                startPing(ip)
        except:
            startPing(ip)
#arp探测主机存活
def scapy_arp_scan(ip):
    # for ipFix in range(1, 255 + 1):
    # 构造本网段的ip。如：192.168.50.20
    # 组合协议包
    # 通过 '/' 可叠加多个协议层(左底层到右上层)，如Ether()/IP()/UDP()/DNS()
    try:
        arpPkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        # 发送arp请求，并获取响应结果。设置1s超时。
        res = srp1(arpPkt, timeout=0.5, verbose=0)
        # 如果ip存活
        if res:
            # print("[*] [ARP]IP:" + ip + " is alive\n", end="")
            cunhuo_ip_list.append('ARP|'+ip+'|1')
            return
        # 如果ip不存活
        else:
            scapy_ping_scan(ip)
    except:
        scapy_ping_scan(ip)
#ping探测主机存活
def scapy_ping_scan(host):
    try:
        id_ip = randint(1, 65535)
        id_ping = randint(1, 65535)
        seq_ping = randint(1, 65535)
        packet = IP(dst=host, ttl=128, id=id_ip) / ICMP(id=id_ping, seq=seq_ping) / b'hi! I am qianxiao996'
        ping = sr1(packet, timeout=0.5, verbose=False)
        if ping:
            cunhuo_ip_list.append('ICMP|'+host+'|1')
            return
        else:
            scapy_tcp_scan(host)
    except:
        scapy_tcp_scan(host)

def scapy_tcp_scan(ip):
    try:
        packet = IP(dst=ip) / TCP(dport=22, flags="A")  # 构造标志位为syn的数据包
        result = sr1(packet, timeout=0.5, verbose=0)
        if int(result[TCP].flags) == 4:
            cunhuo_ip_list.append('TCP|' + ip + '|1')
            # 注意这里如果使用+号进行字符串拼接的话会导致报错，使用逗号即可拼接
            return
        else:
            scapy_udp_scan(ip)
    except:
        scapy_udp_scan(ip)
def scapy_udp_scan(ip):
    try:  # 端口要求一定是没开放
        packet = IP(dst=ip) / UDP(dport=52249)
        result = sr1(packet, timeout=0.5, verbose=0)
        # result.show()
        if int(result[IP].proto) == 0x01:  # 0x01 代表的ICMP字段值
            cunhuo_ip_list.append('UDP|' + ip + '|1')
            return
        else:
            startPing(ip)
    except:
        startPing(ip)
        return
# ping探测主机存活
def startPing(ip_str):
    # print(ip_str)
    shell = ['ping', '-{op}'.format(op=get_system()), '2', ip_str]
    output = os.popen(' '.join(shell)).readlines()
    for line in list(output):
        if not line:
            continue
        if str(line).upper().find('TTL') >= 0:
            # print("ip: %s is ok " % ip_str)
            cunhuo_ip_list.append('ICMP|'+ip_str+'|1')
            return
        else:
            continue
    cunhuo_ip_list.append('ALL|' + ip_str + '|0')

def get_system():
    if os.name == 'nt':
        return 'n'
    else:
        return 'c'

if __name__ == '__main__':
    ip_list=['127.0.0.1','129.204.113.202']
    result = ip_main(ip_list,5)
    print(result)
