#!/usr/bin/env python
# -*- coding: utf-8 -*-
import html
from socket import *
import threading      #导入线程相关模块
import queue,os,requests
import re,sys
from colorama import init, Fore
import click
import eventlet
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp1
from tqdm import tqdm
import ipaddr
requests.packages.urllib3.disable_warnings()
init(autoreset=True)    #  初始化，并且设置颜色设置自动恢复
# print(Fore.CYAN+'''
# _____                         _____           _    _____   
# / ____|                       |  __ \         | |  / ____|                
# | (___  _   _ _ __   ___ _ __  | |__) |__  _ __| |_| (___   ___ __ _ _ __  
# \___ \| | | | '_ \ / _ \ '__| |  ___/ _ \| '__| __|\___ \ / __/ _` | '_ \ 
# ____) | |_| | |_) |  __/ |    | |  | (_) | |  | |_ ____) | (_| (_| | | | |
# |_____/ \__,_| .__/ \___|_|    |_|   \___/|_|   \__|_____/ \___\__,_|_| |_|
#         | |                                                           
#         |_|                                       
#                 github: https://github.com/qianxiao996/Super-PortScan''')

lock = threading.Lock() #申请一个锁
# scan(['blog.qianxiao996.cn','129.204.113.202'], [443,80,8081], 22,1)


signs_rules=[
'http|^HTTP.*',
'ssh|SSH-2.0-OpenSSH.*',
'ssh|SSH-1.0-OpenSSH.*',
'netbios|^\x79\x08.*BROWSE',
'netbios|^\x79\x08.\x00\x00\x00\x00',
'netbios|^\x05\x00\x0d\x03',
'netbios|^\x83\x00',
'netbios|^\x82\x00\x00\x00',
'netbios|\x83\x00\x00\x01\x8f',
'backdoor-fxsvc|^500 Not Loged in',
'backdoor-shell|GET: command',
'backdoor-shell|sh: GET:',
'bachdoor-shell|[a-z]*sh: .* command not found',
'backdoor-shell|^bash[$#]',
'backdoor-shell|^sh[$#]',
'backdoor-cmdshell|^Microsoft Windows .* Copyright .*>',
'db2|.*SQLDB2RA',
'dell-openmanage|^\x4e\x00\x0d',
'finger|^\r\n	Line	  User',
'finger|Line	 User',
'finger|Login name: ',
'finger|Login.*Name.*TTY.*Idle',
'finger|^No one logged on',
'finger|^\r\nWelcome',
'finger|^finger:',
'finger|^must provide username',
'finger|finger: GET: ',
'ftp|^220.*\n331',
'ftp|^220.*\n530',
'ftp|^220.*FTP',
'ftp|^220 .* Microsoft .* FTP',
'ftp|^220 Inactivity timer',
'ftp|^220 .* UserGate',
'http|^HTTP/0.',
'http|^HTTP/1.',
'http|<HEAD>.*<BODY>',
'http|<HTML>.*',
'http|<html>.*',
'http|<!DOCTYPE.*',
'http|^Invalid requested URL ',
'http|.*<?xml',
'http|^HTTP/.*\nServer: Apache/1',
'http|^HTTP/.*\nServer: Apache/2',
'http-iis|.*Microsoft-IIS',
'http-iis|^HTTP/.*\nServer: Microsoft-IIS',
'http-iis|^HTTP/.*Cookie.*ASPSESSIONID',
'http-iis|^<h1>Bad Request .Invalid URL.</h1>',
'http-jserv|^HTTP/.*Cookie.*JServSessionId',
'http-tomcat|^HTTP/.*Cookie.*JSESSIONID',
'http-weblogic|^HTTP/.*Cookie.*WebLogicSession',
'http-vnc|^HTTP/.*VNC desktop',
'http-vnc|^HTTP/.*RealVNC/',
'ldap|^\x30\x0c\x02\x01\x01\x61',
'ldap|^\x30\x32\x02\x01',
'ldap|^\x30\x33\x02\x01',
'ldap|^\x30\x38\x02\x01',
'ldap|^\x30\x84',
'ldap|^\x30\x45',
'smb|^\0\0\0.\xffSMBr\0\0\0\0.*',
'msrdp|^\x03\x00\x00\x0b',
'msrdp|^\x03\x00\x00\x11',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x12.\0$',
'msrdp|^\x03\0\0\x17\x08\x02\0\0Z~\0\x0b\x05\x05@\x06\0\x08\x91J\0\x02X$',
'msrdp|^\x03\0\0\x11\x08\x02..}\x08\x03\0\0\xdf\x14\x01\x01$',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\x03.\0$',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\0\0\0\0',
'msrdp|^\x03\0\0\x0e\t\xd0\0\0\0[\x02\xa1]\0\xc0\x01\n$',
'msrdp|^\x03\0\0\x0b\x06\xd0\0\x004\x12\0',
'msrdp-proxy|^nmproxy: Procotol byte is not 8\n$',
'msrpc|^\x05\x00\x0d\x03\x10\x00\x00\x00\x18\x00\x00\x00\x00\x00',
'msrpc|\x05\0\r\x03\x10\0\0\0\x18\0\0\0....\x04\0\x01\x05\0\0\0\0$',
'mssql|^\x04\x01\0C..\0\0\xaa\0\0\0/\x0f\xa2\x01\x0e.*',
'mssql|^\x05\x6e\x00',
'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\x00\x25\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\x00.\x00\x00\x01\x00\x00\x00\x15.*',
'mssql|^\x04\x01\0\x25\0\0\x01\0\0\0\x15\0\x06\x01.*',
'mssql|^\x04\x01\x00\x25\x00\x00\x01.*',
'telnet|^xff\xfb\x01\xff\xfb\x03\xff\xfb\0\xff\xfd.*',
'mssql|;MSSQLSERVER;',
'mysql|.*mysql.*',
'mysql|.*mysql_native_password.*/g',
'mysql|^\x19\x00\x00\x00\x0a',
'mysql|^\x2c\x00\x00\x00\x0a',
'mysql|hhost \'',
'mysql|khost \'',
'mysql|mysqladmin',
'mysql|whost \'',
'mysql-blocked|^\(\x00\x00',
'mysql-secured|this MySQL',
'mongodb|^.*version.....([\.\d]+)',
'nagiosd|Sorry, you \(.*are not among the allowed hosts...',
'nessus|< NTP 1.2 >\x0aUser:',
'oracle-tns-listener|\(ERROR_STACK=\(ERROR=\(CODE=',
'oracle-tns-listener|\(ADDRESS=\(PROTOCOL=',
'oracle-dbsnmp|^\x00\x0c\x00\x00\x04\x00\x00\x00\x00',
'oracle-https|^220- ora',
'oracle-rmi|\x00\x00\x00\x76\x49\x6e\x76\x61',
'oracle-rmi|^\x4e\x00\x09',
'postgres|Invalid packet length',
'postgres|^EFATAL',
'rlogin|login: ',
'rlogin|rlogind: ',
'rlogin|^\x01\x50\x65\x72\x6d\x69\x73\x73\x69\x6f\x6e\x20\x64\x65\x6e\x69\x65\x64\x2e\x0a',
'rpc-nfs|^\x02\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00',
'rpc|\x01\x86\xa0',
'rpc|\x03\x9b\x65\x42\x00\x00\x00\x01',
'rpc|^\x80\x00\x00',
'rsync|^@RSYNCD:.*',
'smux|^\x41\x01\x02\x00',
'snmp-public|\x70\x75\x62\x6c\x69\x63\xa2',
'snmp|\x41\x01\x02',
'socks|^\x05[\x00-\x08]\x00',
'ssh|^SSH-',
'ssh|^SSH-.*openssh',
'ssl|^..\x04\0.\0\x02',
'ssl|^\x16\x03\x01..\x02...\x03\x01',
'ssl|^\x16\x03\0..\x02...\x03\0',
'ssl|SSL.*GET_CLIENT_HELLO',
'ssl|-ERR .*tls_start_servertls',
'ssl|^\x16\x03\0\0J\x02\0\0F\x03\0',
'ssl|^\x16\x03\0..\x02\0\0F\x03\0',
'ssl|^\x15\x03\0\0\x02\x02\.*',
'ssl|^\x16\x03\x01..\x02...\x03\x01',
'ssl|^\x16\x03\0..\x02...\x03\0',
'sybase|^\x04\x01\x00',
'telnet|^\xff\xfd',
'telnet|Telnet is disabled now',
'telnet|^\xff\xfe',
'tftp|^\x00[\x03\x05]\x00',
'http-tomcat|.*Servlet-Engine',
'uucp|^login: password: ',
'vnc|^RFB.*',
'webmin|.*MiniServ',
'webmin|^0\.0\.0\.0:.*:[0-9]',
'websphere-javaw|^\x15\x00\x00\x00\x02\x02\x0a']



PROBES=[
'\r\n\r\n',
'GET / HTTP/1.0\r\n\r\n',
'GET / \r\n\r\n',
'\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08',
'\x80\0\0\x28\x72\xFE\x1D\x13\0\0\0\0\0\0\0\x02\0\x01\x86\xA0\0\x01\x97\x7C\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
'\x03\0\0\x0b\x06\xe0\0\0\0\0\0',
'\0\0\0\xa4\xff\x53\x4d\x42\x72\0\0\0\0\x08\x01\x40\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x40\x06\0\0\x01\0\0\x81\0\x02PC NETWORK PROGRAM 1.0\0\x02MICROSOFT NETWORKS 1.03\0\x02MICROSOFT NETWORKS 3.0\0\x02LANMAN1.0\0\x02LM1.2X002\0\x02Samba\0\x02NT LANMAN 1.0\0\x02NT LM 0.12\0',
'\x80\x9e\x01\x03\x01\x00u\x00\x00\x00 \x00\x00f\x00\x00e\x00\x00d\x00\x00c\x00\x00b\x00\x00:\x00\x009\x00\x008\x00\x005\x00\x004\x00\x003\x00\x002\x00\x00/\x00\x00\x1b\x00\x00\x1a\x00\x00\x19\x00\x00\x18\x00\x00\x17\x00\x00\x16\x00\x00\x15\x00\x00\x14\x00\x00\x13\x00\x00\x12\x00\x00\x11\x00\x00\n\x00\x00\t\x00\x00\x08\x00\x00\x06\x00\x00\x05\x00\x00\x04\x00\x00\x03\x07\x00\xc0\x06\x00@\x04\x00\x80\x03\x00\x80\x02\x00\x80\x01\x00\x80\x00\x00\x02\x00\x00\x01\xe4i<+\xf6\xd6\x9b\xbb\xd3\x81\x9f\xbf\x15\xc1@\xa5o\x14,M \xc4\xc7\xe0\xb6\xb0\xb2\x1f\xf9)\xe8\x98',
'\x16\x03\0\0S\x01\0\0O\x03\0?G\xd7\xf7\xba,\xee\xea\xb2`~\xf3\0\xfd\x82{\xb9\xd5\x96\xc8w\x9b\xe6\xc4\xdb<=\xdbo\xef\x10n\0\0(\0\x16\0\x13\0\x0a\0f\0\x05\0\x04\0e\0d\0c\0b\0a\0`\0\x15\0\x12\0\x09\0\x14\0\x11\0\x08\0\x06\0\x03\x01\0',
'< NTP/1.2 >\n',
'< NTP/1.1 >\n',
'< NTP/1.0 >\n',
'\0Z\0\0\x01\0\0\0\x016\x01,\0\0\x08\0\x7F\xFF\x7F\x08\0\0\0\x01\0 \0:\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\04\xE6\0\0\0\x01\0\0\0\0\0\0\0\0(CONNECT_DATA=(COMMAND=version))',
'\x12\x01\x00\x34\x00\x00\x00\x00\x00\x00\x15\x00\x06\x01\x00\x1b\x00\x01\x02\x00\x1c\x00\x0c\x03\x00\x28\x00\x04\xff\x08\x00\x01\x55\x00\x00\x00\x4d\x53\x53\x51\x4c\x53\x65\x72\x76\x65\x72\x00\x48\x0f\x00\x00',
'\0\0\0\0\x44\x42\x32\x44\x41\x53\x20\x20\x20\x20\x20\x20\x01\x04\0\0\0\x10\x39\x7a\0\x01\0\0\0\0\0\0\0\0\0\0\x01\x0c\0\0\0\0\0\0\x0c\0\0\0\x0c\0\0\0\x04',
'\x01\xc2\0\0\0\x04\0\0\xb6\x01\0\0\x53\x51\x4c\x44\x42\x32\x52\x41\0\x01\0\0\x04\x01\x01\0\x05\0\x1d\0\x88\0\0\0\x01\0\0\x80\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x08\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x01\0\0\x40\0\0\0\x40\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x04\0\0\0\x02\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x80\0\0\0\x01\x08\0\0\0\x01\0\0\x40\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x10\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x04\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x40\0\0\0\x01\x09\0\0\0\x01\0\0\x80\0\0\0\x01\x04\0\0\0\x03\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\x01\x04\0\0\x01\0\0\x80\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x40\0\0\0\x01\0\0\0\0\x01\0\0\x40\0\0\0\0\x20\x20\x20\x20\x20\x20\x20\x20\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\xff\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\xe4\x04\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x7f',
'\x41\0\0\0\x3a\x30\0\0\xff\xff\xff\xff\xd4\x07\0\0\0\0\0\0test.$cmd\0\0\0\0\0\xff\xff\xff\xff\x1b\0\0\0\x01serverStatus\0\0\0\0\0\0\0\xf0\x3f\0'
]



html_head='''
<html>
<head>
    <title>Super-PortScan Sacn Result</title>
    <link rel="stylesheet" href="http://cdn.datatables.net/1.10.21/css/jquery.dataTables.min.css">
    <script src="http://libs.baidu.com/jquery/2.0.0/jquery.min.js"></script>
    <script src="http://cdn.datatables.net/1.10.21/js/jquery.dataTables.min.js"></script>
    <script src="https://cdn.jsdelivr.net/gh/rainabba/jquery-table2excel@master/src/jquery.table2excel.js"></script>
    


    <style type="text/css">
        /*表格样式*/			
        table {
            /*table-layout: fixed;*/
            /* word-break:break-all; */
            width: 80%;
            margin: 10px auto;
            border-collapse: collapse;
        }				
        th,td {
            text-align: center;
            border: 1px solid #ccc;
        }		
        th {
            min-width:50px;
            font-weight: normal;
            color:white;
            background-color: rgb(8, 103, 193);
            padding: 0.5em;
        }	
        td{
            min-width:50px;
            font-weight: normal;
            /* text-align: left; */
            padding: 0.5em;
        }	
        table tbody tr td a {
            color: #06f;
            text-decoration: none;
        }	
        	
        table tbody tr td a:visited
        {
            color:	green;
            text-decoration: none;

        }
        table tbody tr:nth-child(odd) {
             /* 匹配奇数行 */
            background-color: #F1F1F1  ;
            color: black;
        }

        table tbody tr:nth-child(even) {
            /* 匹配偶数行 */
            background-color:white ;
            color: black;
        }
        
    </style>
</head>
<body style="margin:0px;background-color:#F0F2F5">
    <div style="position: fixed;background: rgb(8, 103, 193);width:100%; z-index:9999">
        <p  style="color:white;width: 100%;height: 20px;display: block;line-height: 20px;text-align: center;">Super-PortScan Sacn Result</p>
    </div>
    <div style="padding-top:70px;padding-bottom:0px;padding-left:80px;padding-right:80px">
        <table id="table" align="center">
        </table>
    </div>
</body>
</html>
<script>

    $("#table").dataTable({
         //lengthMenu: [5, 10, 20, 30],//这里也可以设置分页，但是不能设置具体内容，只能是一维或二维数组的方式，所以推荐下面language里面的写法。
        destroy:true,
        "autoWidth": false,
        paging: true,//分页
        ordering: true,//是否启用排序
        searching: true,//搜索
        language: {
            lengthMenu: '<select class="form-control input-xsmall">' + '<option value="1">1</option>' + '<option value="10">10</option>' + '<option value="20">20</option>' + '<option value="50">50</option>' + '<option value="100">100</option>' + '<option value="200">200</option>'  + '<option value="500">500</option>'  + '<option value="1000">1000</option>' + '<option value="5000">5000</option>' + '</select>条记录',//左上角的分页大小显示。
            search: '<button onclick="exportCsv()" style="margin:2px 30px">导出CSV</button><span class="label label-success" style="">搜索:</span>',//右上角的搜索文本，可以写html标签
            
            paginate: {//分页的样式内容。
                previous: "上一页",
                next: "下一页",
                first: "第一页",
                last: "最后"
            },

            zeroRecords: "无扫描结果",//table tbody内容为空时，tbody的内容。
            //下面三者构成了总体的左下角的内容。
            info: "总共_PAGES_ 页，显示第_START_ 到第 _END_ ，筛选之后得到 _TOTAL_ 条，初始_MAX_ 条 ",//左下角的信息显示，大写的词为关键字。
            infoEmpty: "0条记录",//筛选为空时左下角的显示。
            infoFiltered: ""//筛选之后的左下角筛选提示，
        },
        paging: true,
        pagingType: "full_numbers",//分页样式的类型


        columns: [
        { title: "IP地址", sortable: true },
        { title: "端口", sortable: true },
        { title: "状态", sortable: true },
        { title: "服务", sortable: true },
        { title: "Banner", sortable: true },
        { title: "URL地址", sortable: true, render: function(data, type, row) { return '<a  href="'+data+'" target="_blank">' + data + '</a>'; }},
    ]       

    });
    $("#table_local_filter input[type=search]").css({ width: "auto" });//右上角的默认搜索文本框，不写这个就超出去了。
    $('#table').on( 'click', 'tr', function () {
        var table = $('#table').DataTable();
        // var id = table.row(this).row();
        var background = $(this).css('backgroundColor');
        // console.log(background);
        
        if(background=="rgb(216, 191, 216)")
        {
            $(this).css("background","white");
        }
        else
        {
            $(this).css("background","rgb(216, 191, 216)");
        }

        // alert( '被点击行的id是 '+id );
    } );

    function add_table(ip,port,flag,service,banner,url){
        var t = $('#table').DataTable();
        t.row.add( [ip,port,flag,service,banner,url
        ] ).draw( false );
    }


    
    function exportCsv() {
            $("#table").table2excel({
                exclude: ".noExl",
                name: "Excel Document Name",
                // Excel文件的名称
                filename: "Super-PortScan Sacn Result",
                exclude_img: true,
                exclude_links: true,
                exclude_inputs: true
            });
        }

        
</script>
'''

class Portscan:
    def __init__(self):
        self.portQueue = queue.Queue()
        self.ipQueue = queue.Queue()
        self.flag = 0  # 是否显示过程
        self.jp_flag = 0  # 跳过主机发现
        self.out_txt = ''  # 输出txt文件
        self.out_html = ''
        self.all_remove_port = []  # 排除的端口
        self.all_port_list = [21, 22, 23, 25, 53, 53, 80, 81, 110, 111, 123, 123, 135, 137, 139, 161, 389, 443, 445, 465,
                         500, 515, 520, 523, 548, 623, 636, 873, 902, 1080, 1099, 1433, 1521, 1604, 1645, 1701, 1883,
                         1900, 2049, 2181, 2375, 2379, 2425, 3128, 3306, 3389, 4730, 5060, 5222, 5351, 5353, 5432, 5555,
                         5601, 5672, 5683, 5900, 5938, 5984, 6000, 6379, 7001, 7077, 8001, 8002, 8003, 8004, 8005, 8006,
                         8007, 8008, 8009, 8010, 8080, 8081, 8443, 8545, 8686, 9000, 9042, 9092, 9100, 9200, 9418, 9999,
                         11211, 15210, 27017, 37777, 33899, 33889, 50000, 50070]
        self.ip_1_list=[] #存放存活的ip
        self.ip_2_list = []  # ip:port 模式存放列表
    def chuli_canshu(self,ip,file,port,port_file,remove_port,ip_port,jump_port,timeout,verbose,threads,txt,html):
        try:
            if verbose:
                self.flag=1
            if jump_port:
                self.jp_flag=1
            if txt:
                self.out_txt=txt
            if html:
                self.out_html=html

            if timeout:
                timeout=int(timeout)
            else:
                timeout=1
                # print(remove_port)
            if  port :
                self.all_port_list  = self.get_port_list(port)
            elif port_file:
                self.all_port_list  = self.get_port_file_list(port_file)
            else:
                self.all_port_list  = self.diff_of_two_list(self.all_port_list,self.all_remove_port)
            if remove_port:
                remove_port_temp = (remove_port).split(",")
                # print(type(remove_port_temp))
                self.all_remove_port.extend(remove_port_temp)
            ip_list=[]
            if ip and file:
                click.echo(Fore.RED+"[E] 不能同时输入IP和文件参数！")
                sys.exit()
            if (port and ip_port) or (port_file and ip_port):
                click.echo(Fore.RED + "[E] IP对应端口探测模式不允许指定-p参数！")
                sys.exit()
            #ip:port模式
            if ip_port:
                if ip:
                    self.ip_2_list.append(ip)
                elif file:
                    if os.path.exists(file):
                        try:
                            all_list=[]
                            file = open(file, 'r', encoding='utf-8')
                            for line in file:
                                all_list.append(line.strip())
                            file.close()
                            self.ip_2_list=list(filter(None, all_list))  # 去除 none 和 空字符
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
                    if len(ip.split(":"))==2:
                        self.ip_2_list.append(ip)
                        if len(self.ip_2_list) > 0:
                            self.ip_port_scan(int(threads), timeout)
                        else:
                            print(Fore.YELLOW + "[*] NO IP")
                        sys.exit()
                    else:
                        print(Fore.BLUE + "[*] GET IP...")
                        ip_list =  self.get_ip_d_list(ip)
                        print(Fore.BLUE + "[*] IP Num:%s"%len(ip_list))
                elif file:
                    ip_list =  self.get_ip_f_list(file)
                else:
                    return
                if (self.jp_flag == 1):
                    self.ip_1_list = ip_list
                else:
                    try:
                        print(Fore.BLUE + "[*] Start survival detection")
                        for ip in ip_list:
                            self.ipQueue.put(ip)
                        ip_threads=[]
                        if threads>self.ipQueue.qsize():
                            ip_threads_num=self.ipQueue.qsize()
                        else:
                            ip_threads_num=threads
                        for i in range(int(ip_threads_num)):

                            i = threading.Thread(target=self.ipScanner, args=())
                            ip_threads.append(i)
                        for i in ip_threads:
                            i.start()
                        for j in ip_threads:
                            j.join()
                            # 开始扫描
                    except KeyboardInterrupt:
                        self.ipQueue.queue.clear()
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
            print(Fore.RED+str(e)+str(e.__traceback__.tb_lineno)+'行')
            print(Fore.RED+'参数输入错误！')
    def ipScanner(self):
        while True:
            if self.ipQueue.empty():  # 队列空就结束
                break
            ip= self.ipQueue.get()  # 从队列中取出
            try:
                result = self.arp_scan(ip)
                if result:
                    print(Fore.YELLOW + "[*] [ARP]IP:" + ip + " is alive\n", end="")
                    self.ip_1_list.append(ip)
                else:
                    if (self.startPing(ip)):
                        print(Fore.YELLOW + "[*] [ICMP]IP:" + ip + " is alive\n", end="")
                        self.ip_1_list.append(ip)
            except:

                if (self.startPing(ip)):
                    print(Fore.YELLOW + "[*] [ICMP]IP:" + ip + " is alive\n", end="")
                    self.ip_1_list.append(ip)


    def arp_scan(self,ip):

        for ipFix in range(1, 255 + 1):
            # 构造本网段的ip。如：192.168.50.20

            # 组合协议包
            # 通过 '/' 可叠加多个协议层(左底层到右上层)，如Ether()/IP()/UDP()/DNS()
            arpPkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            # 发送arp请求，并获取响应结果。设置1s超时。
            res = srp1(arpPkt, timeout=1, verbose=0)

            # 如果ip存活
            if res:
                return  1

            # 如果ip不存活
            else:
                return  0


    def get_system(self):
        if os.name == 'nt':
            return 'n'
        else:
            return 'c'
    #探测主机存活
    def startPing(self,ip_str):
        # print(ip_str)
        a=0
        shell = ['ping','-{op}'.format(op=self.get_system()),'2',ip_str]
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
    def get_ip_d_list(self,ip):
        ip_list=[]
        #127.0.0.1/24匹配
        remath_1 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/([1-9]|[1-2]\d|3[0-2])$'
        re_result1 =  re.search(remath_1,ip,re.I|re.M)
        #127.0.0.1-222匹配
        remath_2 = r'^(?:(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\-(25[0-5]|2[0-4][0-9]|[0-1]?[0-9]?[0-9])$'
        re_result2 =  re.search(remath_2,ip,re.I|re.M)
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
                print(Fore.RED+'Error:IP段设置错误！')
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
            if int(ip_start)>int(ip_end):
                numff =ip_start
                ip_start= ip_end
                ip_end = numff
            for i in range(int(ip_start), int(ip_end)+1):
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
    #得到文件中的ip列表
    def get_ip_f_list(self,file):
        all_list =[]
        if os.path.exists(file):
            try:
                file = open(file,'r',encoding= 'utf-8')
                for line in file:
                    all_list =all_list+  self.get_ip_d_list(line)
                file.close()
                # all_list2 = []
                # for i in all_list:
                #     if i not in all_list2:
                #         all_list2.append(i)
                return list(filter(None, all_list))  # 去除 none 和 空字符
            except:
                print(Fore.RED+'Error:文件读取错误！')
                sys.exit()
        else:
            print(Fore.RED+'Error:文件不存在')
            sys.exit()
    #得到端口列表
    def get_port_list(self,port):
        port_list=[]
        if ',' in port and '-' not in port:
            port_list = port.strip().split(',')
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
        port_list = self.diff_of_two_list(port_list,self.all_remove_port)
        # print(port_list)
        return port_list
    def get_port_file_list(self,port_file_path):
            
        try:
            if os.path.exists(port_file_path):
                file_cls = open(port_file_path,'r',encoding= 'utf-8')
                data = file_cls.read()
                try:
                    port_list = data.split(',')
                    for i in port_list:
                        try:    
                            if  int(i) > 65535:
                                port_list.remove(i)
                        except:
                            port_list.remove(i)
                except:
                    print(Fore.RED+'Error:端口文件读取错误！')
                port_list = self.diff_of_two_list(port_list,self.all_remove_port)
                return port_list
            else:
                print(Fore.RED+'Error:端口文件不存在！')
        except:
            print(Fore.RED+'Error:文件读取错误！')

    #从list1排除list2
    def diff_of_two_list(self,list1,list2):
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

    def portScanner(self,timeout,pbar,list_type):
        while True:
            try:
                # tqdm.write(str(self.portQueue.qsize()))
                if self.portQueue.qsize()==0 and  list_type=='1' and len(self.ip_1_list)>0:
                    for i in self.all_port_list :
                        # print(port_list)
                        self.portQueue.put(self.ip_1_list[0]+':'+str(i))
                    del(self.ip_1_list[0])
                elif self.portQueue.qsize() == 0 and list_type =='2' and len(self.ip_2_list)>0:
                    self.portQueue.put(self.ip_2_list[0])
                    del(self.ip_2_list[0])
                else:
                    Banner=''
                    title=''
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(60, False):
                        if self.portQueue.empty():  # 队列空就结束
                            break
                        ip_port = self.portQueue.get().split(":")  # 从队列中取出
                        if len(ip_port)==2:
                            host = ip_port[0]
                            port = ip_port[1]
                        else:
                            host = ip_port[0]
                            port=80
                        pbar.set_description(Fore.BLUE+'[*] Scanning:'+host+' '+port)  # 修改进度条描述
                        pbar.update(1)
                        # print(host,port)
                        try:
                            tcp = socket(AF_INET, SOCK_STREAM)
                            tcp.settimeout(int(timeout))  # 如果设置太小，检测不精确，设置太大，检测太慢
                            # print(host,port)
                            result = tcp.connect_ex((host, int(port)))  # 效率比connect高，成功时返回0，失败时返回错误码
                            # print(port+"success")
                            if result == 0:
                                url_address=''
                                tcp.send("test".encode(encoding='gbk'))
                                try:
                                    #Banner = tcp.recv(100).decode("raw_unicode_escape")
                                    Banner = tcp.recv(100)
                                    try:
                                        Banner = Banner.decode("gbk")
                                    except:
                                        # print(str(Banner.decode("raw_unicode_escape").strip().encode("utf-8")))
                                        Banner=str(Banner.decode("raw_unicode_escape").strip().encode("utf-8"))
                                    # Banner = tcp.recv(100)
                                    # print(str(Banner)[2:-1])
                                    # print(Banner)

                                    Banner=str(Banner[2:-1])
                                    service=self.matchbanner(Banner,signs_rules)
                                    if service=="Unknown":
                                        return_Data  = self.scanservice(host, port,timeout)
                                        service = return_Data[0]
                                        if return_Data[1]!='':
                                            Banner =return_Data[1]
                                        if return_Data[2]:
                                            title =return_Data[2]
                                    # print(Banner)
                                    # print(service)
                                except:
                                    return_Data = self.scanservice(host, port, timeout)
                                    service = return_Data[0]
                                    if return_Data[1]!='':
                                        Banner =return_Data[1]
                                    if return_Data[2]:
                                        title = return_Data[2]
                                if service =='http' or  service =='HTTP'  or  service =='HTTPS'  or  service =='https' :
                                    try:
                                        if  service =='https' or  service =='HTTPS':
                                            url_address = 'https://'+host+':'+port
                                        else:
                                            url_address = 'http://'+host+':'+port
                                        html = requests.get(url_address,verify = False)
                                        if html.status_code==400 and 'The plain HTTP request was sent to HTTPS port' in html.text:
                                            # print(html.text)
                                            service='https'
                                            url_address = 'https://'+host+':'+port
                                        html = requests.get(url_address,verify = False)
                                        if not html:
                                            html = requests.post(url_address,verify = False)
                                        html.encoding = html.apparent_encoding
                                        if html.status_code==404:
                                            title="404 Not Found"
                                        elif html.text:
                                            Banner = html.text
                                            # print (html.text)
                                            re_data = re.search(r'<title>(.+)</title>',html.text,re.I|re.M)
                                            if re_data:
                                                title = re_data.group().replace('<title>','').replace('</title>','').replace('<TITLE>','').replace('</TITLE>','')
                                            # print(html.text)
                                            elif "404 Not Found" in html.text:
                                                title="404 Not Found"
                                            elif "Page Not Found" in html.text:
                                                title="Page Not Found"
                                            else:
                                                title=''
                                        else:
                                            title='404'

                                        # print (title)
                                    except Exception as e:
                                        # print(e)
                                        title = ""
                                self.out_result(host,port,'Opened',Banner,service,url_address,title)
                            else:
                                # print(self.flag)
                                if  self.flag:
                                    self.out_result(host,port,'Close',"None",'Unknown','','')
                        except Exception as e:
                            # print(e)
                            if  self.flag:
                                self.out_result(host, port, 'Close', "None", 'Unknown','','')
                            continue
                        finally:
                            try:
                                tcp.close()
                            except:
                                pass
                    continue
            except Exception as e:
                print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')

                continue

    def scanservice(self,host,port,timeout):
        Banner = ''
        title=''
        service='Unknown'
        for probe in PROBES:
            try:
                sd = socket(AF_INET, SOCK_STREAM)
                sd.settimeout(int(timeout))
                sd.connect((host, int(port)))
                sd.send(probe.encode(encoding='gbk'))
            except:
                continue
            try:
                result = sd.recv(1024)
                try:
                    result = result.decode("gbk")
                except:
                    result=str(result.decode("raw_unicode_escape").strip().encode("utf-8"))
                    # result=str(result.decode("raw_unicode_escape").strip().encode("utf-8"))[2:-1]
                    # result = result.decode("raw_unicode_escape")


                # result = sd.recv(1024).decode("raw_unicode_escape")
                # print(result)
                if ("<title>400 Bad Request</title>"in result and  "https" in result ) or ("<title>400 Bad Request</title>"in result and  "HTTPS" in result ):
                    service ='https'
                    title =result
                    break
                service = self.matchbanner(result, signs_rules)
                if service != 'Unknown':
                    Banner =result
                    break

            except:
                continue
        if service!="Unknown":
            pass
        else:
            service = self.get_server(str(port))
        return service,Banner,title

    def get_server(self,port):
        SERVER = {
            'FTP': '21',
            'SSH': '22',
            'Telnet': '23',
            'SMTP': '25',
            'DNS': '53',
            'DHCP': '68',
            'HTTP': '80',
            'TFTP': '69',
            'HTTP': '8080',
            'POP3': '995',
            'NetBIOS': '139',
            'IMAP': '143',
            'HTTPS': '443',
            'SNMP': '161',
            'LDAP': '489',
            'SMB': '445',
            'SMTPS': '465',
            'Linux R RPE': '512',
            'Linux R RLT': '513',
            'Linux R cmd': '514',
            'Rsync': '873',
            'IMAPS': '993',
            'Proxy': '1080',
            'JavaRMI': '1099',
            'Lotus': '1352',
            'MSSQL': '1433',
            'MSSQL': '1434',
            'Oracle': '1521',
            'PPTP': '1723',
            'cPanel': '2082',
            'CPanel': '2083',
            'Zookeeper': '2181',
            'Docker': '2375',
            'Zebra': '2604',
            'MySQL': '3306',
            'Kangle': '3312',
            'RDP': '3389',
            'SVN': '3690',
            'Rundeck': '4440',
            'GlassFish': '4848',
            'PostgreSql': '5432',
            'PcAnywhere': '5632',
            'VNC': '5900',
            'CouchDB': '5984',
            'varnish': '6082',
            'Redis': '6379',
            'Weblogic': '7001',
            'Kloxo': '7778',
            'Zabbix': '8069',
            'RouterOS': '8291',
            'Elasticsearch': '9200',
            'Elasticsearch': '9300',
            'Zabbix': '10050',
            'Zabbix': '10051',
            'Memcached': '11211',
            'MongoDB': '27017',
            'MongoDB': '28017',
            'Hadoop': '50070'
        }
        for k, v in SERVER.items():
            if v == port:
                return k
        return 'Unknown'

    def matchbanner(self,banner,slist):
        for item in slist:
            item = item.split('|')
            p=re.compile(item[1])
            if p.search(banner)!=None:
                return item[0]
        return 'Unknown'
    def out_result(self,host,port,zhuangtai,Banner='None',service='Unknown',url_address='',title=''):
        lock.acquire()  #加锁
        if len(Banner)>60:
            Banner =Banner[:60]
        if zhuangtai=='Opened':
            if title:
                Banner = (str(title).strip('\n').strip('\r').replace('\r', '').replace('\n', '').replace('"', '').replace('\'', ''))
            else:
                Banner = (str(Banner).strip('\n').strip('\r').replace('\r', '').replace('\n', '').replace('"', '').replace('\'', ''))
            tqdm.write(Fore.GREEN+'[+] ' + host.ljust(15, ' ') + '\t' + port.ljust(6, ' ') + '\t\t' + 'Opened'.ljust(6,' ') + '\t\t' + service.ljust(
            6, ' ') + '\t\t' + Banner.ljust(20, ' '))
        else:
            Banner = (str(Banner).strip('\n').strip('\r').replace('\r', '').replace('\n', '').replace('"', '').replace('\'', ''))

            tqdm.write(Fore.MAGENTA+'[-] ' + host.ljust(15, ' ') + '\t' + port.ljust(6, ' ') + '\t\t' + 'Close'.ljust(6,' ') + '\t\t' + service.ljust(
                6, ' ') + '\t\t' + Banner.ljust(20, ' '))
        try:
            if self.out_txt!='':
                f=open(self.out_txt,"a")
                f.write(host+' '+port+' opened '+service+'\n')
                f.close()
            if self.out_html !='':
                # print(Banner)
                if title:
                    Banner = ((title.strip()).encode(encoding='gbk',errors='ignore')).decode("gbk",errors='ignore')
                else:
                    Banner = ((Banner.strip()).encode(encoding='gbk',errors='ignore')).decode("gbk",errors='ignore')
                # Banner=Banner.replace("\\x",'\\\\x')
                # print(Banner)
                # Banner = Banner.strip()
                Banner = html.escape(Banner)
                out_str = '<script>add_table("'+host+'","'+port+'","'+zhuangtai+'","'+service+'","'+Banner+'","'+url_address+'");</script>'

                if os.path.exists(self.out_html):
                    f2 = open(self.out_html, "a",encoding='utf-8')
                    f2.write(out_str)
                else:
                    f2 = open(self.out_html, "a",encoding='utf-8')
                    f2.write(html_head)
                    f2.write(out_str)
                f2.close()
        except Exception as e :
            print(Fore.RED+'文件写入出错！'+str(e))
        lock.release()  #执行完 ，释放锁
    #ip:port 单端口扫描
    def ip_port_scan(self,threadNum,timeout):
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
                    Fore.CYAN + '[*] ' + 'Host'.ljust(15, ' ') + '\t' + 'Port'.ljust(6, ' ') + '\t\t' + 'Status'.ljust(
                        6, ' ') + '\t\t' + 'Service'.ljust(6, ' ') + '\t\t' + 'Banner'.ljust(20, ' '))

                self.portQueue.queue.clear()
                kkk = int(threadNum / len(self.ip_2_list)) + 1
                try:
                    if kkk>len(self.ip_2_list):
                        kkk=len(self.ip_2_list)
                    for i in range(0, kkk):
                        self.portQueue.put(self.ip_2_list[i])
                        self.ip_2_list.remove(self.ip_2_list[i])
                except:
                    pass
                if self.portQueue.qsize() > 0:
                    try:
                        threads = []  # 线程列表
                        for i in range(threadNum):
                            i = threading.Thread(target=self.portScanner, args=(timeout, pbar,'2'))
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

    def  scan(self,threadNum,timeout):
        if(threadNum<len(self.all_port_list)):
            threadNum=threadNum
        else:
            threadNum =len(self.all_port_list)
        print(Fore.CYAN+'[*] 共扫描%s个IP,%s种端口,排除%s种端口,线程:%s,请稍后..'%(len(self.ip_1_list),len(self.all_port_list),len(self.all_remove_port),threadNum))
        print(Fore.YELLOW+'[*] The PortScan is Start')
        count = len(self.all_port_list )*len(self.ip_1_list)
        try:
            with tqdm(total=count,ncols=100) as pbar:
                tqdm.write(
                    Fore.CYAN + '[*] ' + 'Host'.ljust(15, ' ') + '\t' + 'Port'.ljust(6, ' ') + '\t\t' + 'Status'.ljust(
                        6,' ') + '\t\t' + 'Service'.ljust(6, ' ') + '\t\t' + 'Banner'.ljust(20, ' '))

                self.portQueue.queue.clear()
                kkk = int(threadNum/len(self.all_port_list ))+1
                try:
                    if kkk>len(self.ip_1_list):
                        kkk=len(self.ip_1_list)
                    for i in range(0,kkk):
                        for port in self.all_port_list :
                            # print(port_list)
                            self.portQueue.put(self.ip_1_list[i]+':'+str(port))
                        self.ip_1_list.remove(self.ip_1_list[i])
                    # for ip in self.ip_1_list:
                    #     ip = ip.replace("https://",'').replace("http://",'').split("/")[0]

                    #     for i in port_list:
                    #         # print(port_list)
                    #         self.portQueue.put(ip+':'+str(i))
                        # print(threadNum)
                        # print(self.portQueue.qsize())
                        # print(threadNum)
                    if self.portQueue.qsize() >0:
                        try:
                            threads = []  # 线程列表
                            for i in range(threadNum):
                                i = threading.Thread(target=self.portScanner, args=(timeout, pbar,'1'))
                                threads.append(i)
                            for t in threads:#启动线程
                                t.start()

                            for t in threads:#阻塞线程，等待线程结束
                                t.join()

                        except KeyboardInterrupt:
                            self.portQueue.queue.clear()
                            print(Fore.RED + "用户中途退出！")
                            return

                    tqdm.write(Fore.YELLOW+'[*] The Scan is Complete!')
                    pbar.set_description(Fore.BLUE+'[*] Scan Complete!')  # 修改进度条描述
                    pbar.close()
                except Exception as e:
                    print(str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
        except KeyboardInterrupt:
            print(Fore.RED+"用户中途退出！")
            pass

@click.command()
@click.version_option(version='1.4.1')
@click.option("-i", "--ip",help="输入ip，例如：192.168.1.1、192.168.1.1/24、192.168.1.1-99",default='',is_eager=True)
@click.option("-f", "--file",help="从文件加载ip列表",default='')
@click.option("-p", "--port",help="定义扫描的端口，例如:80、80,8080、80-8000",default='',is_eager=True)
@click.option("-pf", "--port_file",help="从文件加载端口列表，使用逗号分隔",default='')
@click.option("-rp","--remove_port",help="定义排除的端口，例如:25,110",default='25,110')
@click.option("--ip_port",help="对特定的IP及端口进行测试，从文件加载，格式为:IP:端口",is_flag=True)
@click.option("-jp","--jump_port",help="跳过主机发现",is_flag=True)
@click.option("-to","--timeout",help="设置超时时间",default=1,show_default=True)
@click.option("-v", "--verbose", is_flag=True,help="显示详细信息")
@click.option("-t", "--threads",show_default=True,default=400, help="定义扫描的线程")
@click.option("--txt", help="定义输出文本文件",default='')
@click.option("--html",help="定义输出html文件",default='')
def click_main(ip,file,port,port_file,remove_port,ip_port,jump_port,timeout,verbose,threads,txt,html):
    # print(ip)
    portscan = Portscan()
    # portscan.chuli_canshu('',file='C:\\Users\\qianxiao996\\Desktop\\22.txt',port='',port_file='',remove_port='25,110',ip_port='1',jump_port='',timeout=1,verbose='1',threads=400,txt='',html='')

    portscan.chuli_canshu(ip,file,port,port_file,remove_port,ip_port,jump_port,timeout,verbose,threads,txt,html)
    

if __name__ == '__main__':
    click.echo(Fore.CYAN+'''
   _____                         _____           _    _____   
  / ____|                       |  __ \         | |  / ____|                
 | (___  _   _ _ __   ___ _ __  | |__) |__  _ __| |_| (___   ___ __ _ _ __  
  \___ \| | | | '_ \ / _ \ '__| |  ___/ _ \| '__| __|\___ \ / __/ _` | '_ \ 
  ____) | |_| | |_) |  __/ |    | |  | (_) | |  | |_ ____) | (_| (_| | | | |
 |_____/ \__,_| .__/ \___|_|    |_|   \___/|_|   \__|_____/ \___\__,_|_| |_|
             | |                                                           
             |_|                                       
                       Github: https://github.com/qianxiao996/Super-PortScan''')
    click_main()
    # portscan = Portscan()
    # portscan.chuli_canshu('192.168.31.126/24','','','','','',1,0,400,'','')









        