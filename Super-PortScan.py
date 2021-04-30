#!/usr/bin/env python
# -*- coding: utf-8 -*-
from socket import *
import threading      #导入线程相关模块
import queue,os,requests
import argparse,time,re
from color import *
requests.packages.urllib3.disable_warnings()


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
            lengthMenu: '<select class="form-control input-xsmall">' + '<option value="1">1</option>' + '<option value="10">10</option>' + '<option value="20">20</option>' + '<option value="30">30</option>' + '<option value="40">40</option>' + '<option value="50">50</option>' + '</select>条记录',//左上角的分页大小显示。
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
            tcp.settimeout(int(timeout))  # 如果设置太小，检测不精确，设置太大，检测太慢
            # print(host,port)
            result = tcp.connect_ex((host, int(port)))  # 效率比connect高，成功时返回0，失败时返回错误码
            # print(port+"success")
            if result == 0:
                url_address=''
                tcp.send("test".encode(encoding='utf-8'))
                try:
                    Banner = tcp.recv(100).decode("raw_unicode_escape")
                    service=matchbanner(Banner,signs_rules)
                    if service=="Unknown":
                        return_Data  = scanservice(host, port,timeout)
                        service = return_Data[0]
                        Banner =return_Data[1]
                    # print(Banner)
                    # print(service)
                except:
                    return_Data = scanservice(host, port, timeout)
                    service = return_Data[0]
                    Banner = return_Data[1]
                if service =='http' or  service =='HTTP'  or  service =='HTTPS'  or  service =='https' :
                    try:
                        if  service =='https' or  service =='HTTPS':
                            url_address = 'https://'+host+':'+port
                        else:
                            url_address = 'http://'+host+':'+port
                        html = requests.get(url_address,verify = False).text
                        # print (html)
                        Banner=re.search('<title>(.+)</title>',html).group().replace('<title>','').replace('</title>','')
                        # print (title)
                        

                    except:
                        Banner =Banner

                # Banner=''
                out_result(host,port,'Opened',Banner,service,url_address)
            else:
                if  flag:
                    out_result(host,port,'Close',"None",'Unknown','')
        except:
            if  flag:
                out_result(host, port, 'Close', "None", 'Unknown','')
            continue
        finally:
            try:
                tcp.close()
            except:
                pass
def scanservice(host,port,timeout):
    return_result =''
    service='Unknown'
    for probe in PROBES:
        try:
            sd = socket(AF_INET, SOCK_STREAM)
            sd.settimeout(int(timeout))
            sd.connect((host, int(port)))
            sd.send(probe.encode(encoding='utf-8'))
        except:
            continue
        try:
            result = sd.recv(1024).decode("raw_unicode_escape")
            # print(result)
            if ("<title>400 Bad Request</title>"in result and  "https" in result ) or ("<title>400 Bad Request</title>"in result and  "HTTPS" in result ):
                service ='https'
                return_result =result
                break
            service = matchbanner(result, signs_rules)
            if service != 'Unknown':
                return_result =result
                break

        except:
            continue
    if service!="Unknown":
        pass
    else:
        service = get_server(str(port))
    return service,return_result

def get_server(port):
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
        'Weblogic': '9001',
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

def matchbanner(banner,slist):
    for item in slist:
        item = item.split('|')
        p=re.compile(item[1])
        if p.search(banner)!=None:
            return item[0]
    return 'Unknown'
def out_result(host,port,zhuangtai,Banner='None',service='Unknown',url_address=''):
    lock.acquire()  #加锁
    if zhuangtai=='Opened':
        Banner = (str(Banner).strip('\n').strip('\r').replace('\r', '').replace('\n', '').replace('"', '').replace('\'', ''))
        printGreen('[*] ' + host.ljust(15, ' ') + '\t' + port.ljust(6, ' ') + '\t\t' + 'Opened'.ljust(6,' ') + '\t\t' + service.ljust(
        6, ' ') + '\t\t' + Banner.ljust(20, ' '))
    else:
        Banner = (str(Banner).strip('\n').strip('\r').replace('\r', '').replace('\n', '').replace('"', '').replace('\'', ''))

        printDarkGray('[*] ' + host.ljust(15, ' ') + '\t' + port.ljust(6, ' ') + '\t\t' + 'Close'.ljust(6,' ') + '\t\t' + service.ljust(
            6, ' ') + '\t\t' + Banner.ljust(20, ' '))
    try:
        if out_txt!='':
            f=open(out_txt,"a")
            f.write(host+' '+port+' opened '+service+'\n')
            f.close()
        if out_html !='':
            # print(Banner)
            Banner = ((Banner.strip()).encode(encoding='gbk',errors='ignore')).decode("gbk",errors='ignore')
            # print(Banner)
            # Banner = Banner.strip()
            out_str = '<script>add_table("'+host+'","'+port+'","'+zhuangtai+'","'+service+'","'+Banner+'","'+url_address+'");</script>'

            if os.path.exists(out_html):
                f2 = open(out_html, "a")
                f2.write(out_str)
            else:
                f2 = open(out_html, "a")
                f2.write(html_head)
                f2.write(out_str)
            f2.close()
    except:
        print('文件写入出错！')

    lock.release()  #执行完 ，释放锁
    #创建线程
def createThread(num,portQueue,timeout,threads):
    # portScanner(portQueue,timeout)
    for i in range(num):
        i= threading.Thread(target=portScanner, args=(portQueue,timeout))
        threads.append(i)
def  scan(ip_list,port_list,threadNum,timeout):

    # print(get_server(str(22)))
    # print(port_list)
    # ip_list=['192.168.1.1','192.168.1.2']
    # port_list = [80, 25, 110]
    if(threadNum<len(port_list)):
        threadNum=threadNum
    else:
        threadNum =len(port_list)
    printSkyBlue('[*] 共扫描%s个IP,%s种端口,排除%s种端口,线程:%s,请稍后..'%(len(ip_list),len(port_list),len(remove_port),threadNum))
    printYellow('[*] The Scan is Start')
    for ip in ip_list:
        if(jp_flag==1):
            printYellow('[*] The '+ip+' is Start!')
            printSkyBlue('[*] ' + 'Host'.ljust(15, ' ') + '\t' + 'Port'.ljust(6, ' ') + '\t\t' + 'Status'.ljust(6,
                                                                                                                ' ') + '\t\t' + 'Service'.ljust(
                6, ' ') + '\t\t' + 'Banner'.ljust(20, ' '))
            threads=[]#线程列表
            portQueue = queue.Queue()  # 待检测端口队列，会在《Python常用操作》一文中更新用法
            portQueue.queue.clear()
            for i in port_list:
                # print(port_list)
                portQueue.put(ip+':'+str(i))
            # print(threadNum)
            # print(portQueue.qsize())
            # print(threadNum)
            createThread(threadNum, portQueue,timeout,threads)
            for t in threads:#启动线程
                t.start()
            for t in threads:#阻塞线程，等待线程结束
                # print(len(threads))
                # if len(threads)==0:
                #     # exit()
                #     time.sleep(5)
                #     break
                t.join()
                threads=[]
            printYellow('[*] The '+ip+' is complete!')
        else:
            if(startPing(ip)):
                printSkyBlue('[*] The '+ip+' is Up!')
                printSkyBlue('[*] ' + 'Host'.ljust(15, ' ') + '\t' + 'Port'.ljust(6, ' ') + '\t\t' + 'Status'.ljust(6,
                                                                                                                  ' ') + '\t\t' + 'Service'.ljust(
                    6, ' ') + '\t\t' + 'Banner'.ljust(20, ' '))
                threads=[]#线程列表
                portQueue = queue.Queue()  # 待检测端口队列，会在《Python常用操作》一文中更新用法
                portQueue.queue.clear()
                for i in port_list:
                    # print(port_list)
                    portQueue.put(ip+':'+str(i))
                # print(portQueue.qsize())
                # print(threadNum)/
                createThread(threadNum, portQueue,timeout,threads)
                # print(threads)
                for t in threads:#启动线程
                    t.start()
                for t in threads:#阻塞线程，等待线程结束
                    # if len(threads)==0:
                    #     # exit()
                    #     time.sleep(5)
                    #     break
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
    lock = threading.Lock() #申请一个锁
    # out_html = '111.html'
    # scan(['blog.qianxiao996.cn'], [443], 22,1)
    # exit();
    all_port_list = [21,22,23,25,53,53,80,81,110,111,123,123,135,137,139,161,389,443,445,465,500,515,520,523,548,623,636,873,902,1080,1099,1433,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,7001,7077,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010,8080,8081,8443,8545,8686,9000,9042,9092,9100,9200,9418,9999,11211,15210,27017,37777,33899,33889,50000,50070,61616]
    parser = argparse.ArgumentParser(usage='\n\tpython3 Super-PortScan.py -i 192.168.1.1 -p 80\n\tpython3 Super-PortScan.py -f ip.txt -p 80')
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-i", "--ip" ,help="输入一个或一段ip，例如：192.168.1.1、192.168.1.1/24、192.168.1.1-99")
    group.add_argument("-f", "--file",help="从文件加载ip列表")
    parser.add_argument("-p", "--port", help="定义扫描的端口，例如:80、80,8080、80-8000")
    parser.add_argument("-rp",help="定义排除的端口，例如:25,110")
    parser.add_argument("-jp",action="store_true",help="跳过主机发现")
    parser.add_argument("-ts",help="设置超时时间，默认1s")
    parser.add_argument("-v", action="store_true",help="显示所有扫描结果")
    parser.add_argument("-t", "--threads", help="定义扫描的线程，默认为400")
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
        timeout=1
    if args.rp:
        remove_port_temp = (args.rp).split(",")
        remove_port.extend(remove_port_temp)
        # print(remove_port)
    if args.ip:
        port_list=[]
        if  args.port :
            port_list = get_port_list(args.port)
        if not args.port:
            port_list = diff_of_two_list(all_port_list,remove_port)
        ip_list =  get_ip_d_list(args.ip)
        if args.threads:
            scan(ip_list,port_list,int(args.threads),timeout)
        else:
            scan(ip_list,port_list,400,timeout)
        # for i in ip_list:
        #     scan(i, port_list, threadNum)

    if args.file:
        port_list=[]
        if  args.port :
            port_list = get_port_list(args.port)
        if not args.port:
            port_list = diff_of_two_list(all_port_list,remove_port)
        ip_list =  get_ip_f_list(args.file)
        if args.threads:
            scan(ip_list,port_list,int(args.threads),timeout)
        else:
            scan(ip_list, port_list, 400,timeout)


