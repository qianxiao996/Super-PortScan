import sys,os,queue
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from socket import *
import threading,time

from ui.main import Ui_MainWindow
import win32con
import win32clipboard as wincld


class MainWindows(QtWidgets.QMainWindow,Ui_MainWindow): #主窗口

    def __init__(self,parent=None):
        super(MainWindows,self).__init__(parent)
        self.Ui = Ui_MainWindow()
        self.Ui.setupUi(self)
        self.setWindowIcon(QtGui.QIcon('./logo.ico'))
        self.port_list = []
        self.load()
        self.threads=[]
        #列表框点击切换
        self.Ui.port_file.activated[str].connect(self.change_port_file)
        #引入文件
        self.Ui.pushButton_file.clicked.connect(self.open_file)
        #开始扫描
        self.Ui.pushButton_start.clicked.connect(self.start_scanner)

        #设置漏洞扫描表格属性  列宽度
        # self.Ui.tableWidget_result.setColumnWidth(0, 55 )
        self.Ui.tableWidget_result.setColumnWidth(0, 211)
        self.Ui.tableWidget_result.setColumnWidth(1, 100)
        self.Ui.tableWidget_result.setColumnWidth(2, 300)
    def load(self):
        for file_dir, dirs_list, file_name_list in os.walk('dict'):
            for file_name in file_name_list:
                f=open('dict/'+file_name,'r')
                port_Data = f.read().replace("\n",",")
                f.close()
                self.port_list.append(file_name+":"+port_Data)
                self.Ui.port_file.addItem(file_name.replace('.ini',''))
        #设置初始数据
        set_Data_list =  self.port_list[0].split('.ini:')
        self.Ui.textEdit_port.setText(set_Data_list[1])

    def change_port_file(self):
        com_name_text = self.Ui.port_file.currentText()
        for i in self.port_list:
            if com_name_text == i.split('.ini:')[0]:
                self.Ui.textEdit_port.setText(i.split('.ini:')[1])
                break

    def open_file(self):
        filename = self.file_open(r"Text Files (*.txt);;All files(*.*)")
        # with open(filename, 'r') as f:
        #     for line in f:
        #         self.ip_list.append(line.strip())
        # f.close()
        self.Ui.lineEdit_ip.setText(filename)
    def get_ip_f_list(self,file):
        all_list = []
        if os.path.exists(file):
            try:
                file = open(file, 'r', encoding='utf-8')
                for line in file:
                    all_list = all_list + self.get_ip_d_list(line)
                file.close()
                all_list2 = []
                for i in all_list:
                    if i not in all_list2:
                        all_list2.append(i)
                return list(filter(None, all_list2))  # 去除 none 和 空字符
            except:
                pass
                # printRed('Error:文件读取错误！')
        else:
            pass
            # printRed('Error:文件不存在')
    def get_ip_d_list(self,ip):
        ip_list = []
        if '/24' in ip:
            ip = ip.replace('/24', '')
            for i in range(1, 255):
                ip_list.append(ip[:ip.rfind('.')] + '.' + str(i))
        elif '-' in ip:
            ip_start = ip.split('.')[-1].split('-')[0]
            ip_end = ip.split('.')[-1].split('-')[1]
            if int(ip_start) > int(ip_end):
                numff = ip_start
                ip_start = ip_end
                ip_end = numff
            for i in range(int(ip_start), int(ip_end) + 1):
                ip_list.append(ip[:ip.rfind('.')] + '.' + str(i))
        else:
            ip_list = ip.split()
        # 列表去重
        all_list = []
        for i in ip_list:
            if i not in all_list:
                all_list.append(i)
        return list(filter(None, ip_list))  # 去除 none 和 空字符
    def start_scanner(self):
        input_Data=self.Ui.lineEdit_ip.text()
        try:
            if os.path.exists(input_Data):
                ip_list = self.get_ip_f_list(input_Data)
            else:
                ip_list= self.get_ip_d_list(input_Data)
        except:
            ip_list = self.get_ip_d_list(input_Data)
        port_list = self.Ui.textEdit_port.toPlainText().split(',')
        threadnum =  self.Ui.lineEdit_thread.text()
        timeout = self.Ui.comboBox_timeout.currentText()
        self.scan(ip_list,port_list,threadnum,timeout)

    def scan(self,ip_list, port_list, threadNum,timeout):
        self.Ui.pushButton_start.setEnabled(False)
        portQueue = queue.Queue()  # 待检测端口队列，会在《Python常用操作》一文中更新用法
        for ip in ip_list:
            for i in port_list:
                portQueue.put(ip + ':' + str(i))
        self.createThread(threadNum, portQueue, timeout)
        # printYellow('[*] The Scan is Start')
        self.statusBar().showMessage("The Scan is Start", 5000)
        for t in self.threads:  # 启动线程
            t.setDaemon(True)  # 设置为后台线程，这里默认是False，设置为True之后则主线程不用等待子线程
            t.start()

        # for t in self.threads:  # 阻塞线程，等待线程结束
        #     t.join()
        # printYellow('[*] The Scan is complete!')

    def createThread(self,num, portQueue, timeout):
        self.threads=[]
        for i in range(int(num)):
            i = threading.Thread(target=self.portScanner, args=(portQueue, timeout))
            self.threads.append(i)

    def portScanner(self,portQueue, timeout):
        while True:
            if portQueue.empty():  # 队列空就结束
                time.sleep(5)
                self.Ui.pushButton_start.setEnabled(True)
                return
            ip_port = portQueue.get()  # 从队列中取出
            host = ip_port.split(':')[0]
            port = ip_port.split(':')[1]
            # print(host,port)
            try:

                tcp = socket(AF_INET, SOCK_STREAM)
                tcp.settimeout(int(timeout))  # 如果设置太小，检测不精确，设置太大，检测太慢
                result = tcp.connect_ex((host, int(port)))  # 效率比connect高，成功时返回0，失败时返回错误码

                # print(222)
                try:
                    Banner = tcp.recv(1024).decode('utf-8').strip()
                except:
                    Banner = 'unknow'
                # print(Banner)
                if result == 0:
                    # print(host,port)
                    self.statusBar().showMessage(host+":"+port+" is open!", 5000)
                    row = self.Ui.tableWidget_result.rowCount()  # 获取行数
                    self.Ui.tableWidget_result.setRowCount(row + 1)
                    hostItem = QTableWidgetItem(host)
                    portItem = QTableWidgetItem(port)
                    BannerItem = QTableWidgetItem(Banner)
                    self.Ui.tableWidget_result.setItem(row, 0, hostItem)
                    self.Ui.tableWidget_result.setItem(row, 1, portItem)
                    self.Ui.tableWidget_result.setItem(row, 2, BannerItem)

            except:
                pass
                # exit()
            finally:
                tcp.close()

    # 文件打开对话框
    def file_open(self, type):
        fileName, selectedFilter = QFileDialog.getOpenFileName(self, (r"打开文件"),'', type)
        return (fileName)  # 返回文件路径

    # 保存文件对话框
    def file_save(self, filename):
        fileName, filetype = QFileDialog.getSaveFileName(self, (r"保存文件"), (r'C:\Users\Administrator\\' + filename),
                                                         r"All files(*.*)")
        # print(fileName)
        return fileName


if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindows()
    # styleFile = './qss/black.qss'
    # qssStyle = Common.readQss(styleFile)
    # window.setStyleSheet(qssStyle)
    window.show()
    sys.exit(app.exec_())
