# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'main.ui'
#
# Created by: PyQt5 UI code generator 5.11.3
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets

class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(656, 639)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")
        self.verticalLayout_4 = QtWidgets.QVBoxLayout()
        self.verticalLayout_4.setObjectName("verticalLayout_4")
        self.horizontalLayout_6 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_6.setObjectName("horizontalLayout_6")
        self.verticalLayout_3 = QtWidgets.QVBoxLayout()
        self.verticalLayout_3.setObjectName("verticalLayout_3")
        self.horizontalLayout_5 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_5.setObjectName("horizontalLayout_5")
        self.label_ip = QtWidgets.QLabel(self.centralwidget)
        self.label_ip.setObjectName("label_ip")
        self.horizontalLayout_5.addWidget(self.label_ip)
        self.lineEdit_ip = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_ip.setMinimumSize(QtCore.QSize(200, 26))
        self.lineEdit_ip.setMaximumSize(QtCore.QSize(16777215, 16777215))
        self.lineEdit_ip.setStyleSheet("")
        self.lineEdit_ip.setObjectName("lineEdit_ip")
        self.horizontalLayout_5.addWidget(self.lineEdit_ip)
        self.verticalLayout_3.addLayout(self.horizontalLayout_5)
        self.horizontalLayout_4 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_4.setObjectName("horizontalLayout_4")
        self.label_port = QtWidgets.QLabel(self.centralwidget)
        self.label_port.setMaximumSize(QtCore.QSize(100, 16777215))
        self.label_port.setObjectName("label_port")
        self.horizontalLayout_4.addWidget(self.label_port)
        self.port_file = QtWidgets.QComboBox(self.centralwidget)
        self.port_file.setStyleSheet("")
        self.port_file.setObjectName("port_file")
        self.horizontalLayout_4.addWidget(self.port_file)
        self.verticalLayout_3.addLayout(self.horizontalLayout_4)
        self.horizontalLayout_6.addLayout(self.verticalLayout_3)
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout()
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.pushButton_file = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_file.setMinimumSize(QtCore.QSize(80, 28))
        self.pushButton_file.setStyleSheet("")
        self.pushButton_file.setObjectName("pushButton_file")
        self.verticalLayout_2.addWidget(self.pushButton_file)
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout()
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setMaximumSize(QtCore.QSize(35, 16777215))
        self.label_2.setObjectName("label_2")
        self.horizontalLayout_2.addWidget(self.label_2)
        self.lineEdit_thread = QtWidgets.QLineEdit(self.centralwidget)
        self.lineEdit_thread.setMaximumSize(QtCore.QSize(50, 16777215))
        self.lineEdit_thread.setObjectName("lineEdit_thread")
        self.horizontalLayout_2.addWidget(self.lineEdit_thread)
        self.verticalLayout_2.addLayout(self.horizontalLayout_2)
        self.horizontalLayout_3.addLayout(self.verticalLayout_2)
        self.verticalLayout = QtWidgets.QVBoxLayout()
        self.verticalLayout.setObjectName("verticalLayout")
        self.pushButton_start = QtWidgets.QPushButton(self.centralwidget)
        self.pushButton_start.setMinimumSize(QtCore.QSize(80, 28))
        self.pushButton_start.setStyleSheet("")
        self.pushButton_start.setObjectName("pushButton_start")
        self.verticalLayout.addWidget(self.pushButton_start)
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.label_timeout = QtWidgets.QLabel(self.centralwidget)
        self.label_timeout.setMaximumSize(QtCore.QSize(35, 16777215))
        self.label_timeout.setObjectName("label_timeout")
        self.horizontalLayout.addWidget(self.label_timeout)
        self.comboBox_timeout = QtWidgets.QComboBox(self.centralwidget)
        self.comboBox_timeout.setMaximumSize(QtCore.QSize(50, 16777215))
        self.comboBox_timeout.setObjectName("comboBox_timeout")
        self.comboBox_timeout.addItem("")
        self.comboBox_timeout.addItem("")
        self.comboBox_timeout.addItem("")
        self.comboBox_timeout.addItem("")
        self.comboBox_timeout.addItem("")
        self.horizontalLayout.addWidget(self.comboBox_timeout)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.horizontalLayout_3.addLayout(self.verticalLayout)
        self.horizontalLayout_6.addLayout(self.horizontalLayout_3)
        self.verticalLayout_4.addLayout(self.horizontalLayout_6)
        self.textEdit_port = QtWidgets.QTextEdit(self.centralwidget)
        self.textEdit_port.setMaximumSize(QtCore.QSize(16777215, 61))
        self.textEdit_port.setObjectName("textEdit_port")
        self.verticalLayout_4.addWidget(self.textEdit_port)
        self.tableWidget_result = QtWidgets.QTableWidget(self.centralwidget)
        self.tableWidget_result.setObjectName("tableWidget_result")
        self.tableWidget_result.setColumnCount(3)
        self.tableWidget_result.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_result.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_result.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.tableWidget_result.setHorizontalHeaderItem(2, item)
        self.tableWidget_result.verticalHeader().setVisible(False)
        self.tableWidget_result.verticalHeader().setDefaultSectionSize(25)
        self.verticalLayout_4.addWidget(self.tableWidget_result)
        self.gridLayout.addLayout(self.verticalLayout_4, 0, 0, 1, 1)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 656, 26))
        self.menubar.setObjectName("menubar")
        self.menu = QtWidgets.QMenu(self.menubar)
        self.menu.setObjectName("menu")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.action = QtWidgets.QAction(MainWindow)
        self.action.setObjectName("action")
        self.action_2 = QtWidgets.QAction(MainWindow)
        self.action_2.setObjectName("action_2")
        self.actionGithub = QtWidgets.QAction(MainWindow)
        self.actionGithub.setObjectName("actionGithub")
        self.menu.addAction(self.action)
        self.menu.addAction(self.action_2)
        self.menu.addAction(self.actionGithub)
        self.menubar.addAction(self.menu.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Super-PortScan by qianxiao996"))
        self.label_ip.setText(_translate("MainWindow", "IP："))
        self.label_port.setText(_translate("MainWindow", "端口配置文件"))
        self.pushButton_file.setText(_translate("MainWindow", "引入文件"))
        self.label_2.setText(_translate("MainWindow", "线程"))
        self.lineEdit_thread.setText(_translate("MainWindow", "3000"))
        self.pushButton_start.setText(_translate("MainWindow", "开始扫描"))
        self.label_timeout.setText(_translate("MainWindow", "超时"))
        self.comboBox_timeout.setItemText(0, _translate("MainWindow", "5"))
        self.comboBox_timeout.setItemText(1, _translate("MainWindow", "3"))
        self.comboBox_timeout.setItemText(2, _translate("MainWindow", "10"))
        self.comboBox_timeout.setItemText(3, _translate("MainWindow", "15"))
        self.comboBox_timeout.setItemText(4, _translate("MainWindow", "30"))
        self.textEdit_port.setHtml(_translate("MainWindow", "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\" \"http://www.w3.org/TR/REC-html40/strict.dtd\">\n"
"<html><head><meta name=\"qrichtext\" content=\"1\" /><style type=\"text/css\">\n"
"p, li { white-space: pre-wrap; }\n"
"</style></head><body style=\" font-family:\'SimSun\'; font-size:9pt; font-weight:400; font-style:normal;\">\n"
"<p style=\" margin-top:0px; margin-bottom:0px; margin-left:0px; margin-right:0px; -qt-block-indent:0; text-indent:0px;\">21,22,23,25,53,69,80,81,82,83,84,85,86,87,88,89,110,135,139,143,443,445,465,993,995,1080,1158,1433,1521,1863,2100,3128,3306,3389,7001,8080,8081,8082,8083,8084,8085,8086,8087,8088,8888,9080,9090</p></body></html>"))
        item = self.tableWidget_result.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "IP"))
        item = self.tableWidget_result.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "PORT"))
        item = self.tableWidget_result.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Banner"))
        self.menu.setTitle(_translate("MainWindow", "关于"))
        self.action.setText(_translate("MainWindow", "检查更新"))
        self.action_2.setText(_translate("MainWindow", "联系作者"))
        self.actionGithub.setText(_translate("MainWindow", "Github"))

