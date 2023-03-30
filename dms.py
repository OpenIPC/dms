#!/usr/bin/env python3

import os
import sys
import struct
import json
from locale import getdefaultlocale
from subprocess import check_output
from socket import *
from datetime import *

import netifaces
import logging

from dvrip import DVRIPCam

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import uic, QtCore, QtWidgets
from PyQt5.QtCore import Qt, QSettings

(Ui_MainWindow, QMainWindow) = uic.loadUiType('dms.ui')
(Ui_Form, QtWidgets.QDialog) = uic.loadUiType('remotedevice.ui')

cam = DVRIPCam('')
udptimeout = 3
tcptimeout = 10

if os.path.exists('debug'):
    debug = True
else:
    debug = False

if debug:
    debugLevel = logging.DEBUG
    devices = ({'00:00:00:00:00:64': {'ChannelNum': 9, 'DeviceType': 4, 'GateWay': '0xFE01A8C0', 'HostIP': '0x0A01A8C0', 'HostName': 'NBD80N32RA-KL', 'HttpPort': 80, 'MAC': '00:00:00:00:00:64', 'MaxBps': 0, 'MonMode': 'TCP', 'NetConnectState': 0, 'OtherFunction': 'D=2023-03-21 13:21:32 V=78775aada187e84', 'SN': '0000000000000081', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'TransferPlan': 'Quality', 'UDPPort': 34568, 'UseHSDownLoad': False, 'Brand': 'xm'}, '00:00:00:00:00:17': {'ChannelNum': 1, 'DeviceType': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x0801A8C0', 'HostName': 'LocalHost', 'HttpPort': 80, 'MAC': '00:00:00:00:00:17', 'MaxBps': 0, 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=1482fd4408e15a7', 'SN': '0000000000000006', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'TransferPlan': 'Quality', 'UDPPort': 34568, 'UseHSDownLoad': False, 'Brand': 'xm'}, '00:00:00:00:00:1e': {'BuildDate': '2020-07-04 09:25:14', 'ChannelNum': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x0701A8C0', 'HostName': 'IVG-85HF20PYA-S', 'HttpPort': 80, 'MAC': '00:00:00:00:00:1e', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=d0384e6d8a46c2f', 'SN': '0000000000000033', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': True, 'Version': 'V5.00.R02.000559A7.10010.040400.0020000', 'Brand': 'xm'}, '00:00:00:00:00:48': {'BuildDate': '2022- 2-23 16:34: 0', 'ChannelNum': 1, 'DeviceType': 0, 'GateWay': '0xFE01A8C0', 'HostIP': '0x0501A8C0', 'HostName': 'IVG-N4', 'HttpPort': 80, 'MAC': '00:00:00:00:00:48', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:33 V=a721ad83d521bc7',
               'SN': '000000000000002a', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': False, 'Version': 'V5.00.R02.000629G3.10010.140200.0020000', 'Brand': 'xm'}, '00:00:00:00:00:6b': {'BuildDate': '2020-07-04 09:25:14', 'ChannelNum': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x0401A8C0', 'HostName': 'IVG-85HF20PYA-S', 'HttpPort': 80, 'MAC': '00:00:00:00:00:6b', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:33 V=088a5643e0387f2', 'SN': '0000000000000095', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': False, 'Version': 'V5.00.R02.000559A7.10010.040400.0020000', 'Brand': 'xm'}, '00:00:00:00:00:43': {'BuildDate': '2020-07-04 09:25:14', 'ChannelNum': 1, 'GateWay': '0x0201A8C0', 'HostIP': '0x0601A8C0', 'HostName': 'IVG-85HF20PYA-S', 'HttpPort': 80, 'MAC': '00:00:00:00:00:43', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=6d1150f906f4948', 'SN': '0000000000000039', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': False, 'Version': 'V5.00.R02.000559A7.10010.040400.0020000', 'Brand': 'xm'}, '00:00:00:00:00:22': {'BuildDate': '2020- 9- 1 14:38:48', 'ChannelNum': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x6414A8C0', 'HostName': 'camera_', 'HttpPort': 80, 'MAC': '00:00:00:00:00:22', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=bdf396972028edf', 'SN': '0000000000000061', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': True, 'Version': 'V5.00.R02.000529B2.10010.040600.0020000', 'Brand': 'xm'}})
    RemoteDeviceV3 = [{"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "chConfig", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.1.10", "Interval": 10, "MacAddr": "", "MainRtspUrl": "", "PassWord": "", "Port": 34567, "Protocol": "TCP", "SerialNo": "", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": False, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": False, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 3, "ConfName": "LocalHost", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.20.5", "Interval": 10, "MacAddr": "00:00:00:00:00:49", "MainRtspUrl": "", "PassWord": "assword", "Port": 34567, "Protocol": "TCP", "SerialNo": "0000000000000054", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": False, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "SmartNet", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.1.11", "Interval": 10, "MacAddr": "00:00:00:00:00:e4", "MainRtspUrl": "", "PassWord": "", "Port": 34567, "Protocol": "TCP", "SerialNo": "000000000000009b", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": False, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "LocalHost", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.20.253", "Interval": 10, "MacAddr": "00:00:00:00:00:f6", "MainRtspUrl": "", "PassWord": "assword", "Port": 34567, "Protocol": "TCP", "SerialNo": "00000000000000d8", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": True, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "chConfig", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.1.9", "Interval": 10, "MacAddr": "", "MainRtspUrl": "", "PassWord": "", "Port": 34567, "Protocol": "TCP", "SerialNo": "", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": True, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "IVG-85HF20PYA-S", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.250.249", "Interval": 10,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    "MacAddr": "00:00:00:00:00:63", "MainRtspUrl": "", "PassWord": "2assword", "Port": 34567, "Protocol": "TCP", "SerialNo": "00000000000000b2", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": True, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "LocalHost", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.54.214", "Interval": 10, "MacAddr": "00:00:00:00:00:af", "MainRtspUrl": "", "PassWord": "", "Port": 34567, "Protocol": "TCP", "SerialNo": "00000000000000c9", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": True, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": [{"Channel": 0, "ConfName": "Hikvision", "DevType": "IPC", "Enable": True, "IPAddress": "192.168.1.64", "Interval": 10, "MacAddr": "00:00:00:00:00:2b", "MainRtspUrl": "", "PassWord": "a1234567", "Port": 80, "Protocol": "ONVIF", "SerialNo": "", "StreamType": "MAIN", "SubRtspUrl": "", "TransModel": 0, "UserName": "admin"}], "EnCheckTime": True, "Enable": True, "SingleConnId": "0x00000001", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}, {"ConnType": "SINGLE", "Decoder": 'null', "EnCheckTime": True, "Enable": False, "SingleConnId": "0x00000000", "SynchResolution": True, "TourIntv": 10}]
    ChannelTitle = ["CAM01", "Test2", "D03", "5MP 123456789 0",
                    "D05", "CAM04", "D07", "D08", "D09", "D10", "D11", "D12", "D13", "D14", "D15", "D16"]
    DecodeParam = [{"deleyTimeMs": 150}, {"deleyTimeMs": 333}, {"deleyTimeMs": 2000}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {
        "deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}, {"deleyTimeMs": 333}]
    DigTimeSyn = [{"TimeSyn": "OFF"}, {"TimeSyn": "OFF"}, {"TimeSyn": "OFF"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {
        "TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}, {"TimeSyn": "T&Z"}]
    DecodeDeleyTime = ["0x00000096", "0x000000FA", "0x0000014D",
                       "0x0000029B", "0x000003E8", "0x000007D0", "0x00000BB8"]
    NetLocalSearch = [{"ChannelNum": 16, "DeviceType": 305201157, "GateWay": "0xFE01A8C0", "HostIP": "0x0401A8C0", "HostName": "NBD80S16S-KL", "HttpPort": 80, "MAC": "00:00:00:00:00:b6", "Manufacturer": 4, "MaxBps": 0, "MonMode": "TCP", "NetConnectState": 0, "OtherFunction": "", "SN": "00000000000000cfcdp6", "SSLPort": 8443, "Submask": "0x00FFFFFF", "TCPMaxConn": 10, "TCPPort": 34567, "TransferPlan": "Quality", "UDPPort": 34568, "UseHSDownLoad": False, "pAddr": "", "pGateway": "", "pLocalLinkAddr": ""}, {"ChannelNum": 4, "DeviceType": 305201156, "GateWay": "0x0201A8C0", "HostIP": "0x0801A8C0", "HostName": "LocalHost", "HttpPort": 80, "MAC": "00:00:00:00:00:71", "Manufacturer": 4, "MaxBps": 0, "MonMode": "TCP", "NetConnectState": 1,
                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              "OtherFunction": "", "SN": "0000000000000041", "SSLPort": 8443, "Submask": "0x00FFFFFF", "TCPMaxConn": 10, "TCPPort": 34567, "TransferPlan": "Quality", "UDPPort": 34568, "UseHSDownLoad": False, "pAddr": "", "pGateway": "", "pLocalLinkAddr": ""}, {"ChannelNum": 1, "DeviceType": 0, "GateWay": "0xFE01A8C0", "HostIP": "0x0601A8C0", "HostName": "LocalHost", "HttpPort": 80, "MAC": "00:00:00:00:00:ce", "Manufacturer": 4, "MaxBps": 0, "MonMode": "TCP", "NetConnectState": 1, "OtherFunction": "", "SN": "0000000000000083", "SSLPort": 8443, "Submask": "0x00FFFFFF", "TCPMaxConn": 10, "TCPPort": 34567, "TransferPlan": "Transmission", "UDPPort": 34568, "UseHSDownLoad": False, "pAddr": "", "pGateway": "", "pLocalLinkAddr": ""}, {"ChannelNum": 1, "DeviceType": 7, "GateWay": "0xFE01A8C0", "HostIP": "0x0701A8C0", "HostName": "LocalHost", "HttpPort": 80, "MAC": "00:00:00:00:00:cf", "Manufacturer": 4, "MaxBps": 0, "MonMode": "TCP", "NetConnectState": 1, "OtherFunction": "", "SN": "0000000000000084", "SSLPort": 8443, "Submask": "0x00FFFFFF", "TCPMaxConn": 10, "TCPPort": 34567, "TransferPlan": "Transmission", "UDPPort": 34568, "UseHSDownLoad": False, "pAddr": "", "pGateway": "", "pLocalLinkAddr": ""}]
else:
    debugLevel = logging.INFO
    devices = {}


def log(*args):
    # logging.debug(*args)
    print(*args)


logging.basicConfig(format='%(asctime)s> %(message)s',
                    level=debugLevel, datefmt='[%H:%M:%S]')


class RemoteDevices(QtWidgets.QDialog, Ui_Form):
    def __init__(self, parent=None):
        QtWidgets.QDialog.__init__(self, parent=parent)
        self.setupUi(self)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Escape:
            self.hide()


class MainWindow (QMainWindow):
    def __init__(self, parent=None):
        QMainWindow.__init__(self, parent)
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

    def __del__(self):
        self.ui = None

    def filedialog(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(
            self, "Select upgrade file", settings.value("fwdir", '.'), "Firmware files (*.bin)", options=options)
        if fileName:
            self.ui.labFilename.setText(fileName)
            settings.setValue("fwdir", os.path.dirname(fileName))

    def getCheckedDevices(self, column):
        checked_list = []
        for i in range(self.ui.tableWidget.rowCount()):
            if self.ui.tableWidget.cellWidget(i, 0).isChecked():
                selected_dev = self.ui.tableWidget.item(i, column).text()
                checked_list.append([selected_dev])
            else:
                pass
        return checked_list

    def btnAutoIP(self):
        for dev in w.getCheckedDevices(3):
            log(dev[0])
            # tcpSetAddresses(['config', dev[0], w.ui.editIPAddress.text(), w.ui.editSubnetAddress.text(), w.ui.editGatewayAddress.text(), ''])

    def btnChangePassword(self):
        newPassword = self.ui.editNewPassword.text()
        if newPassword:
            log(self.getCheckedDevices(1), newPassword)

    def onRowClick(self):
        selected_dev = w.ui.tableWidget.item(
            self.ui.tableWidget.currentRow(), 3).text()
        self.ui.editIPAddress.setText(ip2str(devices[selected_dev]["HostIP"]))
        self.ui.editSubnetAddress.setText(
            ip2str(devices[selected_dev]["Submask"]))
        self.ui.editGatewayAddress.setText(
            ip2str(devices[selected_dev]["GateWay"]))
        # w.ui.editDNS1Address.setText(ip2str(devices[selected_dev]["DNS"]))
        # for item in devices:
        #     print(item)
        # print(devices[selected_dev])
        # print(devices[1])
        # self.ui.statusbar.showMessage(selected_dev)

    def keyPressEvent(self, event):
        if event.key() == QtCore.Qt.Key_Escape:
            app.quit()


def onBtnSearch():
    global devices
    QApplication.setOverrideCursor(Qt.WaitCursor)
    if not debug:
        devices = {}
        try:
            devices = udpSearch(devices)
        except Exception as error:
            print(" ".join([str(x) for x in list(error.args)]))
    QApplication.restoreOverrideCursor()
    count = 0
    w.ui.tableWidget.setRowCount(len(devices))
    for dev in devices:
        w.ui.tableWidget.setCellWidget(count, 0, QCheckBox())
        w.ui.tableWidget.setItem(count, 1, QTableWidgetItem(
            ip2str(devices[dev]["HostIP"])))
        w.ui.tableWidget.setItem(
            count, 2, QTableWidgetItem(str(devices[dev]["TCPPort"])))
        w.ui.tableWidget.setItem(
            count, 3, QTableWidgetItem(devices[dev]["MAC"]))
        w.ui.tableWidget.setItem(
            count, 4, QTableWidgetItem(devices[dev]["SN"]))
        w.ui.tableWidget.setItem(count, 5, QTableWidgetItem(
            devices[dev].get("Version", "")[0:18]))
        w.ui.tableWidget.setItem(count, 6, QTableWidgetItem(
            devices[dev].get("BuildDate", "")[0:10]))
        w.ui.tableWidget.setItem(
            count, 7, QTableWidgetItem(devices[dev]["HostName"]))
        count += 1


def ip2str(s):
    return inet_ntoa(struct.pack("I", int(s, 16)))


def str2ip(s):
    return "0x%08X" % struct.unpack("I", inet_aton(s))


def udpSearch(devices):
    sender = socket(AF_INET, SOCK_DGRAM)
    sender.bind((w.ui.comboIPAddresses.currentText(), 0))
    sender.settimeout(1)
    sender.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    sender.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)

    listener = socket(AF_INET, SOCK_DGRAM)
    listener.bind(('', 34569))
    listener.settimeout(udptimeout)
    listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    listener.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    for i in range(2):
        sender.sendto(
            struct.pack("BBHIIHHI", 255, 0, 0, 0, 0, 0,
                        1530, 0), ("255.255.255.255", 34569)
        )
    while True:
        data = listener.recvfrom(1024)
        head, ver, typ, session, packet, info, msg, leng = struct.unpack(
            "BBHIIHHI", data[0][:20]
        )
        if (msg == 1531) and leng > 0:
            answer = json.loads(
                data[0][20: 20 + leng].replace(b"\x00", b""))
            if answer["NetWork.NetCommon"]["MAC"] not in devices.keys():
                devices[answer["NetWork.NetCommon"]["MAC"]] = answer[
                    "NetWork.NetCommon"
                ]
                devices[answer["NetWork.NetCommon"]["MAC"]][u"Brand"] = u"xm"
    return devices


def cbProgress(s):
    w.ui.statusbar.showMessage(s)


def upgradeFirmware(ip, username, password, filename):
    QApplication.setOverrideCursor(Qt.WaitCursor)
    if cam.login():
        log("Auth success")
        cam.upgrade(filename, 0x4000, cbProgress)
    else:
        log("Auth failed")
    QApplication.restoreOverrideCursor()


def udpSetAddresses(data):
    config = {}
    for k in [u"HostName", u"HttpPort", u"MAC", u"MaxBps", u"MonMode", u"SSLPort", u"TCPMaxConn", u"TCPPort", u"TransferPlan", u"UDPPort", "UseHSDownLoad"]:
        if k in devices[data[1]]:
            config[k] = devices[data[1]][k]
    config[u"DvrMac"] = devices[data[1]][u"MAC"]
    config[u"EncryptType"] = 1
    config[u"GateWay"] = str2ip(data[4])
    config[u"HostIP"] = str2ip(data[2])
    config[u"Submask"] = str2ip(data[3])
    config[u"Username"] = w.ui.editUsername.text()
    config[u"Password"] = DVRIPCam.sofia_hash(
        '', w.ui.editCurrentPassword.text())
    devices[data[1]][u"GateWay"] = config[u"GateWay"]
    devices[data[1]][u"HostIP"] = config[u"HostIP"]
    devices[data[1]][u"Submask"] = config[u"Submask"]
    config = json.dumps(
        config, ensure_ascii=False, sort_keys=True, separators=(", ", " : ")
    ).encode("utf8")
    if not debug:
        server = socket(AF_INET, SOCK_DGRAM)
        server.bind((w.ui.comboIPAddresses.currentText(), 34569))
        server.settimeout(udptimeout)
        server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        clen = len(config)

        server.sendto(
            struct.pack(
                "BBHIIHHI%ds2s" % clen,
                255,
                0,
                254,
                0,
                0,
                0,
                1532,
                clen + 2,
                config,
                b"\x0a\x00",
            ),
            ("255.255.255.255", 34569),
        )
        answer = {"Ret": 203}
        e = 0
        while True:
            try:
                data = server.recvfrom(1024)
                head, ver, typ, session, packet, info, msg, leng = struct.unpack(
                    "BBHIIHHI", data[0][:20]
                )
                if (msg == 1533) and leng > 0:
                    answer = json.loads(
                        data[0][20: 20 + leng].replace(b"\x00", b""))
                    break
            except:
                e += 1
                if e > 3:
                    break
        server.close()
        return answer


def btnSave():
    if w.ui.tableWidget.selectedItems():
        QApplication.setOverrideCursor(Qt.WaitCursor)
        selected_dev = w.ui.tableWidget.item(
            w.ui.tableWidget.currentRow(), 3).text()
        udpSetAddresses(['config', selected_dev, w.ui.editIPAddress.text(
        ), w.ui.editSubnetAddress.text(), w.ui.editGatewayAddress.text(), ''])
    QApplication.restoreOverrideCursor()


def btnUpgrade():
    if w.ui.tableWidget.selectedItems() and w.ui.labFilename.text():
        QApplication.setOverrideCursor(Qt.WaitCursor)
        selected_dev = w.ui.tableWidget.item(
            w.ui.tableWidget.currentRow(), 1).text()
        upgradeFirmware(w.ui.editIPAddress.text(), w.ui.editUsername.text(
        ), w.ui.editCurrentPassword.text(), w.ui.labFilename.text())
    QApplication.restoreOverrideCursor()


def netipLogin():
    global cam
    if w.ui.tableWidget.selectedItems():
        selected_dev = w.ui.tableWidget.item(
            w.ui.tableWidget.currentRow(), 1).text()
        ip = w.ui.editIPAddress.text()
        username = w.ui.editUsername.text()
        password = w.ui.editCurrentPassword.text()

        if not cam.socket:
            QApplication.setOverrideCursor(Qt.WaitCursor)
            cam = DVRIPCam(ip, username=username, password=password)
            if cam.login():
                w.ui.status2.setText(w.tr(f"Connected to {ip}"))
            else:
                w.ui.status2.setText(w.tr("Login failed"))
            QApplication.restoreOverrideCursor()

            return cam
        else:
            w.ui.status2.setText(w.tr(f"Disconnected"))
            cam.close()


def netipSendCommand(command, *args):
    if cam.login():
        getattr(cam, command)(*args)
        w.ui.statusbar.showMessage(w.tr(f"{command} OK"))
    else:
        w.ui.statusbar.showMessage(w.tr("Command failed"))


def getDigitalChannels():
    global RemoteDeviceV3
    QApplication.setOverrideCursor(Qt.WaitCursor)
    if not debug:
        RemoteDeviceV3 = {}
        try:
            if cam.login():
                RemoteDeviceV3 = cam.get_info("NetWork.RemoteDeviceV3")
                r.show()
        except Exception as error:
            print(" ".join([str(x) for x in list(error.args)]))
    else:
        r.show()
    QApplication.restoreOverrideCursor()
    r.tableChannels.setRowCount(len(RemoteDeviceV3))
    count = 0
    for channel in RemoteDeviceV3:
        chkBoxEnable = QTableWidgetItem()
        chkBoxEnable.setFlags(
            QtCore.Qt.ItemIsUserCheckable | QtCore.Qt.ItemIsEnabled)
        if RemoteDeviceV3[count]['Enable']:
            chkBoxEnable.setCheckState(QtCore.Qt.Checked)
        else:
            chkBoxEnable.setCheckState(QtCore.Qt.Unchecked)
        r.tableChannels.setItem(count, 0, chkBoxEnable)

        r.tableChannels.setItem(
            count, 1, QTableWidgetItem(str(ChannelTitle[count])))

        comboSyncRes = QComboBox()
        comboSyncRes.setFrame(False)
        comboSyncRes.addItems(['False', 'True'])
        r.tableChannels.setCellWidget(count, 4, comboSyncRes)

        comboTimeSyn = QComboBox()
        comboTimeSyn.setFrame(False)
        comboTimeSyn.addItems(['OFF', 'T&Z', 'Local', 'UTC'])
        r.tableChannels.setCellWidget(count, 5, comboTimeSyn)

        comboDelayDecode = QComboBox()
        comboDelayDecode.setFrame(False)
        comboDelayDecode.addItems([str(int(x, 16)) for x in DecodeDeleyTime])
        r.tableChannels.setIndexWidget(
            r.tableChannels.model().index(count, 6), comboDelayDecode)

        comboProtocol = QComboBox()
        comboProtocol.setFrame(False)
        comboProtocol.addItems(['TCP', 'ONVIF', 'RTSP'])
        r.tableChannels.setCellWidget(count, 8, comboProtocol)

        if RemoteDeviceV3[count]['Decoder'] != 'null':
            r.tableChannels.setItem(count, 2, QTableWidgetItem(
                str(RemoteDeviceV3[count]['Decoder'][0]['IPAddress'])))
            r.tableChannels.setItem(count, 3, QTableWidgetItem(
                str(RemoteDeviceV3[count]['Decoder'][0]['Port'])))
            comboSyncRes.setCurrentText(
                str(not RemoteDeviceV3[count]['SynchResolution']))
            comboTimeSyn.setCurrentText(str(str(DigTimeSyn[count]['TimeSyn'])))
            comboDelayDecode.setCurrentText(
                str(DecodeParam[count]['deleyTimeMs']))
            r.tableChannels.setItem(count, 7, QTableWidgetItem(
                str(RemoteDeviceV3[count]['Decoder'][0]['Channel'])))
            comboProtocol.setCurrentText(
                str(RemoteDeviceV3[count]['Decoder'][0]['Protocol']))
            r.tableChannels.setItem(count, 9, QTableWidgetItem(
                RemoteDeviceV3[count]['Decoder'][0]['UserName']))
            r.tableChannels.setItem(count, 10, QTableWidgetItem(
                RemoteDeviceV3[count]['Decoder'][0]['PassWord']))
        count += 1


def btnDigitalChannelsSave():
    trow = []
    for row in range(16):
        for i in range(2, 7):
            try:
                trow.append(r.tableChannels.item(
                    r.tableChannels.verticalHeader().logicalIndex(row), i).text())
            except:
                print(" ".join([str(x) for x in list(error.args)]))
    print(trow)


def btnDigitalSearch():
    global NetLocalSearch
    QApplication.setOverrideCursor(Qt.WaitCursor)
    if not debug:
        NetLocalSearch = {}
        try:
            if cam.login():
                NetLocalSearch = cam.get_info("NetLocalSearch")
        except Exception as error:
            print(" ".join([str(x) for x in list(error.args)]))
    QApplication.restoreOverrideCursor()
    count = 0
    r.tableSearch.setRowCount(len(NetLocalSearch))
    for dev in NetLocalSearch:
        r.tableSearch.setItem(
            count, 0, QTableWidgetItem(ip2str(dev["HostIP"])))
        r.tableSearch.setItem(
            count, 1, QTableWidgetItem(str(dev["TCPPort"])))
        r.tableSearch.setItem(
            count, 2, QTableWidgetItem(dev["MAC"]))
        r.tableSearch.setItem(
            count, 3, QTableWidgetItem(dev["SN"]))
        devtype = {305201157: 'NVR', 305201156: 'DVR', 7: 'IPCWIFI', 0: 'IPC'}
        r.tableSearch.setItem(count, 4, QTableWidgetItem(dev["HostName"]))
        r.tableSearch.setItem(
            count, 5, QTableWidgetItem(str(dev["ChannelNum"])))
        r.tableSearch.setItem(
            count, 6, QTableWidgetItem(devtype[dev["DeviceType"]]))
        count += 1


def onComboSelectInterface():
    iface = str(w.ui.comboInterfaces.currentText())
    w.ui.comboIPAddresses.clear()
    for addr_info in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
        w.ui.comboIPAddresses.addItem(
            str(addr_info['addr']))
    w.ui.comboIPAddresses.setCurrentText(
        str(netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']))


if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setOrganizationName("OpenIPC")
    app.setOrganizationDomain("openipc.org")
    app.setApplicationName("DMS")
    settings = QSettings()
    # locale = getdefaultlocale()
    locale = 'ru'

    translator = QtCore.QTranslator(app)
    translator.load('res/%s.qm' % locale[0])
    app.installTranslator(translator)

    w = MainWindow()
    w.show()
    r = RemoteDevices()

    r.tableChannels.setColumnWidth(0, 5)
    r.tableChannels.setColumnWidth(1, 150)
    r.tableChannels.setColumnWidth(2, 110)
    r.tableChannels.setColumnWidth(3, 50)
    r.tableChannels.setColumnWidth(4, 75)
    r.tableChannels.setColumnWidth(5, 75)
    r.tableChannels.setColumnWidth(6, 75)
    r.tableChannels.setColumnWidth(7, 50)
    r.tableChannels.setColumnWidth(8, 65)
    r.tableChannels.setColumnWidth(9, 75)
    r.tableChannels.setColumnWidth(10, 85)
    # r.tableChannels.horizontalHeader().setSectionResizeMode(QHeaderView.Fixed)
    r.tableChannels.verticalHeader().setSectionResizeMode(QHeaderView.Fixed)
    r.tableChannels.verticalHeader().setSectionsMovable(True)
    r.tableChannels.verticalHeader().setAcceptDrops(True)
    r.btnDigitalChannelsSave.clicked.connect(btnDigitalChannelsSave)

    r.tableSearch.setColumnWidth(0, 110)
    r.tableSearch.setColumnWidth(1, 50)
    r.tableSearch.setColumnWidth(2, 120)
    r.tableSearch.setColumnWidth(3, 155)
    r.tableSearch.setColumnWidth(4, 200)
    r.tableSearch.setColumnWidth(5, 50)
    r.tableSearch.verticalHeader().setSectionsMovable(True)
    r.btnDigitalSearch.clicked.connect(btnDigitalSearch)

    w.ui.btnAutoIP.clicked.connect(w.btnAutoIP)
    w.ui.searchDevices.clicked.connect(onBtnSearch)
    w.ui.btnBrowse.clicked.connect(w.filedialog)
    w.ui.btnSave.clicked.connect(btnSave)
    w.ui.btnUpgrade.clicked.connect(btnUpgrade)
    w.ui.btnReboot.clicked.connect(lambda: netipSendCommand("reboot"))
    w.ui.btnDigitalChannels.clicked.connect(getDigitalChannels)
    w.ui.btnChangePassword.clicked.connect(w.btnChangePassword)
    w.ui.tableWidget.cellClicked.connect(w.onRowClick)
    w.ui.tableWidget.cellDoubleClicked.connect(netipLogin)
    w.ui.comboInterfaces.currentTextChanged.connect(onComboSelectInterface)

    w.ui.tableWidget.horizontalHeader().resizeSection(0, 1)
    w.ui.tableWidget.horizontalHeader().setSectionResizeMode(
        QHeaderView.ResizeToContents)

    w.ui.statusbar.setFixedHeight(25)
    w.ui.statusbar.showMessage(w.tr("Idle"))
    w.ui.status2 = QLabel("Disconnected")
    w.ui.statusbar.addPermanentWidget(w.ui.status2)

    # need to find replacement for netifaces, no binary builds for python 3.10 on windows
    hostinterfaces = netifaces.interfaces()
    hostdefaultgw = netifaces.gateways()['default'][netifaces.AF_INET][1]
    badinterfaces = ['lo', 'docker', 'veth', 'vbox']
    for iface in hostinterfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in addrs:
            badinterfaces.append(iface)
    w.ui.comboInterfaces.addItems(
        [x for x in hostinterfaces if not any(x.startswith(s) for s in badinterfaces)])
    if hostdefaultgw:
        w.ui.comboInterfaces.setCurrentText(hostdefaultgw)

    sys.exit(app.exec_())
