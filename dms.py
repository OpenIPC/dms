#!/usr/bin/env python3

import os
import sys
import struct
import json
from locale import getdefaultlocale
from subprocess import check_output
from socket import *
import platform
from datetime import *
import hashlib
import base64

import netifaces
import logging

from dvrip import DVRIPCam

from PyQt5.QtWidgets import *
from PyQt5.QtGui import *
from PyQt5 import uic, QtCore
from PyQt5.QtCore import Qt, QSettings

(Ui_MainWindow, QMainWindow) = uic.loadUiType('dms.ui')

cam = DVRIPCam('')

if os.path.exists('debug'):
    debug = True
else:
    debug = False

if debug:
    debugLevel = logging.DEBUG
    devices = ({'00:00:00:00:00:64': {'ChannelNum': 9, 'DeviceType': 4, 'GateWay': '0xFE01A8C0', 'HostIP': '0x0A01A8C0', 'HostName': 'NBD80N32RA-KL', 'HttpPort': 80, 'MAC': '00:00:00:00:00:64', 'MaxBps': 0, 'MonMode': 'TCP', 'NetConnectState': 0, 'OtherFunction': 'D=2023-03-21 13:21:32 V=78775aada187e84', 'SN': '0000000000000081', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'TransferPlan': 'Quality', 'UDPPort': 34568, 'UseHSDownLoad': False, 'Brand': 'xm'}, '00:00:00:00:00:17': {'ChannelNum': 1, 'DeviceType': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x0801A8C0', 'HostName': 'LocalHost', 'HttpPort': 80, 'MAC': '00:00:00:00:00:17', 'MaxBps': 0, 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=1482fd4408e15a7', 'SN': '0000000000000006', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'TransferPlan': 'Quality', 'UDPPort': 34568, 'UseHSDownLoad': False, 'Brand': 'xm'}, '00:00:00:00:00:1e': {'BuildDate': '2020-07-04 09:25:14', 'ChannelNum': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x0701A8C0', 'HostName': 'IVG-85HF20PYA-S', 'HttpPort': 80, 'MAC': '00:00:00:00:00:1e', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=d0384e6d8a46c2f', 'SN': '0000000000000033', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': True, 'Version': 'V5.00.R02.000559A7.10010.040400.0020000', 'Brand': 'xm'}, '00:00:00:00:00:48': {'BuildDate': '2022- 2-23 16:34: 0', 'ChannelNum': 1, 'DeviceType': 0, 'GateWay': '0xFE01A8C0', 'HostIP': '0x0501A8C0', 'HostName': 'IVG-N4', 'HttpPort': 80, 'MAC': '00:00:00:00:00:48', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:33 V=a721ad83d521bc7',
               'SN': '000000000000002a', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': False, 'Version': 'V5.00.R02.000629G3.10010.140200.0020000', 'Brand': 'xm'}, '00:00:00:00:00:6b': {'BuildDate': '2020-07-04 09:25:14', 'ChannelNum': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x0401A8C0', 'HostName': 'IVG-85HF20PYA-S', 'HttpPort': 80, 'MAC': '00:00:00:00:00:6b', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:33 V=088a5643e0387f2', 'SN': '0000000000000095', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': False, 'Version': 'V5.00.R02.000559A7.10010.040400.0020000', 'Brand': 'xm'}, '00:00:00:00:00:43': {'BuildDate': '2020-07-04 09:25:14', 'ChannelNum': 1, 'GateWay': '0x0201A8C0', 'HostIP': '0x0601A8C0', 'HostName': 'IVG-85HF20PYA-S', 'HttpPort': 80, 'MAC': '00:00:00:00:00:43', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=6d1150f906f4948', 'SN': '0000000000000039', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': False, 'Version': 'V5.00.R02.000559A7.10010.040400.0020000', 'Brand': 'xm'}, '00:00:00:00:00:22': {'BuildDate': '2020- 9- 1 14:38:48', 'ChannelNum': 1, 'GateWay': '0x0101A8C0', 'HostIP': '0x6414A8C0', 'HostName': 'camera_', 'HttpPort': 80, 'MAC': '00:00:00:00:00:22', 'MonMode': 'TCP', 'NetConnectState': 1, 'OtherFunction': 'D=2023-03-21 13:21:34 V=bdf396972028edf', 'SN': '0000000000000061', 'SSLPort': 8443, 'Submask': '0x00FFFFFF', 'TCPMaxConn': 10, 'TCPPort': 34567, 'UDPPort': 34568, 'UseHSDownLoad': True, 'Version': 'V5.00.R02.000529B2.10010.040600.0020000', 'Brand': 'xm'}})
else:
    debugLevel = logging.INFO
    devices = {}


def log(*args):
    # logging.debug(*args)
    print(*args)


logging.basicConfig(format='%(asctime)s> %(message)s',
                    level=debugLevel, datefmt='[%H:%M:%S]')


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
        self.ui.statusbar.showMessage(selected_dev)


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
    server = socket(AF_INET, SOCK_DGRAM)
    server.bind((w.ui.comboIPAddresses.currentText(), 34569))
    server.settimeout(2)
    server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    server.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
    server.sendto(
        struct.pack("BBHIIHHI", 255, 0, 0, 0, 0, 0,
                    1530, 0), ("255.255.255.255", 34569)
    )
    while True:
        data = server.recvfrom(1024)
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
    QApplication.restoreOverrideCursor


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
        server.settimeout(1)
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

        QApplication.setOverrideCursor(Qt.WaitCursor)
        if not cam.socket:
            cam = DVRIPCam(ip, username=username, password=password)
            if cam.login():
                w.ui.statusbar.showMessage(w.tr("Connected"))
            else:
                w.ui.statusbar.showMessage(w.tr("Login failed"))
            QApplication.restoreOverrideCursor()
            return cam


def netipSendCommand(command, *args):
    if cam.login():
        getattr(cam, command)(*args)
        w.ui.statusbar.showMessage(w.tr(f"{command} OK"))
    else:
        w.ui.statusbar.showMessage(w.tr("Command failed"))


def getDigitalChannels():
    if cam.login():
        info = cam.get_info("NetWork.RemoteDeviceV3")
        print(json.dumps(info, ensure_ascii=False))


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
    w.ui.statusbar.showMessage(w.tr("Idle"))

    # need to find replacement for netifaces, no binary buidls for python 3.10 on windows
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
