#get packet only have payload
import sys
import struct
import os
from PIL import Image
import binascii
import errno
import os
import numpy
from scapy.all import *
import dpkt
import gevent
from gevent import monkey
import logging

# path_packet=[['vpn-five-tuple','packet-feature\\train','packet-feature\\test']]
path_packet=[['nonvpn_dataset','packet-nonvpn\\train','packet-nonvpn\\test']]
# path_png = [['packet-feature\\train','png-feature\\train'],['packet-feature\\test','png-feature\\test']]
# path_packet=[['data-test','packet-feature\\train','packet-feature\\test']]
path_png = [['packet-nonvpn\\train','png-nonvpn\\train'],['packet-nonvpn\\test','png-nonvpn\\test']]
PACKET_LEN = 784
PNG_SIZE = 28
TRAIN_COUNT = 9000
TEST_COUNT = 1000




# 日志
logger = logging.getLogger(__name__)
#get packet
def getPacket(dir,savetrain,savetest):


    filein_obj = pcap_open(dir) #文件对象
    packetin = pcap_reader(filein_obj)  # 读取数据包
    # packetin = rdpcap(dir)

    payload_all = []
    for (timestamp, pkt) in packetin:
        # 数据链路层
        eth = dpkt.ethernet.Ethernet(pkt)
        # 网络层
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
            ip.src = b'\x00\x00\x00\x00'
            ip.dst = b'\x00\x00\x00\x00'
        else :
            continue

        # 传输层
        if isinstance(ip.data, dpkt.tcp.TCP):  # TCP
            tcp = ip.data
            tcp.dport = 0
            tcp.sport = 0
            if tcp.flags == 16:  # ACK
                continue
            payload = raw(ip)
            length =len(payload)

        elif isinstance(ip.data, dpkt.udp.UDP):  # UDP
            udp = ip.data
            udp.dport = 0
            udp.sport = 0
            payload = raw(ip)
            length = len(payload)

        else :
            continue

        if length > 0 and length < 1520 :
            payload = zeropadding_fixedlength(payload,50)
            payload_all = combine(bytes(payload_all), payload)
            if len(payload_all) > PACKET_LEN :
                global count  # 全局变量
                count += 1
                # threading
                if count % 1000 == 0:
                    gevent_threading_patch()
                if count < TRAIN_COUNT:
                    savelist = savetrain + "." + str(count) + ".pcap"
                    # 保存为pcap格式
                    fileout_obj = open(savelist, 'wb')  # 文件对象
                    packetout = dpkt.pcap.Writer(fileout_obj)  # 读取数据包
                    packetout.writepkt(payload_all, ts=timestamp)  # 补零
                elif count >= TRAIN_COUNT and count < TRAIN_COUNT + TEST_COUNT:
                    savelist = savetest + "." + str(count) + ".pcap"
                    # 保存为pcap格式
                    fileout_obj = open(savelist, 'wb')  # 文件对象
                    packetout = dpkt.pcap.Writer(fileout_obj)  # 读取数据包
                    packetout.writepkt(payload_all, ts=timestamp)  # 补零
                else:
                    break
                payload_all = []
    #pcap_close(filein_obj)
    pcap_close(packetin)


#zeropadding
def zeropadding_fixedlength(p,n):
    data = list(p)
    # 填充数据到固定长度
    data += [0 for _ in range(n)]  #填充数据
    data = bytes(data)
    return data

#zeropadding
def zeropadding(p):
    data = list(p)
    length = len(p)
    if length < PACKET_LEN:
        # 填充数据到固定长度
        data += [0 for _ in range(PACKET_LEN - length)]
    data = bytes(data)
    return data

#cutLength
def cutlength(p,l):
    data = list(p)
    data = data[l:]
    data = bytes(data)
    return data

#getpayload
def getpayload(data):
    data = bytearray(data)
    del(data[0:39])
    return data

#combine
def combine(a,b):
    a = list(a)
    b = list(b)
    a = a+b
    data = bytes(a)
    return data

#open pcap
def pcap_open(filepath):
    file_obj = None
    # 二进制模式打开
    file_obj = open(filepath, 'rb')
    # magic_head = file_obj.read(4)
    # file_obj.seek(0, 0)
    # if magic_head == b'\n\r\r\n':
    #     pcap_reader = dpkt.pcapng.Reader(file_obj)
    # elif magic_head == b'\xd4\xc3\xb2\xa1':
    #     pcap_reader = dpkt.pcap.Reader(file_obj)
    # else:
    #     print("[DEBUG in PcapUtils] It is not a pcap or pcapng file")
    #     exit(1)
    return file_obj

#close pcap
def pcap_close(file_obj):
    try:
        file_obj.close()
    except:
        pass

#pcap reader
def pcap_reader(file_obj):
    reader = None
    # try:
    #     # .pcap文件
    #     reader = dpkt.pcap.Reader(file_obj)
    # except Exception as e:
    #     logger.info('获取pcap.Reader失败: {}.'.format(repr(e)))
    #     pass
    # try:
    #     if not reader:
    #         # .pcapng文件
    #         reader = dpkt.pcapng.Reader(file_obj)
    # except Exception as e:
    #     logger.info('获取pcapng.Reader失败: {}.'.format(repr(e)))
    #     pass
    #
    # if not reader:
    #     logger.warning('解析器不支持的文件类型.')
    magic_head = file_obj.read(4)
    file_obj.seek(0, 0)
    if magic_head == b'\n\r\r\n':
        reader = dpkt.pcapng.Reader(file_obj)
    elif magic_head == b'\xd4\xc3\xb2\xa1':
        reader = dpkt.pcap.Reader(file_obj)
    else:
        print("[DEBUG in PcapUtils] It is not a pcap or pcapng file")
        exit(1)
    return reader

#change time format
def utc_2_str(timestamp):
    ltime = time.localtime(timestamp)
    stime = time.strftime('%Y-%m-%d %H:%M:%S', ltime)
    return stime

#threading
#在进行多线程时monkey会阻塞住线程的继续执行，需要对monkey.patch_all进行处理, 在实例中添加一个sleep()可以解决,这里时间可以设置一个非常小的数就可以了
def gevent_threading_patch():
    if monkey.is_module_patched('threading'):
        gevent.sleep(0.000001)
#build path
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

#delete pcapheader and packetheader(40 byte)
def deleteHeader(content):
    data = list(content)
    data = data [40:]
    data = bytes(data)
    return data

# packet to matrix


def getMatrixfrom_pcap(filename,width):
    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content) #pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    #rn = len(fh)/width
    fh = numpy.reshape(fh[:int(width)*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh




if __name__ == '__main__':
    for p in path_packet:
        dirlist = os.listdir(p[0])
        for i, d in enumerate(os.listdir(p[0])):
            count = -1  # 计数器（记录每一类存储的数据的数量）
            for f in os.listdir(os.path.join(p[0], d)):
                if count == TRAIN_COUNT + TEST_COUNT:
                    break
                dirfulllist = os.path.join(os.getcwd(), p[0], d, f)
                print(dirfulllist)
                mkdir_p(os.path.join(os.getcwd(), p[1], d))  # 生成路径
                mkdir_p(os.path.join(os.getcwd(), p[2], d))
                trainsavelist = os.path.join(os.getcwd(), p[1], d, f)
                testsavelist = os.path.join(os.getcwd(), p[2], d, f)
                getPacket(dirfulllist, trainsavelist, testsavelist)

    for p in path_png:
        for i, d in enumerate(os.listdir(p[0])):
            dir_full = os.path.join(p[1], str(i))
            mkdir_p(dir_full)
            print(dir_full)
            for f in os.listdir(os.path.join(p[0], d)):
                bin_full = os.path.join(p[0], d, f)
                im = Image.fromarray(getMatrixfrom_pcap(bin_full, PNG_SIZE))
                png_full = os.path.join(dir_full, os.path.splitext(f)[0] + '.png')
                im.save(png_full)