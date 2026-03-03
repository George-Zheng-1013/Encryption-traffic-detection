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
# path_packet=[['16lei','packet-feature\\train','packet-feature\\test']]
# path_png = [['packet-feature\\train','png-feature\\train'],['packet-feature\\test','png-feature\\test']]
path_packet=[['10lei','packet-10\\train','packet-10\\test']]
path_png = [['packet-10\\train','png-10\\train'],['packet-10\\test','png-10\\test']]
PACKET_LEN = 784
PNG_SIZE = 28
TRAIN_COUNT = 1000
TEST_COUNT = 200




# 日志
logger = logging.getLogger(__name__)
#get packet
def getPacket(dir,savetrain,savetest):  #dir == dirfulllist（data-test）
    filein_obj = pcap_open(dir) #文件对象
    packetin = pcap_reader(filein_obj)  # 读取数据包
    payload_all = []
    for (timestamp, pkt) in packetin:
        # 数据链路层
        eth = dpkt.ethernet.Ethernet(pkt)
        # 网络层
        if isinstance(eth.data, dpkt.ip.IP):
            ip = eth.data
        else :
            continue

        # 传输层
        if isinstance(ip.data, dpkt.tcp.TCP):  # TCP
            tcp = ip.data
            if tcp.flags == 16:  # ACK
                continue
            payload = tcp.data
            length =len(payload)
        elif isinstance(ip.data, dpkt.udp.UDP):  # UDP
            udp = ip.data
            payload = udp.data
            length = len(payload)
        else :
            continue

        if length > 0 and length < 800 :
            payload = zeropadding_fixedlength(payload,50)   #
            payload_all = combine(bytes(payload_all), payload)
            if len(payload_all) > PACKET_LEN :
                global count  # 全局变量
                count += 1
                # threading
                if count % 1000 == 0: #取余=0 count是1000的倍数 =1000
                    gevent_threading_patch()
                if count < TRAIN_COUNT: # < 1000
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
    pcap_close(filein_obj)


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
    try:
        # .pcap文件
        reader = dpkt.pcap.Reader(file_obj)
    except Exception as e:
        logger.info('获取pcap.Reader失败: {}.'.format(repr(e)))
        pass
    try:
        if not reader:
            # .pcapng文件
            reader = dpkt.pcapng.Reader(file_obj)
    except Exception as e:
        logger.info('获取pcapng.Reader失败: {}.'.format(repr(e)))
        pass

    if not reader:
        logger.warning('解析器不支持的文件类型.')

    return reader

#change time format
def utc_2_str(timestamp):
    ltime = time.localtime(timestamp)
    stime = time.strftime('%Y-%m-%d %H:%M:%S', ltime)
    return stime

#threading
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
def getMatrixfrom_pcap(filename,width):  #pcap -> 矩阵 (数组)
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
    for p in path_packet:   #path_packet=[['data-test','packet-feature1\\train','packet-feature1\\test']]
        dirlist = os.listdir(p[0]) #获取文件路径  p[0] == data-test
        for  i,d in enumerate(os.listdir(p[0])): # i == 0123456..., d == data-test里的文件夹名
            count = -1  # 计数器（记录每一类存储的数据的数量） 这一步相当于清零计数器
            for f in os.listdir(os.path.join(p[0], d)):
                if count == TRAIN_COUNT + TEST_COUNT:
                    break
                dirfulllist = os.path.join(os.getcwd(), p[0], d,f) #data-test文件夹里的文件路径
                print(dirfulllist)
                mkdir_p(os.path.join(os.getcwd(), p[1],d))  # 生成路径 生成packet-feature1\\train
                mkdir_p(os.path.join(os.getcwd(), p[2],d))  #生成 packet-feature1\\test
                trainsavelist = os.path.join(os.getcwd(), p[1], d ,f) #train 文件存储路径
                testsavelist = os.path.join(os.getcwd(), p[2], d ,f)  #test 文件
                getPacket(dirfulllist, trainsavelist, testsavelist)

    for p in path_png:  #path_png = [['packet-feature1\\train','png-feature1\\train'],['packet-feature1\\test','png-feature1\\test']]
        for i, d in enumerate(os.listdir(p[0])): #p[0] == packet-feature1\\train or packet-feature1\\test d == packet-feature1\\train里的文件夹
            dir_full = os.path.join(p[1], str(i))  #png-feature1\\train\\0,1,2,...
            mkdir_p(dir_full)#生成文件夹 png-feature1\\train\\0,1,2,...
            print(dir_full)
            for f in os.listdir(os.path.join(p[0], d)): #d == packet-feature1\\train\\chat,...
                bin_full = os.path.join(p[0], d, f)     #packet-feature1\\train\\chat,...\\...
                im = Image.fromarray(getMatrixfrom_pcap(bin_full, PNG_SIZE))  #矩阵转图像
                png_full = os.path.join(dir_full, os.path.splitext(f)[0] + '.png') #图像路径命名与packet-feature里一致
                im.save(png_full) #保存图像