# get packet only have payload
import sys
import struct
import os
from PIL import Image
import binascii
import errno
import os
import numpy
from scapy.all import *
from scapy.layers.inet import TCP
import dpkt
import gevent
from gevent import monkey
import logging
import shutil
import random

# path_packet=[['vpn-five-tuple','packet-feature\\train','packet-feature\\test']]
# path_packet = [['6class-vpn', 'packet-feature-Linear\\train', 'packet-feature-Linear\\test']]

# path_packet=[['dataset','packet-feature-Linear\\train','packet-feature-Linear\\test']]
path_packet=[['vpn_dataset','packet-vpn\\train','packet-vpn\\test']]
path_png = [['packet-vpn\\train','png-vpn\\train'],['packet-vpn\\test','png-vpn\\test']]
PACKET_LEN = 784
PNG_SIZE = 28
ALL_COUNT = 10000
TRAIN_COUNT = 9000
TEST_COUNT = 1000


# 日志
logger = logging.getLogger(__name__)


# get packet
def getPacket(dir, savetrain, savetest):

    packetin = rdpcap(dir)

    # filein_obj = pcap_open(dir)  # 文件对象
    # packetin = pcap_reader(filein_obj)  # 读取数据包

    payload_all = []
    for pkt in packetin:
        # 数据链路层
        pkt = ip_shield(pkt)

        payload = raw(pkt)
        length = len(payload)

        if pkt.haslayer('UDP'):
            length = len(pkt['UDP'].payload)
        if pkt.haslayer('TCP'):
            length = len(pkt['TCP'].payload)

        #if length > 0 and length < 1360:
        if length > 0 and length < 1520:
            payload = zeropadding_fixedlength(payload, 50)
            payload_all = combine(bytes(payload_all), payload)
            if len(payload_all) > PACKET_LEN:
                global count  # 全局变量
                count += 1
                # threading
                if count % 1000 == 0:
                    gevent_threading_patch()
                # if count < ALL_COUNT:
                #     savelist = savetrain + "." + str(count) + ".pcap"
                #     # 保存为pcap格式
                #     fileout_obj = open(savelist, 'wb')  # 文件对象
                #     packetout = dpkt.pcap.Writer(fileout_obj)  # 读取数据包
                #     packetout.writepkt(payload_all)  # 补零
                if count < TRAIN_COUNT:
                    savelist = savetrain + "." + str(count) + ".pcap"
                    # 保存为pcap格式
                    fileout_obj = open(savelist, 'wb')  # 文件对象
                    packetout = dpkt.pcap.Writer(fileout_obj)  # 读取数据包
                    packetout.writepkt(payload_all)  # 补零
                elif count >= TRAIN_COUNT and count < TRAIN_COUNT + TEST_COUNT:
                    savelist = savetest + "." + str(count) + ".pcap"
                    # 保存为pcap格式
                    fileout_obj = open(savelist, 'wb')  # 文件对象
                    packetout = dpkt.pcap.Writer(fileout_obj)  # 读取数据包
                    packetout.writepkt(payload_all)  # 补零
                else:
                    break
                payload_all = []



# ip_shield
def ip_shield(pkt):
    if pkt.haslayer('Ether'):
        pkt.src = "00:00:00:00:00:00"
        pkt.dst = "00:00:00:00:00:00"
    
    if pkt.haslayer('IP'):
        pkt['IP'].src = "00.00.00.00"
        pkt['IP'].dst = "00.00.00.00"
        pkt.sport = 0
        pkt.dport = 0

    return pkt

# zeropadding
def zeropadding_fixedlength(p, n):
    data = list(p)
    # 填充数据到固定长度
    data += [0 for _ in range(n)]  # 填充数据
    data = bytes(data)
    return data


# zeropadding
def zeropadding(p):
    data = list(p)
    length = len(p)
    if length < PACKET_LEN:
        # 填充数据到固定长度
        data += [0 for _ in range(PACKET_LEN - length)]
    data = bytes(data)
    return data


# cutLength
def cutlength(p, l):
    data = list(p)
    data = data[l:]
    data = bytes(data)
    return data


# getpayload
def getpayload(data):
    data = bytearray(data)
    del (data[0:39])
    return data


# combine
def combine(a, b):
    a = list(a)
    b = list(b)
    a = a + b
    data = bytes(a)
    return data


# open pcap
def pcap_open(filepath):
    file_obj = None
    # 二进制模式打开
    file_obj = open(filepath, 'rb')

    return file_obj


# close pcap
def pcap_close(file_obj):
    try:
        file_obj.close()
    except:
        pass


# pcap reader
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


# change time format
def utc_2_str(timestamp):
    ltime = time.localtime(timestamp)
    stime = time.strftime('%Y-%m-%d %H:%M:%S', ltime)
    return stime


# threading
# 在进行多线程时monkey会阻塞住线程的继续执行，需要对monkey.patch_all进行处理, 在实例中添加一个sleep()可以解决,这里时间可以设置一个非常小的数就可以了
def gevent_threading_patch():
    if monkey.is_module_patched('threading'):
        gevent.sleep(0.000001)

# move/copy file

def movefile(filedir, tardir,rate):
    pathdir = os.listdir(filedir)  # 取数据集的原始路径
    filenumber = len(pathdir)
    # 自定义抽取数据集的比例，比方说1000张抽100张，那就是0.1
    picknumber = int(filenumber * rate)  # 按照rate比例从数据集中取一定数量文件
    samples = random.sample(pathdir, picknumber)  # 随机选取picknumber数量的文件
    count = 1 #计数变量
    for sample in samples:# 当前目录下选取的数据
        if sample.endswith(".pcap") or sample.endswith(".pcapng"): # 查看选取的是否是jpg图片
            shutil.move(filedir + '\\' + sample, tardir + '\\' + sample)
            # shutil.move(filedir + os.path.splitext(sample)[0] + '.txt', tardir + os.path.splitext(sample)[0] + '.txt')
            count += 1
        # if(count == 1001): # 移动的图片已经超过总数据集的10%，跳出
        #     break



# build path
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise


# delete pcapheader and packetheader(40 byte)
def deleteHeader(content):
    data = list(content)
    data = data[40:]
    data = bytes(data)
    return data


# packet to matrix


def getLinearMatrixfrom_pcap(filename, width):
    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content)  # pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i + 2], 16) for i in range(0, len(hexst), 2)])
    # rn = len(fh)/width
    fh = numpy.reshape(fh[:int(width) * width], (-1, width))
    fh = numpy.uint8(fh)
    return fh

def getDiagonalMatrixfrom_pcap(filename,width):
    hang_=[]
    lie_=[]
    out =numpy.zeros((width,width))

    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content) #pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)

    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])

    for i in range(width+width-1):
        for j in range(i+1):
            k = i-j
            if k<width and k>=0 and j<width:
                hang_.append(k)
                lie_.append(j)

    for index, item in enumerate(fh):
        if index < PACKET_LEN :
            out[hang_[index]][lie_[index]] = item
        else :
            break

    fh = numpy.reshape(out[:int(width)*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh


def getWaterfallMatrixfrom_pcap(filename,width):

    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content) #pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    fh = fh[0:PACKET_LEN]
    out = numpy.zeros((width, width))

    #waterfall 构图
    for i in range(0, width):
        out[i][i] = fh[i * i]
        for j in range(0, i):
            out[i][j] = fh[i * i + (i - j) * 2]
            out[j][i] = fh[i * i + (i - j) * 2 - 1]

    fh = numpy.reshape(out[:int(width)*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh


def getantiWaterfallMatrixfrom_pcap(filename,width):

    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content) #pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    fh = fh[0:PACKET_LEN]
    out = numpy.zeros((width, width))

    #waterfall 构图
    for i in range(0, width):
        out[i][i] = fh[width * width - (width - i) * (width - i)]
        for j in range(i + 1, width):
            out[i][j] = fh[width * width - (width - i) * (width - i) + (j - i) * 2 - 1]
            out[j][i] = fh[width * width - (width - i) * (width - i) + (j - i) * 2]

    fh = numpy.reshape(out[:int(width)*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh

def getCenterSpiralMatrixfrom_pcap(filename,width):

    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content) #pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    fh = fh[0:PACKET_LEN]
    out = numpy.zeros((width, width))
    i, j, side = int((width - 1) / 2), int(width / 2), width - 1
    for item in fh:
        # print(i,j)
        out[i][j] = item
        if (i < j) and (i + j <= side):
            j = j - 1
        elif (i >= j) and (i + j < side):
            i = i + 1
        elif (i >= j) and (i + j >= side):
            j = j + 1
        elif (i < j) and (i + j > side):
            i = i - 1
    fh = numpy.reshape(out[:int(width)*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh



def getEdgeCenterSpiralMatrixfrom_pcap(filename,width):

    with open(filename, 'rb') as f:
        content = f.read()
    content = deleteHeader(content) #pcap头
    content = zeropadding(content)
    hexst = binascii.hexlify(content)
    fh = numpy.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    fh = fh[0:PACKET_LEN]

    fh = fh[::-1]  # 数组反转

    out = numpy.zeros((width, width))
    i, j, side = int((width - 1) / 2), int(width / 2), width - 1
    for item in fh:
        # print(i,j)
        out[i][j] = item
        if (i < j) and (i + j <= side):
            j = j - 1
        elif (i >= j) and (i + j < side):
            i = i + 1
        elif (i >= j) and (i + j >= side):
            j = j + 1
        elif (i < j) and (i + j > side):
            i = i - 1
    fh = numpy.reshape(out[:int(width)*width],(-1,width))
    fh = numpy.uint8(fh)
    return fh



if __name__ == '__main__':

    for p in path_packet:
        dirlist = os.listdir(p[0])
        for i, d in enumerate(os.listdir(p[0])):
            count = -1  # 计数器（记录每一类存储的数据的数量）
            #trainsavelist = ''
            #testsavelist = ''
            for f in os.listdir(os.path.join(p[0], d)):
                if count == ALL_COUNT:
                    break
                dirfulllist = os.path.join(os.getcwd(), p[0], d, f)
                print(dirfulllist)
                mkdir_p(os.path.join(os.getcwd(), p[1], d))  # 生成路径
                mkdir_p(os.path.join(os.getcwd(), p[2], d))
                trainsavelist = os.path.join(os.getcwd(), p[1], d, f)
                #print(trainsavelist)
                testsavelist = os.path.join(os.getcwd(), p[2], d, f)
                #print(testsavelist)
                getPacket(dirfulllist, trainsavelist, testsavelist)

                 # trainsavelist = os.path.split(trainsavelist)[0]
                 #testsavelist = os.path.split(testsavelist)[0]
                 # movefile(trainsavelist, testsavelist,rate=0.2)



    for p in path_png:
        for i, d in enumerate(os.listdir(p[0])):
            dir_full = os.path.join(p[1], str(i))
            mkdir_p(dir_full)
            print(dir_full)
            for f in os.listdir(os.path.join(p[0], d)):
                bin_full = os.path.join(p[0], d, f)
                im = Image.fromarray(getLinearMatrixfrom_pcap(bin_full, PNG_SIZE))
                png_full = os.path.join(dir_full, os.path.splitext(f)[0] + '.png')
                im.save(png_full)
