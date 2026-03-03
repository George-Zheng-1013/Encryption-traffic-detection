from scapy.all import *
import os
import random
import shutil
import sys

#path_packet=[['png-10/Train/0','png-10/Test/0'],['png-10/Train/1','png-10/Test/1'],['png-10/Train/2','png-10/Test/2'],['png-10/Train/3','png-10/Test/3'],['png-10/Train/4','png-10/Test/4'],['png-10/Train/5','png-10/Test/5'],['png-10/Train/6','png-10/Test/6'],['png-10/Train/7','png-10/Test/7'],['png-10/Train/8','png-10/Test/8'],['png-10/Train/9','png-10/Test/9']]
path_packet=[['png-10/train/0','png-10/test/0'],['png-10/train/1','png-10/test/1'],['png-10/train/2','png-10/test/2']]
# path_packet=[['4_Png/Train/0','4_Png/Test/0']]
# path_packet=[['4_Png/Train/SsrFacebook','4_Png/Test/SsrFacebook'],['4_Png/Train/SsrTelegram','4_Png/Test/SsrTelegram'],['4_Png/Train/SsrTwitter','4_Png/Test/SsrTwitter'],['4_Png/Train/SsrYoutube','4_Png/Test/SsrYoutube']]

def movefile(filedir, tardir):
    pathdir = os.listdir(filedir)  # 取数据集的原始路径
    filenumber = len(pathdir)
    rate = 0.101 # 自定义抽取数据集的比例，比方说1000张抽100张，那就是0.1
    picknumber = int(filenumber * rate)  # 按照rate比例从数据集中取一定数量文件
    samples = random.sample(pathdir, picknumber)  # 随机选取picknumber数量的文件
    count = 1 #计数变量
    for sample in samples:# 当前目录下选取的数据
        if sample.endswith(".png"): # 查看选取的是否是jpg图片
            shutil.move(filedir + sample, tardir + sample)
            # shutil.move(filedir + os.path.splitext(sample)[0] + '.txt', tardir + os.path.splitext(sample)[0] + '.txt')
            count += 1
        if(count == 1001): # 移动的图片已经超过总数据集的10%，跳出
            break
    return

#build path
def mkdir_p(path):
    try:
        os.makedirs(path)
    except OSError as exc:
        if exc.errno == errno.EEXIST and os.path.isdir(path):
            pass
        else:
            raise

if __name__ == '__main__':

    # # filedir = 'D:/VPN/vpn_classifier20201104/png/ExpressTelegram/'  # 源数据集文件夹路径
    # # tardir = 'D:/VPN/vpn_classifier20201104/4_Png/Train/0/'  # 移动到新的文件夹路径
    # filedir = 'D:/VPN/vpn_classifier20201104/4_Png/Train/3/'
    # tardir ='D:/VPN/vpn_classifier20201104/4_Png/Test/3/'
    # # filedir = 'D:/VPN/VPN_classifier20201031/4_Png_04_784/Train/4/'
    # # tardir ='D:/VPN/VPN_classifier20201031/4_Png_04_784/Test/4/'
    # movefile(filedir, tardir)


    for p in path_packet:
        dirlist = os.listdir(p[0])
        # print(dirlist)
        dirfulllist = os.path.join(os.getcwd(), p[0])
        print(dirfulllist)
        testpath = os.path.join(os.getcwd(), p[1])
        print(testpath)
        mkdir_p(testpath)

        movefile(dirfulllist+'/', testpath+'/')




