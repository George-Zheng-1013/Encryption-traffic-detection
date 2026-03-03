import os
import matplotlib.pyplot as plt

from os.path import join, getsize


def getdirsize(dir):
    size = 0
    for root, dirs, files in os.walk(dir):
        size += sum([getsize(join(root, name)) for name in files])
    return size


dirpath = 'png-10\\train'
sz = []
for i in range(0,5):
    sz.append(getdirsize(dirpath + '\\' + str(i)))

plt.bar(range(len(sz)), sz)
plt.show()

print(sz)