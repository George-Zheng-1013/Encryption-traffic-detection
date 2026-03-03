import numpy as np
import torch
from torch.utils.data import DataLoader, Dataset
import torch.nn as nn
import torch.nn.functional as F
import torch.optim as optim
from torch.optim import lr_scheduler
from torchvision import transforms
from RSGmain.RSG import *
import gzip
import os
import torchvision
import cv2
import matplotlib.pyplot as plt


a = torch.rand(5,1,1,1)

num, C,H,W= a.size()
print(num//2)
if(num // 2 != 0):
    a1 = a[0:num//2,:,:,:]
    c = torch.zeros(1,C,H,W)
    a1 = torch.cat([a1,c],dim = 0)
    print(a1.size())
    a2 = a[num//2:num,:,:,:]


target_cat = torch.cat([a1,a2],dim=1)

print(target_cat)