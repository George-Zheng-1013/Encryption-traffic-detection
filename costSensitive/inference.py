import os
import csv
import torch
import torch.nn.functional as F
from torch.utils.data import DataLoader
from torchvision import transforms
from RSG_pytroch_CNN784 import ConvNet, DealDataset, DEVICE  # 使用已定义的类/常量

DATA_DIR = os.path.join("processed_full", "mnist")

# 数据路径与文件名与训练时一致
test_ds = DealDataset(
    DATA_DIR,
    "t10k-images-idx3-ubyte.gz",
    "t10k-labels-idx1-ubyte.gz",
    transform=transforms.ToTensor(),
)
test_loader = DataLoader(test_ds, batch_size=100, shuffle=False)

# 加载模型
model_path = "pytorch_model/convnet.pth"
assert os.path.exists(model_path), "模型文件不存在: " + model_path

net = ConvNet()
net.load_state_dict(torch.load(model_path, map_location=DEVICE))
net.to(DEVICE)
net.eval()

save_path = "pytorch_model/predictions.csv"
os.makedirs(os.path.dirname(save_path), exist_ok=True)

total_correct = 0
total = 0
rows = []  # 存储 (index, pred, label, confidence)
start_index = 0

with torch.no_grad():
    for batch_idx, (data, target) in enumerate(test_loader):
        data, target = data.to(DEVICE), target.to(DEVICE)
        logits = net(data)
        probs = F.softmax(logits, dim=1)
        preds = logits.argmax(dim=1)

        batch_size = target.size(0)
        correct = preds.eq(target).sum().item()
        total_correct += correct
        total += batch_size

        # 收集每个样本的结果（索引从 start_index 开始）
        confidences, _ = probs.max(dim=1)  # 每个样本的置信度
        for i in range(batch_size):
            idx = start_index + i
            rows.append(
                (
                    idx,
                    int(preds[i].item()),
                    int(target[i].item()),
                    float(confidences[i].item()),
                )
            )
        start_index += batch_size

accuracy = total_correct / total if total > 0 else 0.0

# 保存到 CSV
with open(save_path, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["index", "pred", "label", "confidence"])
    writer.writerows(rows)

# 打印摘要与前若干条结果
print(f"Inference accuracy: {accuracy:.6f}  ({total_correct}/{total})")
print(f"Predictions saved to: {save_path}")
print("First 20 predictions (index, pred, label, confidence):")
for r in rows[:20]:
    print(r)
