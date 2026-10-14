import os

# 生成差分补丁文件指令
command = "detools create_patch -c heatshrink V1.bin V2.bin patch_1_2.bin"

# 执行指令
os.system(command)

# 读取原始文件内容
with open('patch_1_2.bin', 'rb') as file:
    original_content = file.read()

# 计算文件大小
file_size = os.path.getsize('patch_1_2.bin').to_bytes(4, byteorder='little')

# 构造要添加的数据
new_data = b'\x3A' + file_size + b'\x3B' + b'\x0d\x0a'

# 写入新文件
with open('patch_1_2_new.bin', 'wb') as file:
    file.write(new_data + original_content)

file_path = "patch_1_2_new.bin"
desired_size = os.path.getsize(file_path)
while desired_size % 128 != 0:
    desired_size += 1

with open(file_path, "ab") as file:
    file.write(b'\x00' * (desired_size - os.path.getsize(file_path)))

print("文件修改完成。")