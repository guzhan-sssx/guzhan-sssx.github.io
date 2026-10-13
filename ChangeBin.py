import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import struct
import datetime

def Get_CRC16_START_1021(InitCrc, Buf, Len):
    CrcReg = 0xFFFF
    for i in range(Len):
        CurVal = Buf[i] << 8
        for j in range(8):
            if (CrcReg ^ CurVal) & 0x8000:  # 检查高位
                CrcReg = (CrcReg << 1) ^ 0x1021
            else:
                CrcReg <<= 1
            CurVal <<= 1
    return CrcReg & 0xFFFF

def import_file():
    file_path = filedialog.askopenfilename(title="选择一个 BIN 文件", filetypes=[("BIN Files", "*.bin")])
    if file_path:
        process_file(file_path)

def process_file(file_path):
    # 获取用户选择
    comm_type = comm_var.get()
    baud_rate = baud_var.get()
    erase_value = erase_var.get()
    device_value = device_var.get()

    if comm_type not in ["CAN", "UART"]:
        messagebox.showerror("错误", "请选择通讯方式。")
        return

    # 创建新的数据缓冲区
    new_data = bytearray([0x0d, 0x0a])  # 前两个字节
    new_data.append(0x00 if comm_type == "CAN" else 0x01)  # 第三个字节

    # 设置第4到第7个字节
    if comm_type == "CAN":
        if baud_rate == "250 Kbps":
            new_data += bytearray(struct.pack('>I', 250))  # 250
        elif baud_rate == "500 Kbps":
            new_data += bytearray(struct.pack('>I', 500))  # 500
    else:  # UART
        if baud_rate == "9600 bps":
            new_data += bytearray(struct.pack('>I', 9600))  # 9600
        elif baud_rate == "57600 bps":
            new_data += bytearray(struct.pack('>I', 57600))  # 57600

    # 读取当前日期和时间
    # now = datetime.datetime.now()
    new_data.append(0)  # 年高位
    new_data.append(0)  # 年低位
    new_data.append(0)  # 月 
    new_data.append(0)  # 日
    new_data.append(0)  # 时
    new_data.append(0)  # 分
    new_data.append(0)  # 秒

    if erase_value == "1":
        new_data += bytearray(struct.pack('>I', 1))  # 擦除次数
    elif erase_value == "20":
        new_data += bytearray(struct.pack('>I', 20))  # 擦除次数

    if device_value == "仪表":
        new_data += bytearray(struct.pack('>I', 0))  # 仪表
    elif device_value == "控制器":
        new_data += bytearray(struct.pack('>I', 1))  # 控制器
    elif device_value == "烧录器":
        new_data += bytearray(struct.pack('>I', 2))  # 烧录器
    elif device_value == "ESP32":
        new_data += bytearray(struct.pack('>I', 3))  # ESP32仪表
    elif device_value == "ESP32_POLINI":
        new_data += bytearray(struct.pack('>I', 4))  # ESP32仪表

    version = version_entry.get().strip()
    print(version)
    version_bytes = version.encode('ascii')
    new_data += bytearray(version_bytes)  # 版本号

    # 填充到1024字节（总共1024字节）
    new_data += bytearray(1022 - len(new_data))  # 填充0

    # 计算CRC并添加到最后两字节
    crc_value = Get_CRC16_START_1021(0xFFFF, new_data, len(new_data))
    new_data.append(crc_value & 0xFF)       # CRC低位
    new_data.append((crc_value >> 8) & 0xFF)  # CRC高位

    # 读取原始文件内容
    with open(file_path, 'rb') as f:
        original_data = f.read()

    # 写入新的文件
    new_file_path = file_path.replace(".bin", "_modified.bin")
    with open(new_file_path, 'wb') as f:
        f.write(new_data)
        f.write(original_data)

    messagebox.showinfo("成功", f"文件已处理并保存为: {new_file_path}")

# 创建主窗口
root = tk.Tk()
root.title("BIN 文件处理程序")
root.geometry("500x500")

# 用户选择通讯方式
comm_var = tk.StringVar(value="CAN")
comm_label = tk.Label(root, text="选择通讯方式:")
comm_label.pack()

comm_can = tk.Radiobutton(root, text="CAN", variable=comm_var, value="CAN")
comm_can.pack()

comm_uart = tk.Radiobutton(root, text="UART", variable=comm_var, value="UART")
comm_uart.pack()

# 用户选择波特率
baud_var = tk.StringVar(value="250 Kbps")
baud_label = tk.Label(root, text="选择波特率:")
baud_label.pack()

baud_combobox = ttk.Combobox(root, textvariable=baud_var)
baud_combobox['values'] = ['250 Kbps', '500 Kbps', '9600 bps', '57600 bps']
baud_combobox.pack()

# 用户擦写种类选择
erase_var = tk.StringVar(value="1")
erase_label = tk.Label(root, text="选择擦写次数:")
erase_label.pack()

erase_type = ttk.Combobox(root, textvariable=erase_var)
erase_type['values'] = ['1', '20']
erase_type.pack()

# 烧写设备选择 仪表/控制器
device_var = tk.StringVar(value="仪表")
device_label = tk.Label(root, text="选择烧写设备:")
device_label.pack()

device_type = ttk.Combobox(root, textvariable=device_var)
device_type['values'] = ['仪表', '控制器','烧录器','ESP32','ESP32_POLINI']
device_type.pack()

# 版本号输入
version_label = tk.Label(root, text="版本号：")
version_label.pack()

version_entry = tk.Entry(root, width=30)
version_entry.pack()

# 导入文件按钮
import_button = tk.Button(root, text="导入 BIN 文件", command=import_file)
import_button.pack()

# 运行主循环
root.mainloop()