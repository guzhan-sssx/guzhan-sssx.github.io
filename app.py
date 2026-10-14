import tkinter as tk
from tkinter import filedialog, messagebox
import shutil
import subprocess
import os

class App:
    def __init__(self, root):
        self.root = root
        self.root.title("BIN差分处理程序")
        
        self.bin1_path = ""
        self.bin2_path = ""

        # 创建选择框和按钮
        self.label1 = tk.Label(root, text="选择BIN文件1:")
        self.label1.pack()
        self.btn1 = tk.Button(root, text="浏览", command=self.select_bin1)
        self.btn1.pack()

        self.label2 = tk.Label(root, text="选择BIN文件2:")
        self.label2.pack()
        self.btn2 = tk.Button(root, text="浏览", command=self.select_bin2)
        self.btn2.pack()

        self.confirm_btn = tk.Button(root, text="确定", command=self.confirm)
        self.confirm_btn.pack()

    def select_bin1(self):
        self.bin1_path = filedialog.askopenfilename(filetypes=[("BIN files", "*.bin")])
        if self.bin1_path:
            self.label1.config(text=f"选择BIN文件1: {self.bin1_path}")

    def select_bin2(self):
        self.bin2_path = filedialog.askopenfilename(filetypes=[("BIN files", "*.bin")])
        if self.bin2_path:
            self.label2.config(text=f"选择BIN文件2: {self.bin2_path}")

    def confirm(self):
        if not self.bin1_path or not self.bin2_path:
            messagebox.showerror("错误", "请确保选择两个BIN文件。")
            return
        
        # 获取程序的当前路径
        current_dir = os.path.dirname(os.path.abspath(__file__))
        
        # 复制并重命名BIN文件
        try:
            shutil.copy(self.bin1_path, os.path.join(current_dir, "V1.bin"))
            shutil.copy(self.bin2_path, os.path.join(current_dir, "V2.bin"))
            messagebox.showinfo("成功", "BIN文件已复制并重命名。")
            
            # 运行Python程序
            subprocess.Popen(["python", os.path.join(current_dir, "generate_patch.py")])
        except Exception as e:
            messagebox.showerror("错误", f"发生错误: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()