# -*- coding: utf-8 -*-
"""
ESP-IDF 固件读取 / 重命名工具（带 SHA-256 指纹）
================================================

参考 tools/bin_renamer 的「重命名固件」流程，命名规则
    {产品型号}_{协议类型}_{电压}{轮径}{限速}_{客户}_{版本号}_{时间简写}_{8位SHA}{扩展名}

命名示例（时间简写 = YYMMDDHHMMSS，末尾为 elf_sha256 前 8 个十六进制字符）：
    CDC60X_MultiProtocolC_482725_CD_V2.1.79_260918155146_4057d37e.bin
    CDC52X_MultiProtocolC_3670025_NDY_V2.1.67_260804091502_4057d37e.bin

时间来源可选（界面上切换，默认取 app_desc 编译时间）：
  app_desc 编译时间：编译器写入的 __DATE__/__TIME__，稳定不受拷贝影响
  文件修改时间    ：历史发布固件的文件名用的就是这个（实测 6 个文件全部吻合 mtime）

SHA-256 显示原则：界面完整显示 64 字符（输入框已加宽）；
.json 清单与命令行 `--info` 同样保留完整值，云端匹配差分基版本请用完整值。

两个 SHA-256 的含义（不要混用）：
  elf_sha256 : bin 内 app_desc 结构体 app_elf_sha256 字段（32 字节原始摘要）
               = sha256(CD_HMI.elf)，由 esptool --elf-sha256-offset 0xb0 写入
               与设备端 esp_ota_get_app_elf_sha256() 返回的字符串完全一致，
               可直接作为差分升级的「基版本」唯一标识，供云端匹配差分包
  bin_sha256 : 整个 bin 文件的 SHA-256，用于发布件完整性校验

地址速查（ESP32-S3，app 镜像 24 字节镜像头 + 8 字节段头）：
  纯 app 固件 CD_HMI.bin           : app_desc @ 0x20  → elf_sha256 @ 0xB0
  merge_bin 整片固件（app@0x10000）: app_desc @ 0x10020 → elf_sha256 @ 0x100B0

用法：
  图形界面：python firmware_renamer_sha256.py
  命令行  ：python firmware_renamer_sha256.py --info build/CD_HMI.bin
"""

import configparser
import hashlib
import json
import os
import struct
import sys
import zlib
from datetime import datetime

# ==================== 固件结构常量 ====================

APP_DESC_MAGIC = 0xABCD5432          # esp_app_desc_t.magic_word
ESP_IMAGE_MAGIC = 0xE9               # esp_image_header_t.magic
APP_DESC_SIZE = 256                  # sizeof(esp_app_desc_t)
APP_DESC_OFFSET = 0x20               # app_desc 在 app 镜像内的偏移（24 字节头 + 8 字节段头）
OFFSET_ELF_SHA_IN_DESC = 0x90        # app_elf_sha256 在 app_desc 内的偏移
OFFSET_APP = 0x10000                 # app 分区烧录地址（见 build/flasher_args.json）
OFFSET_CHIP_ID_IN_IMAGE = 0x0C       # esp_image_header_t.chip_id
CHIP_ID_ESP32S3 = 9

ELF_SHA_LEN = 32                     # 原始摘要 32 字节
# 候选 app_desc 起点：纯 app bin / merge_bin 整片固件
APP_DESC_CANDIDATES = (APP_DESC_OFFSET, OFFSET_APP + APP_DESC_OFFSET)

TIME_NAME_FORMAT = "%y%m%d%H%M%S"    # 文件名时间简写，如 260918155146

# 界面 / 清单 / CLI 均显示完整 64 字符；文件名只取前 8 个十六进制字符（32 bit）。
# 8 位碰撞概率（生日问题，N=2^32）：1000 个包约 0.012%，10000 个包约 1.2%，
# 约 7.7 万个包才到 50%。因此机器匹配（云端选差分包基版本）必须用完整 64 位，
# 8 位只作文件名/工单上的简称，并在入库时做唯一性校验。
SHA_NAME_LEN = 8

# 界面 SHA 输入框宽度（字符数）：需容纳完整 64 字符摘要
SHA_ENTRY_WIDTH = 68

# 文件名时间来源：app_desc 编译时间 / 文件修改时间
TIME_SOURCE_APPDESC = "appdesc"
TIME_SOURCE_MTIME = "mtime"
TIME_SOURCE_LABELS = ((TIME_SOURCE_APPDESC, "app_desc 编译时间"),
                      (TIME_SOURCE_MTIME, "文件修改时间"))


# ==================== 固件解析 ====================

def _read_cstr(buf, offset, length):
    """读取结构体内的定长字符串（C 风格，截断到首个 \\0）"""
    raw = buf[offset:offset + length]
    return raw.split(b"\x00")[0].decode("utf-8", errors="replace").strip()


def locate_app_desc(data):
    """定位 app_desc 在文件中的偏移；找不到返回 None"""
    for base in APP_DESC_CANDIDATES:
        if base + APP_DESC_SIZE > len(data):
            continue
        if struct.unpack_from("<I", data, base)[0] == APP_DESC_MAGIC:
            return base
    return None


def format_timestamp(timestamp):
    """时间戳 -> 文件名时间简写，如 260918155146"""
    if not timestamp:
        return ""
    return _format_datetime(datetime.fromtimestamp(timestamp))


def _format_datetime(dt):
    return dt.strftime(TIME_NAME_FORMAT)


def format_build_time(date_str, time_str, fallback_mtime=None):
    """把 app_desc 的 date / time 转成文件名时间简写

    app_desc 里存的是编译器写入的 __DATE__ / __TIME__，形如 "Aug 14 2026" + "10:13:50"，
    转换结果为 YYMMDDHHMMSS，如 "260814101350"。

    :param date_str: app_desc 中的日期字符串
    :param time_str: app_desc 中的时间字符串
    :param fallback_mtime: 解析失败时的回退时间戳（文件修改时间）
    :return: 时间简写字符串；完全无法获取时返回空串
    """
    normalized = "%s %s" % (" ".join(date_str.split()), " ".join(time_str.split()))
    try:
        return _format_datetime(datetime.strptime(normalized, "%b %d %Y %H:%M:%S"))
    except ValueError:
        return format_timestamp(fallback_mtime)


def parse_firmware(path):
    """解析 ESP-IDF 固件，返回版本号 / 编译时间 / SHA-256 / CRC32 等信息

    :raises ValueError: 文件过小、magic 不匹配等
    """
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < APP_DESC_OFFSET + APP_DESC_SIZE:
        raise ValueError("文件太小，不是有效的 ESP-IDF 固件")

    base = locate_app_desc(data)
    if base is None:
        raise ValueError(
            "未找到 esp_app_desc（magic 0x%08X），"
            "该文件不是 ESP-IDF 应用镜像" % APP_DESC_MAGIC)

    img_start = base - APP_DESC_OFFSET
    if img_start < 0 or data[img_start] != ESP_IMAGE_MAGIC:
        raise ValueError("镜像头 magic 0x%02X 无效，文件可能已损坏" % data[img_start])

    desc = data[base:base + APP_DESC_SIZE]
    elf_sha_raw = desc[OFFSET_ELF_SHA_IN_DESC:OFFSET_ELF_SHA_IN_DESC + ELF_SHA_LEN]
    compile_date = _read_cstr(desc, 0x60, 16)
    compile_time = _read_cstr(desc, 0x50, 16)

    mtime = os.path.getmtime(path)
    build_time_name = format_build_time(compile_date, compile_time, mtime)

    return {
        "file": os.path.abspath(path),
        "file_name": os.path.basename(path),
        "file_size": len(data),
        "app_desc_offset": base,
        "elf_sha_offset": base + OFFSET_ELF_SHA_IN_DESC,
        "chip_id": struct.unpack_from("<H", data, img_start + OFFSET_CHIP_ID_IN_IMAGE)[0],
        "version": _read_cstr(desc, 0x10, 32),
        "project_name": _read_cstr(desc, 0x30, 32),
        "date": compile_date,
        "time": compile_time,
        "idf_ver": _read_cstr(desc, 0x70, 32),
        # 文件名用的时间简写，形如 260918155146
        "build_time_name": build_time_name,          # app_desc 编译时间（不可用时回退 mtime）
        "mtime_time_name": format_timestamp(mtime),  # 文件修改时间
        "mtime": mtime,
        # bin 内偏移 0xB0 处的 32 字节原始摘要 -> 十六进制字符串
        "elf_sha256": elf_sha_raw.hex(),
        "elf_sha256_valid": elf_sha_raw != b"\x00" * ELF_SHA_LEN,
        # 整包 SHA-256 / CRC32（用于发布件校验）
        "bin_sha256": hashlib.sha256(data).hexdigest(),
        "crc32": zlib.crc32(data) & 0xFFFFFFFF,
    }


def verify_with_elf(info):
    """若同目录存在同名 .elf，则用 sha256(elf) 反向校验 bin 内的摘要

    :return: True 一致 / False 不一致 / None 无法校验
    """
    elf_path = os.path.splitext(info["file"])[0] + ".elf"
    if not os.path.isfile(elf_path):
        return None
    with open(elf_path, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest() == info["elf_sha256"]


# ==================== 命名规则 ====================

def get_time_name(info, source):
    """按选择的时间来源取时间片段（另一方为空时自动回退）"""
    if source == TIME_SOURCE_MTIME:
        return info["mtime_time_name"] or info["build_time_name"]
    return info["build_time_name"] or info["mtime_time_name"]


def build_target_name(product, protocol, voltage, wheel, speed, customer,
                      version, build_time, elf_sha256, ext):
    """组装文件名：型号_协议_电压轮径限速_客户_版本_时间简写_8位SHA.ext

    时间简写为 YYMMDDHHMMSS，SHA 取 elf_sha256 前 8 个十六进制字符，例如
    CDC60X_MultiProtocolC_482725_CD_V2.1.79_260918155146_4057d37e.bin
    """
    params = "%s%s%s" % (voltage, wheel, speed)
    sha_short = elf_sha256[:SHA_NAME_LEN].lower()
    parts = [product, protocol, params, customer, version, build_time, sha_short]
    return "_".join(p for p in parts if p) + ext


def build_manifest(info, target_name):
    """生成与固件同名的 .json 清单，供 MES/云平台入库建档"""
    return {
        "file": target_name,
        "project_name": info["project_name"],
        "version": info["version"],
        "compile_date": info["date"],
        "compile_time": info["time"],
        "idf_ver": info["idf_ver"],
        "elf_sha256": info["elf_sha256"],
        "bin_sha256": info["bin_sha256"],
        "crc32": "0x%08X" % info["crc32"],
        "file_size": info["file_size"],
        "source_file": info["file_name"],
        "renamed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ==================== 图形界面 ====================

class FirmwareRenamerSHA(object):
    """固件重命名工具（文件名追加 SHA-256 指纹），带配置记忆"""

    CONFIG_FILE = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "firmware_renamer_sha256.ini")

    def __init__(self, root):
        import tkinter as tk
        from tkinter import ttk, filedialog, messagebox

        self.tk = tk
        self.ttk = ttk
        self.filedialog = filedialog
        self.messagebox = messagebox
        self.root = root
        self.root.title("ESP-IDF 固件重命名（含 SHA-256 指纹）")
        self.root.geometry("1000x700")
        self.root.resizable(False, False)

        self.info = None  # parse_firmware() 结果

        self.config = configparser.ConfigParser()
        self.load_config()

        self.bin_path = tk.StringVar()
        self.version = tk.StringVar()
        self.build_time = tk.StringVar()
        self.elf_sha256 = tk.StringVar()
        self.bin_sha256 = tk.StringVar()
        self.verify_state = tk.StringVar()

        self.product_model = tk.StringVar(value=self.get_config("Product", "model", "CDC60X"))
        self.protocol = tk.StringVar(value=self.get_config("Product", "protocol", "MultiProtocolC"))
        self.voltage = tk.StringVar(value=self.get_config("Product", "voltage", "48"))
        self.wheel_dia = tk.StringVar(value=self.get_config("Product", "wheel", "27"))
        self.speed_limit = tk.StringVar(value=self.get_config("Product", "speed", "25"))
        self.customer = tk.StringVar(value=self.get_config("Product", "customer", "CD"))
        self.file_type = tk.StringVar(value=self.get_config("Naming", "file_type", ".bin"))
        self.time_source = tk.StringVar(
            value=self.get_config("Naming", "time_source", TIME_SOURCE_APPDESC))
        self.gen_manifest = tk.BooleanVar(
            value=self.get_config("Naming", "manifest", "1") == "1")
        self.name_preview = tk.StringVar(value="--")

        self.source_folder = tk.StringVar(value=self.get_config("Folders", "source", ""))
        self.target_folder = tk.StringVar(value=self.get_config("Folders", "target", ""))

        self.create_widgets()
        self.bind_preview_traces()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)

    # ---- 配置 ----

    def get_config(self, section, key, fallback=""):
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return fallback

    def load_config(self):
        if os.path.exists(self.CONFIG_FILE):
            self.config.read(self.CONFIG_FILE)
        for section in ("Product", "Folders", "Naming"):
            if not self.config.has_section(section):
                self.config.add_section(section)

    def save_config(self):
        self.config.set("Product", "model", self.product_model.get())
        self.config.set("Product", "protocol", self.protocol.get())
        self.config.set("Product", "voltage", self.voltage.get())
        self.config.set("Product", "wheel", self.wheel_dia.get())
        self.config.set("Product", "speed", self.speed_limit.get())
        self.config.set("Product", "customer", self.customer.get())
        self.config.set("Naming", "file_type", self.file_type.get())
        self.config.set("Naming", "time_source", self.time_source.get())
        self.config.set("Naming", "manifest", "1" if self.gen_manifest.get() else "0")
        self.config.set("Folders", "source", self.source_folder.get())
        self.config.set("Folders", "target", self.target_folder.get())
        with open(self.CONFIG_FILE, "w") as f:
            self.config.write(f)

    def on_closing(self):
        self.save_config()
        self.root.destroy()

    # ---- 界面 ----

    def create_widgets(self):
        tk, ttk = self.tk, self.ttk

        frame_file = ttk.LabelFrame(self.root, text="1. 选择固件及目录", padding=10)
        frame_file.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame_file, text="固件文件：").grid(row=0, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_file, textvariable=self.bin_path, width=52).grid(row=0, column=1, padx=5, pady=2)
        ttk.Button(frame_file, text="浏览...", command=self.select_file).grid(row=0, column=2, padx=5)
        ttk.Button(frame_file, text="分析", command=self.analyze_firmware).grid(row=0, column=3, padx=5)

        ttk.Label(frame_file, text="目标文件夹：").grid(row=1, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_file, textvariable=self.target_folder, width=52).grid(row=1, column=1, padx=5, pady=2)
        ttk.Button(frame_file, text="选择", command=self.select_target_folder).grid(row=1, column=2, padx=5)

        try:
            from tkinterdnd2 import DND_FILES
            self.root.drop_target_register(DND_FILES)
            self.root.dnd_bind("<<Drop>>", self.on_drop)
            ttk.Label(frame_file, text="（支持拖放 .bin 文件到窗口）",
                      foreground="grey").grid(row=2, column=1, sticky=tk.W, padx=5, pady=2)
        except ImportError:
            pass

        frame_info = ttk.LabelFrame(self.root, text="2. 固件信息（自动读取）", padding=10)
        frame_info.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame_info, text="版本号：").grid(row=0, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_info, textvariable=self.version, state="readonly",
                  width=60).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(frame_info, text="编译时间：").grid(row=1, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_info, textvariable=self.build_time, state="readonly",
                  width=60).grid(row=1, column=1, sticky=tk.W, padx=5)

        ttk.Label(frame_info, text="ELF SHA-256：").grid(row=2, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_info, textvariable=self.elf_sha256, state="readonly",
                  width=SHA_ENTRY_WIDTH, font=("Consolas", 9)).grid(
            row=2, column=1, sticky=tk.W, padx=5)

        ttk.Label(frame_info, text="BIN SHA-256：").grid(row=3, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_info, textvariable=self.bin_sha256, state="readonly",
                  width=SHA_ENTRY_WIDTH, font=("Consolas", 9)).grid(
            row=3, column=1, sticky=tk.W, padx=5)

        ttk.Label(frame_info, text="自校验：").grid(row=4, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Label(frame_info, textvariable=self.verify_state,
                  foreground="grey").grid(row=4, column=1, sticky=tk.W, padx=5)

        frame_input = ttk.LabelFrame(self.root, text="3. 产品信息（手动输入）", padding=10)
        frame_input.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame_input, text="产品型号：").grid(row=0, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_input, textvariable=self.product_model, width=18).grid(row=0, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame_input, text="协议类型：").grid(row=0, column=2, sticky=tk.E, padx=25, pady=2)
        ttk.Entry(frame_input, textvariable=self.protocol, width=18).grid(row=0, column=3, sticky=tk.W, padx=5)

        ttk.Label(frame_input, text="电压 (V)：").grid(row=1, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_input, textvariable=self.voltage, width=18).grid(row=1, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame_input, text="轮径 (in)：").grid(row=1, column=2, sticky=tk.E, padx=25, pady=2)
        ttk.Entry(frame_input, textvariable=self.wheel_dia, width=18).grid(row=1, column=3, sticky=tk.W, padx=5)

        ttk.Label(frame_input, text="限速 (km/h)：").grid(row=2, column=0, sticky=tk.E, padx=5, pady=2)
        ttk.Entry(frame_input, textvariable=self.speed_limit, width=18).grid(row=2, column=1, sticky=tk.W, padx=5)
        ttk.Label(frame_input, text="客户名称：").grid(row=2, column=2, sticky=tk.E, padx=25, pady=2)
        ttk.Entry(frame_input, textvariable=self.customer, width=18).grid(row=2, column=3, sticky=tk.W, padx=5)

        frame_naming = ttk.LabelFrame(self.root, text="4. 命名选项", padding=10)
        frame_naming.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(frame_naming, text="输出类型：").grid(row=0, column=0, sticky=tk.E, padx=5)
        ttk.Radiobutton(frame_naming, text=".bin", variable=self.file_type,
                        value=".bin").grid(row=0, column=1, sticky=tk.W)
        ttk.Radiobutton(frame_naming, text=".gbl", variable=self.file_type,
                        value=".gbl").grid(row=0, column=2, sticky=tk.W)

        ttk.Label(frame_naming, text="文件名时间来源：").grid(row=1, column=0, sticky=tk.E, padx=5)
        for col, (value, label) in enumerate(TIME_SOURCE_LABELS, start=1):
            ttk.Radiobutton(frame_naming, text=label, variable=self.time_source,
                            value=value).grid(row=1, column=col, sticky=tk.W)

        ttk.Checkbutton(frame_naming, text="同时生成 .json 清单",
                        variable=self.gen_manifest).grid(row=2, column=1, columnspan=2, sticky=tk.W, pady=5)

        ttk.Label(frame_naming, text="文件名预览：").grid(row=3, column=0, sticky=tk.E, padx=5)
        ttk.Label(frame_naming, textvariable=self.name_preview,
                  foreground="#0b6623").grid(row=3, column=1, columnspan=4, sticky=tk.W, padx=5)

        ttk.Button(self.root, text="5. 生成新文件并保存",
                   command=self.generate_and_save).pack(pady=12)

        self.status = tk.StringVar(value="就绪：请选择固件文件")
        ttk.Label(self.root, textvariable=self.status,
                  foreground="grey").pack(side=tk.BOTTOM, fill=tk.X, padx=12, pady=6)

    def bind_preview_traces(self):
        for var in (self.product_model, self.protocol, self.voltage, self.wheel_dia,
                    self.speed_limit, self.customer, self.file_type, self.time_source):
            var.trace_add("write", lambda *_: self.update_preview())

    def update_preview(self):
        """刷新文件名预览（依赖已解析的固件信息）"""
        if not self.info:
            self.name_preview.set("--")
            return
        name = build_target_name(
            self.product_model.get().strip(), self.protocol.get().strip(),
            self.voltage.get().strip(), self.wheel_dia.get().strip(),
            self.speed_limit.get().strip(), self.customer.get().strip(),
            self.info["version"], get_time_name(self.info, self.time_source.get()),
            self.info["elf_sha256"], self.file_type.get().strip())
        self.name_preview.set(name)

    # ---- 目录 / 文件选择 ----

    def select_target_folder(self):
        path = self.filedialog.askdirectory(title="选择保存新固件的目标文件夹")
        if path:
            self.target_folder.set(path)

    def select_file(self):
        initial = self.source_folder.get() if os.path.isdir(self.source_folder.get()) else ""
        path = self.filedialog.askopenfilename(
            title="选择固件文件", initialdir=initial,
            filetypes=[("Firmware files", "*.bin"), ("All files", "*.*")])
        if path:
            self.bin_path.set(path)
            self.source_folder.set(os.path.dirname(path))
            self.analyze_firmware()

    def on_drop(self, event):
        path = event.data.strip("{}").strip()
        if path.lower().endswith((".bin", ".gbl")):
            self.bin_path.set(path)
            self.source_folder.set(os.path.dirname(path))
            self.analyze_firmware()

    # ---- 分析 ----

    def analyze_firmware(self):
        path = self.bin_path.get().strip()
        if not path or not os.path.exists(path):
            self.messagebox.showerror("文件不存在", "请选择有效的固件文件")
            return

        try:
            self.info = parse_firmware(path)
        except ValueError as e:
            self.info = None
            self.status.set("解析失败：%s" % path)
            self.messagebox.showerror("解析失败", "%s\n\n%s" % (e, path))
            return
        except OSError as e:
            self.info = None
            self.messagebox.showerror("读取失败", str(e))
            return

        info = self.info
        self.version.set("%s   (IDF %s)" % (info["version"], info["idf_ver"]))
        self.build_time.set("编译 %s / 文件 %s   (app_desc: %s %s)" %
                            (info["build_time_name"], info["mtime_time_name"],
                             info["date"], info["time"]))
        # 完整 64 字符显示（输入框已加宽，可直接复制）
        self.elf_sha256.set(info["elf_sha256"])
        self.bin_sha256.set(info["bin_sha256"])

        notes = []
        if not info["elf_sha256_valid"]:
            notes.append("app_elf_sha256 为全 0，可能不是 elf2image 正常产物")
        if info["chip_id"] != CHIP_ID_ESP32S3:
            notes.append("chip_id=%d 不是 ESP32-S3(%d)" % (info["chip_id"], CHIP_ID_ESP32S3))

        matched = verify_with_elf(info)
        if matched is True:
            notes.append("已与同目录 .elf 的 sha256 比对：一致")
        elif matched is False:
            notes.append("警告：与同目录 .elf 的 sha256 不一致，文件可能被改动过")
        else:
            notes.append("未找到同目录 .elf，未做反向校验")
        notes.append("app_desc@0x%X / elf_sha256@0x%X" %
                     (info["app_desc_offset"], info["elf_sha_offset"]))
        self.verify_state.set("；".join(notes))

        self.status.set("已解析：%s（%d 字节）" % (info["file_name"], info["file_size"]))
        self.update_preview()

    # ---- 保存 ----

    def generate_and_save(self):
        if not self.info:
            self.messagebox.showerror("尚未分析", "请先点击「分析」解析固件")
            return

        fields = {
            "产品型号": self.product_model.get().strip(),
            "协议类型": self.protocol.get().strip(),
            "电压": self.voltage.get().strip(),
            "轮径": self.wheel_dia.get().strip(),
            "限速": self.speed_limit.get().strip(),
            "客户名称": self.customer.get().strip(),
        }
        empty = [k for k, v in fields.items() if not v]
        if empty:
            self.messagebox.showerror("信息不完整", "以下项不能为空：%s" % "、".join(empty))
            return

        version = self.info["version"]
        if not version:
            self.messagebox.showerror("缺少版本", "固件 app_desc 中未读到版本号")
            return

        ext = self.file_type.get().strip()
        target_name = build_target_name(
            fields["产品型号"], fields["协议类型"], fields["电压"], fields["轮径"],
            fields["限速"], fields["客户名称"], version,
            get_time_name(self.info, self.time_source.get()),
            self.info["elf_sha256"], ext)

        target_dir = self.target_folder.get().strip()
        if target_dir and os.path.isdir(target_dir):
            dest = os.path.join(target_dir, target_name)
            if os.path.exists(dest) and not self.messagebox.askyesno(
                    "覆盖确认", "文件已存在，是否覆盖？\n%s" % dest):
                return
        else:
            dest = self.filedialog.asksaveasfilename(
                title="保存新固件", initialfile=target_name,
                filetypes=[("Firmware files", "*%s" % ext), ("All files", "*.*")])
            if not dest:
                return
            self.target_folder.set(os.path.dirname(dest))

        try:
            with open(self.info["file"], "rb") as src, open(dest, "wb") as dst:
                dst.write(src.read())
        except OSError as e:
            self.messagebox.showerror("保存失败", str(e))
            return

        manifest_path = ""
        if self.gen_manifest.get():
            manifest_path = os.path.splitext(dest)[0] + ".json"
            try:
                with open(manifest_path, "w", encoding="utf-8") as f:
                    json.dump(build_manifest(self.info, os.path.basename(dest)),
                              f, ensure_ascii=False, indent=4)
            except OSError as e:
                self.messagebox.showwarning("清单写入失败", str(e))

        self.save_config()
        self.status.set("已保存：%s" % dest)
        self.messagebox.showinfo(
            "完成",
            "固件已保存：\n%s\n\nSHA-256（ELF）：%s\nSHA-256（BIN）：%s\n%s"
            % (dest, self.info["elf_sha256"], self.info["bin_sha256"],
               ("清单：\n%s" % manifest_path) if manifest_path else ""))

    def run(self):
        self.root.mainloop()


# ==================== 命令行模式 ====================

def print_info(path):
    """命令行输出固件指纹（供脚本/CI 调用，无需图形界面）"""
    info = parse_firmware(path)
    matched = verify_with_elf(info)
    info = dict(info)
    info["elf_sha256_match_elf"] = matched
    print(json.dumps(info, ensure_ascii=False, indent=4))
    return 0


def main(argv):
    if len(argv) >= 3 and argv[1] in ("--info", "-i"):
        try:
            return print_info(argv[2])
        except (ValueError, OSError) as e:
            print("解析失败：%s" % e, file=sys.stderr)
            return 1

    import tkinter as tk
    root = tk.Tk()
    FirmwareRenamerSHA(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
