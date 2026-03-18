#!/usr/bin/env python3
import concurrent.futures
import ipaddress
import json
import re
import socket
import struct
import subprocess
import sys
import threading
from datetime import datetime

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
    QMenu,
)

DEFAULT_PORT = 9494
NETWORK_TIMEOUT_SECONDS = 6


class TcpTestWindow(QWidget):
    scan_lan_finished = Signal(object, str, object)

    def __init__(self) -> None:
        super().__init__()
        self.device_sock: socket.socket | None = None
        self.rx_buffer = b""
        self.is_scanning = False
        self.memory_info_data: dict | None = None
        self.scan_page_start = 0
        self.scan_total_count = 0
        self.scan_live_refresh_enabled = False
        self.pointer_scan_running = False
        self.pointer_status_request_inflight = False
        self.hwbp_refresh_inflight = False
        self.saved_items: list[dict[str, str]] = []
        self.browser_base_addr = 0
        self.hwbp_info_data: dict | None = None
        self.live_refresh_timer = QTimer(self)
        self.live_refresh_timer.setInterval(1000)
        self.live_refresh_timer.timeout.connect(self.on_live_refresh_tick)
        self.setWindowTitle("TCP 连通性测试工具")
        self.resize(760, 460)
        self.scan_lan_finished.connect(self._on_scan_lan_finished)
        self._setup_ui()
        self.live_refresh_timer.start()

    def _setup_ui(self) -> None:
        root = QVBoxLayout(self)

        pid_row = QHBoxLayout()
        pid_row.addWidget(QLabel("当前全局PID:"))
        self.global_pid_label = QLabel("--")
        self.global_pid_label.setMinimumWidth(120)
        pid_row.addWidget(self.global_pid_label)

        pid_row.addWidget(QLabel("输入PID或包名:"))
        self.pid_input = QLineEdit()
        self.pid_input.setPlaceholderText("例如 12345 或 com.example.game")
        self.pid_input.returnPressed.connect(self.on_sync_pid)
        pid_row.addWidget(self.pid_input, 1)

        self.sync_pid_button = QPushButton("同步PID")
        self.sync_pid_button.clicked.connect(self.on_sync_pid)
        pid_row.addWidget(self.sync_pid_button)
        root.addLayout(pid_row)

        self._build_connection_panel(root)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs)

        self.memory_page = QWidget()
        self.search_page = QWidget()
        self.browser_page = QWidget()
        self.pointer_page = QWidget()
        self.breakpoint_page = QWidget()
        self.signature_page = QWidget()
        self.save_page = QWidget()
        self.log_page = QWidget()
        self.settings_page = QWidget()

        self.tabs.addTab(self.memory_page, "内存信息页")
        self.tabs.addTab(self.search_page, "扫描页")
        self.tabs.addTab(self.browser_page, "内存浏览页")
        self.tabs.addTab(self.pointer_page, "指针页")
        self.tabs.addTab(self.breakpoint_page, "断点页")
        self.tabs.addTab(self.signature_page, "特征码页")
        self.tabs.addTab(self.save_page, "保存页")
        self.tabs.addTab(self.log_page, "日志页")
        self.tabs.addTab(self.settings_page, "设置页")
        self.tabs.currentChanged.connect(self.on_tab_changed)

        self._build_memory_page()
        self._build_scan_page()
        self._build_browser_page()
        self._build_pointer_page()
        self._build_breakpoint_page()
        self._build_signature_page()
        self._build_save_page()
        self._build_log_page()

        self._build_settings_page()
        self._log("客户端已启动。")
        self._set_connection_ui(False)
        self._show_connect_login_dialog()

    def _build_connection_panel(self, root: QVBoxLayout) -> None:
        device_row = QHBoxLayout()
        device_row.addWidget(QLabel("局域网设备:"))
        self.device_combo = QComboBox()
        self.device_combo.setEditable(False)
        self.device_combo.addItem("请点击“扫描设备”获取列表", "")
        device_row.addWidget(self.device_combo, 1)
        self.scan_device_button = QPushButton("扫描设备")
        self.scan_device_button.clicked.connect(self.on_scan_lan_devices)
        device_row.addWidget(self.scan_device_button)
        device_row.addWidget(QLabel("端口:"))
        self.port_input = QLineEdit(str(DEFAULT_PORT))
        self.port_input.setPlaceholderText("请输入目标端口")
        self.port_input.setMaximumWidth(140)
        device_row.addWidget(self.port_input)
        self.test_button = QPushButton("连接到设备")
        self.test_button.clicked.connect(self.on_toggle_connection)
        device_row.addWidget(self.test_button)
        root.addLayout(device_row)

        status_row = QHBoxLayout()
        status_row.addWidget(QLabel("连接状态:"))
        self.status_label = QLabel("未连接")
        status_row.addWidget(self.status_label, 1)
        root.addLayout(status_row)

    def _show_connect_login_dialog(self) -> None:
        if self._is_connected():
            return

        dialog = QDialog(self)
        dialog.setWindowTitle("登录到设备")
        dialog.setModal(True)
        dialog.resize(520, 220)

        layout = QVBoxLayout(dialog)
        tip = QLabel("请先连接到设备，连接成功后才能进入功能页面。")
        tip.setWordWrap(True)
        layout.addWidget(tip)

        device_row = QHBoxLayout()
        device_row.addWidget(QLabel("局域网设备:"))
        device_combo = QComboBox()
        device_combo.addItem("请点击“扫描设备”获取列表", "")
        device_row.addWidget(device_combo, 1)
        scan_button = QPushButton("扫描设备")
        device_row.addWidget(scan_button)
        layout.addLayout(device_row)

        port_row = QHBoxLayout()
        port_row.addWidget(QLabel("端口:"))
        port_input = QLineEdit(str(DEFAULT_PORT))
        port_row.addWidget(port_input)
        layout.addLayout(port_row)

        status_label = QLabel("未连接")
        layout.addWidget(status_label)

        btn_row = QHBoxLayout()
        btn_row.addStretch(1)
        cancel_btn = QPushButton("取消")
        connect_btn = QPushButton("连接并进入")
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(connect_btn)
        layout.addLayout(btn_row)

        def on_scan() -> None:
            scan_button.setEnabled(False)
            status_label.setText("正在扫描局域网设备，请稍候...")
            QApplication.processEvents()
            try:
                devices = self._discover_lan_devices()
            except Exception as exc:  # noqa: BLE001
                devices = []
                status_label.setText(f"扫描失败: {exc}")
            else:
                device_combo.clear()
                if not devices:
                    device_combo.addItem("未发现设备，请确认同网段后重试", "")
                    status_label.setText("扫描完成：未发现设备")
                else:
                    for ip_text, mac_text in devices:
                        device_combo.addItem(f"{ip_text}    [{mac_text}]", ip_text)
                    status_label.setText(f"扫描完成：发现 {len(devices)} 台设备")
            scan_button.setEnabled(True)

        def on_connect() -> None:
            host_data = device_combo.currentData()
            host = str(host_data).strip() if host_data is not None else ""
            if not host:
                QMessageBox.warning(dialog, "输入提示", "请先扫描并选择局域网设备。")
                return
            port_text = port_input.text().strip()
            try:
                port = int(port_text, 10)
            except ValueError:
                QMessageBox.warning(dialog, "输入提示", "端口必须是整数。")
                return
            if not (1 <= port <= 65535):
                QMessageBox.warning(dialog, "输入提示", "端口范围必须在 1 到 65535 之间。")
                return

            # 同步到主窗口连接控件后复用原有连接流程。
            self.device_combo.clear()
            self.device_combo.addItem(host, host)
            self.device_combo.setCurrentIndex(0)
            self.port_input.setText(str(port))
            self._connect_device()
            if self._is_connected():
                dialog.accept()
            else:
                status_label.setText(self.status_label.text())

        scan_button.clicked.connect(on_scan)
        connect_btn.clicked.connect(on_connect)
        cancel_btn.clicked.connect(dialog.reject)

        if dialog.exec() != QDialog.Accepted and not self._is_connected():
            QTimer.singleShot(0, self.close)

    def _is_pointer_tab_active(self) -> bool:
        return self.tabs.currentWidget() is self.pointer_page

    def _is_breakpoint_tab_active(self) -> bool:
        return self.tabs.currentWidget() is self.breakpoint_page

    def on_tab_changed(self, _index: int) -> None:
        # 仅在切到指针页时主动刷新一次状态，避免后台持续轮询。
        if self._is_pointer_tab_active() and self._is_connected():
            self.on_pointer_status()
        if self._is_breakpoint_tab_active() and self._is_connected():
            self.on_hwbp_refresh(silent=True)

    def _build_memory_page(self) -> None:
        layout = QVBoxLayout(self.memory_page)

        row = QHBoxLayout()
        self.refresh_memory_button = QPushButton("刷新内存信息")
        self.refresh_memory_button.clicked.connect(self.on_refresh_memory_info)
        row.addWidget(self.refresh_memory_button)
        row.addWidget(QLabel("搜索:"))
        self.memory_filter_input = QLineEdit()
        self.memory_filter_input.setPlaceholderText("输入模块名/地址/权限关键字")
        self.memory_filter_input.returnPressed.connect(self.on_filter_memory_info)
        row.addWidget(self.memory_filter_input, 1)
        self.filter_memory_button = QPushButton("筛选")
        self.filter_memory_button.clicked.connect(self.on_filter_memory_info)
        row.addWidget(self.filter_memory_button)
        self.clear_filter_button = QPushButton("清空筛选")
        self.clear_filter_button.clicked.connect(self.on_clear_memory_filter)
        row.addWidget(self.clear_filter_button)
        row.addStretch(1)
        layout.addLayout(row)

        self.memory_view = QTextEdit()
        self.memory_view.setReadOnly(True)
        self.memory_view.setPlaceholderText("点击“刷新内存信息”后显示可读的 memory_info 结构数据。")
        layout.addWidget(self.memory_view, 1)

    def _build_scan_page(self) -> None:
        layout = QVBoxLayout(self.search_page)

        content_row = QHBoxLayout()
        layout.addLayout(content_row, 1)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.addWidget(QLabel("扫描结果"))

        self.scan_view = QTextEdit()
        self.scan_view.setReadOnly(True)
        self.scan_view.setPlaceholderText("这里显示 MemScanner 扫描结果。")
        self.scan_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.scan_view.customContextMenuRequested.connect(self.on_scan_view_context_menu)
        left_layout.addWidget(self.scan_view, 1)
        content_row.addWidget(left_panel, 3)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("类型:"))
        self.scan_type_combo = QComboBox()
        self.scan_type_combo.addItem("I8", "I8")
        self.scan_type_combo.addItem("I16", "I16")
        self.scan_type_combo.addItem("I32", "I32")
        self.scan_type_combo.addItem("I64", "I64")
        self.scan_type_combo.addItem("Float", "Float")
        self.scan_type_combo.addItem("Double", "Double")
        i32_index = self.scan_type_combo.findData("I32")
        self.scan_type_combo.setCurrentIndex(i32_index if i32_index >= 0 else 0)
        row1.addWidget(self.scan_type_combo)

        row1.addWidget(QLabel("模式:"))
        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItem("Unknown", "unknown")
        self.scan_mode_combo.addItem("Equal", "eq")
        self.scan_mode_combo.addItem("Greater", "gt")
        self.scan_mode_combo.addItem("Less", "lt")
        self.scan_mode_combo.addItem("Increased", "inc")
        self.scan_mode_combo.addItem("Decreased", "dec")
        self.scan_mode_combo.addItem("Changed", "changed")
        self.scan_mode_combo.addItem("Unchanged", "unchanged")
        self.scan_mode_combo.addItem("Range", "range")
        self.scan_mode_combo.addItem("Pointer", "pointer")
        eq_index = self.scan_mode_combo.findData("eq")
        self.scan_mode_combo.setCurrentIndex(eq_index if eq_index >= 0 else 0)
        row1.addWidget(self.scan_mode_combo)
        row1.addStretch(1)
        right_layout.addLayout(row1)

        row_value = QHBoxLayout()
        row_value.addWidget(QLabel("值:"))
        self.scan_value_input = QLineEdit()
        self.scan_value_input.setPlaceholderText("例如 100 或 3.14")
        self.scan_value_input.setMinimumWidth(280)
        row_value.addWidget(self.scan_value_input, 1)

        row_value.addWidget(QLabel("范围:"))
        self.scan_range_input = QLineEdit("0")
        self.scan_range_input.setPlaceholderText("range 模式使用")
        self.scan_range_input.setMaximumWidth(100)
        row_value.addWidget(self.scan_range_input)
        row_value.addStretch(1)
        right_layout.addLayout(row_value)

        row2 = QHBoxLayout()
        self.scan_first_button = QPushButton("首次扫描")
        self.scan_first_button.clicked.connect(self.on_scan_first)
        row2.addWidget(self.scan_first_button)

        self.scan_next_button = QPushButton("再次扫描")
        self.scan_next_button.clicked.connect(self.on_scan_next)
        row2.addWidget(self.scan_next_button)

        self.scan_status_button = QPushButton("扫描状态")
        self.scan_status_button.clicked.connect(self.on_scan_status)
        row2.addWidget(self.scan_status_button)

        self.scan_clear_button = QPushButton("清空结果")
        self.scan_clear_button.clicked.connect(self.on_scan_clear)
        row2.addWidget(self.scan_clear_button)

        self.scan_total_label = QLabel("总结果数: 0")
        row2.addWidget(self.scan_total_label)

        row2.addStretch(1)
        right_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("分页数量:"))
        self.scan_page_count_input = QLineEdit("100")
        self.scan_page_count_input.setMaximumWidth(120)
        row3.addWidget(self.scan_page_count_input)

        self.scan_prev_button = QPushButton("上一页")
        self.scan_prev_button.clicked.connect(self.on_scan_prev_page)
        row3.addWidget(self.scan_prev_button)

        self.scan_next_page_button = QPushButton("下一页")
        self.scan_next_page_button.clicked.connect(self.on_scan_next_page)
        row3.addWidget(self.scan_next_page_button)
        row3.addStretch(1)
        right_layout.addLayout(row3)
        right_layout.addStretch(1)

        content_row.addWidget(right_panel, 2)

    def _build_browser_page(self) -> None:
        layout = QVBoxLayout(self.browser_page)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("地址:"))
        self.browser_addr_input = QLineEdit("0x0")
        self.browser_addr_input.setPlaceholderText("输入起始地址，如 0x12345678")
        self.browser_addr_input.returnPressed.connect(self.on_browser_read)
        row1.addWidget(self.browser_addr_input, 1)

        row1.addWidget(QLabel("大小:"))
        self.browser_size_input = QLineEdit("256")
        self.browser_size_input.setMaximumWidth(120)
        row1.addWidget(self.browser_size_input)

        row1.addWidget(QLabel("显示:"))
        self.browser_view_combo = QComboBox()
        self.browser_view_combo.addItem("Hex", "hex")
        self.browser_view_combo.addItem("Hex64", "hex64")
        self.browser_view_combo.addItem("I8", "i8")
        self.browser_view_combo.addItem("I16", "i16")
        self.browser_view_combo.addItem("I32", "i32")
        self.browser_view_combo.addItem("I64", "i64")
        self.browser_view_combo.addItem("Float", "f32")
        self.browser_view_combo.addItem("Double", "f64")
        self.browser_view_combo.addItem("Disasm", "disasm")
        row1.addWidget(self.browser_view_combo)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        self.browser_read_button = QPushButton("读取")
        self.browser_read_button.clicked.connect(self.on_browser_read)
        row2.addWidget(self.browser_read_button)

        self.browser_prev_button = QPushButton("上移")
        self.browser_prev_button.clicked.connect(self.on_browser_prev)
        row2.addWidget(self.browser_prev_button)

        self.browser_next_button = QPushButton("下移")
        self.browser_next_button.clicked.connect(self.on_browser_next)
        row2.addWidget(self.browser_next_button)
        row2.addStretch(1)
        layout.addLayout(row2)

        self.browser_view = QTextEdit()
        self.browser_view.setReadOnly(True)
        self.browser_view.setPlaceholderText("内存浏览结果将显示在这里。")
        layout.addWidget(self.browser_view, 1)

    def _build_pointer_page(self) -> None:
        layout = QVBoxLayout(self.pointer_page)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("目标地址:"))
        self.pointer_target_input = QLineEdit("0x0")
        self.pointer_target_input.setPlaceholderText("例如 0x12345678")
        row1.addWidget(self.pointer_target_input, 1)

        row1.addWidget(QLabel("深度:"))
        self.pointer_depth_input = QLineEdit("5")
        self.pointer_depth_input.setMaximumWidth(80)
        row1.addWidget(self.pointer_depth_input)

        row1.addWidget(QLabel("最大偏移:"))
        self.pointer_max_offset_input = QLineEdit("4096")
        self.pointer_max_offset_input.setMaximumWidth(120)
        row1.addWidget(self.pointer_max_offset_input)
        layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("基址模式:"))
        self.pointer_mode_combo = QComboBox()
        self.pointer_mode_combo.addItem("Module", "module")
        self.pointer_mode_combo.addItem("Manual", "manual")
        self.pointer_mode_combo.addItem("Array", "array")
        row2.addWidget(self.pointer_mode_combo)

        row2.addWidget(QLabel("模块过滤:"))
        self.pointer_filter_input = QLineEdit()
        self.pointer_filter_input.setPlaceholderText("可选，例如 libil2cpp.so")
        row2.addWidget(self.pointer_filter_input, 1)
        layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("手动基址:"))
        self.pointer_manual_base_input = QLineEdit("0x0")
        self.pointer_manual_base_input.setMaximumWidth(180)
        row3.addWidget(self.pointer_manual_base_input)
        row3.addWidget(QLabel("手动范围:"))
        self.pointer_manual_offset_input = QLineEdit("8192")
        self.pointer_manual_offset_input.setMaximumWidth(120)
        row3.addWidget(self.pointer_manual_offset_input)

        row3.addWidget(QLabel("数组基址:"))
        self.pointer_array_base_input = QLineEdit("0x0")
        self.pointer_array_base_input.setMaximumWidth(180)
        row3.addWidget(self.pointer_array_base_input)
        row3.addWidget(QLabel("数组数量:"))
        self.pointer_array_count_input = QLineEdit("128")
        self.pointer_array_count_input.setMaximumWidth(120)
        row3.addWidget(self.pointer_array_count_input)
        layout.addLayout(row3)

        row4 = QHBoxLayout()
        self.pointer_scan_button = QPushButton("开始扫描")
        self.pointer_scan_button.clicked.connect(self.on_pointer_scan)
        row4.addWidget(self.pointer_scan_button)

        self.pointer_status_button = QPushButton("刷新状态")
        self.pointer_status_button.clicked.connect(self.on_pointer_status)
        row4.addWidget(self.pointer_status_button)

        self.pointer_merge_button = QPushButton("合并Bin")
        self.pointer_merge_button.clicked.connect(self.on_pointer_merge)
        row4.addWidget(self.pointer_merge_button)

        self.pointer_export_button = QPushButton("导出文本")
        self.pointer_export_button.clicked.connect(self.on_pointer_export)
        row4.addWidget(self.pointer_export_button)
        row4.addStretch(1)
        layout.addLayout(row4)

        self.pointer_status_label = QLabel("扫描状态: 未开始")
        layout.addWidget(self.pointer_status_label)

        self.pointer_view = QTextEdit()
        self.pointer_view.setReadOnly(True)
        self.pointer_view.setPlaceholderText("这里显示指针扫描指令与状态。")
        layout.addWidget(self.pointer_view, 1)

    def _build_breakpoint_page(self) -> None:
        layout = QVBoxLayout(self.breakpoint_page)

        summary_row = QHBoxLayout()
        self.hwbp_num_brps_label = QLabel("hwbp_info.num_brps: 0")
        summary_row.addWidget(self.hwbp_num_brps_label)
        self.hwbp_num_wrps_label = QLabel("hwbp_info.num_wrps: 0")
        summary_row.addWidget(self.hwbp_num_wrps_label)
        self.hwbp_hit_addr_label = QLabel("hwbp_info.hit_addr: 0x0")
        summary_row.addWidget(self.hwbp_hit_addr_label, 1)
        layout.addLayout(summary_row)

        config_row = QHBoxLayout()
        config_row.addWidget(QLabel("断点地址:"))
        self.hwbp_addr_input = QLineEdit("0x0")
        self.hwbp_addr_input.setPlaceholderText("例如 0x7A12345678")
        config_row.addWidget(self.hwbp_addr_input, 1)

        config_row.addWidget(QLabel("类型:"))
        self.hwbp_type_combo = QComboBox()
        self.hwbp_type_combo.addItem("BP_READ", "0")
        self.hwbp_type_combo.addItem("BP_WRITE", "1")
        self.hwbp_type_combo.addItem("BP_READ_WRITE", "2")
        self.hwbp_type_combo.addItem("BP_EXECUTE", "3")
        config_row.addWidget(self.hwbp_type_combo)

        config_row.addWidget(QLabel("范围:"))
        self.hwbp_scope_combo = QComboBox()
        self.hwbp_scope_combo.addItem("SCOPE_MAIN_THREAD", "0")
        self.hwbp_scope_combo.addItem("SCOPE_OTHER_THREADS", "1")
        self.hwbp_scope_combo.addItem("SCOPE_ALL_THREADS", "2")
        config_row.addWidget(self.hwbp_scope_combo)

        config_row.addWidget(QLabel("长度:"))
        self.hwbp_len_input = QLineEdit("4")
        self.hwbp_len_input.setMaximumWidth(80)
        config_row.addWidget(self.hwbp_len_input)
        layout.addLayout(config_row)

        action_row = QHBoxLayout()
        self.hwbp_refresh_button = QPushButton("刷新断点信息")
        self.hwbp_refresh_button.clicked.connect(self.on_hwbp_refresh)
        action_row.addWidget(self.hwbp_refresh_button)

        self.hwbp_set_button = QPushButton("设置断点")
        self.hwbp_set_button.clicked.connect(self.on_hwbp_set)
        action_row.addWidget(self.hwbp_set_button)

        self.hwbp_remove_button = QPushButton("移除断点")
        self.hwbp_remove_button.clicked.connect(self.on_hwbp_remove_all)
        action_row.addWidget(self.hwbp_remove_button)
        action_row.addStretch(1)
        layout.addLayout(action_row)

        record_row = QHBoxLayout()
        record_row.addWidget(QLabel("hwbp_record 索引:"))
        self.hwbp_record_combo = QComboBox()
        self.hwbp_record_combo.addItem("无记录", "-1")
        self.hwbp_record_combo.currentIndexChanged.connect(self.on_hwbp_record_combo_changed)
        record_row.addWidget(self.hwbp_record_combo, 1)

        record_row.addWidget(QLabel("手动索引:"))
        self.hwbp_record_index_input = QLineEdit("0")
        self.hwbp_record_index_input.setMaximumWidth(100)
        record_row.addWidget(self.hwbp_record_index_input)
        self.hwbp_remove_record_button = QPushButton("删除记录")
        self.hwbp_remove_record_button.clicked.connect(self.on_hwbp_remove_record)
        record_row.addWidget(self.hwbp_remove_record_button)
        self.hwbp_record_count_label = QLabel("hwbp_info.record_count: 0")
        record_row.addWidget(self.hwbp_record_count_label)
        record_row.addStretch(1)
        layout.addLayout(record_row)

        self.hwbp_tree = QTreeWidget()
        self.hwbp_tree.setHeaderLabels(["断点记录（按 PC 折叠）"])
        self.hwbp_tree.setUniformRowHeights(True)
        self.hwbp_tree.setAlternatingRowColors(True)
        self.hwbp_tree.setContextMenuPolicy(Qt.CustomContextMenu)
        self.hwbp_tree.customContextMenuRequested.connect(self.on_hwbp_tree_context_menu)
        self.hwbp_tree.currentItemChanged.connect(self.on_hwbp_tree_current_item_changed)
        layout.addWidget(self.hwbp_tree, 1)

    def _build_signature_page(self) -> None:
        layout = QVBoxLayout(self.signature_page)

        scan_row = QHBoxLayout()
        scan_row.addWidget(QLabel("目标地址:"))
        self.sig_addr_input = QLineEdit("0x0")
        self.sig_addr_input.setPlaceholderText("扫描并保存时使用")
        scan_row.addWidget(self.sig_addr_input, 1)
        scan_row.addWidget(QLabel("范围:"))
        self.sig_range_input = QLineEdit("50")
        self.sig_range_input.setMaximumWidth(100)
        scan_row.addWidget(self.sig_range_input)
        scan_row.addWidget(QLabel("文件:"))
        self.sig_file_input = QLineEdit("Signature.txt")
        scan_row.addWidget(self.sig_file_input, 1)
        self.sig_scan_addr_button = QPushButton("ScanAddressSignature")
        self.sig_scan_addr_button.clicked.connect(self.on_sig_scan_address)
        scan_row.addWidget(self.sig_scan_addr_button)
        layout.addLayout(scan_row)

        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("过滤地址:"))
        self.sig_verify_addr_input = QLineEdit("0x0")
        self.sig_verify_addr_input.setPlaceholderText("过滤 Signature.txt")
        filter_row.addWidget(self.sig_verify_addr_input, 1)
        self.sig_filter_button = QPushButton("FilterSignature")
        self.sig_filter_button.clicked.connect(self.on_sig_filter)
        filter_row.addWidget(self.sig_filter_button)
        self.sig_scan_file_button = QPushButton("ScanSignatureFromFile")
        self.sig_scan_file_button.clicked.connect(self.on_sig_scan_file)
        filter_row.addWidget(self.sig_scan_file_button)
        layout.addLayout(filter_row)

        pattern_row = QHBoxLayout()
        pattern_row.addWidget(QLabel("特征码:"))
        self.sig_pattern_input = QLineEdit()
        self.sig_pattern_input.setPlaceholderText("例如 A1h ?? FFh 00h")
        pattern_row.addWidget(self.sig_pattern_input, 1)
        pattern_row.addWidget(QLabel("偏移:"))
        self.sig_pattern_range_input = QLineEdit("0")
        self.sig_pattern_range_input.setMaximumWidth(100)
        pattern_row.addWidget(self.sig_pattern_range_input)
        self.sig_scan_pattern_button = QPushButton("ScanSignature(pattern)")
        self.sig_scan_pattern_button.clicked.connect(self.on_sig_scan_pattern)
        pattern_row.addWidget(self.sig_scan_pattern_button)
        layout.addLayout(pattern_row)

        self.sig_status_label = QLabel("特征码状态: 未执行")
        layout.addWidget(self.sig_status_label)

        self.sig_view = QTextEdit()
        self.sig_view.setReadOnly(True)
        self.sig_view.setPlaceholderText("这里显示特征码扫描和过滤结果。")
        layout.addWidget(self.sig_view, 1)

    def _build_save_page(self) -> None:
        layout = QVBoxLayout(self.save_page)

        row = QHBoxLayout()
        self.saved_count_label = QLabel("已保存: 0")
        row.addWidget(self.saved_count_label)
        self.clear_saved_button = QPushButton("清空保存")
        self.clear_saved_button.clicked.connect(self.on_clear_saved_items)
        row.addWidget(self.clear_saved_button)
        row.addStretch(1)
        layout.addLayout(row)

        self.saved_view = QTextEdit()
        self.saved_view.setReadOnly(True)
        self.saved_view.setPlaceholderText("在扫描结果里右键保存后，这里会显示地址和数据。")
        self.saved_view.setContextMenuPolicy(Qt.CustomContextMenu)
        self.saved_view.customContextMenuRequested.connect(self.on_saved_view_context_menu)
        layout.addWidget(self.saved_view, 1)

    def _build_settings_page(self) -> None:
        layout = QVBoxLayout(self.settings_page)
        tip = QLabel("设置页已留空。请先在顶部连接到设备后再使用其它页面功能。")
        tip.setWordWrap(True)
        layout.addWidget(tip)
        layout.addStretch(1)

    def _build_log_page(self) -> None:
        layout = QVBoxLayout(self.log_page)

        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view, 1)

        clear_row = QHBoxLayout()
        clear_button = QPushButton("清空日志")
        clear_button.clicked.connect(self.log_view.clear)
        clear_row.addWidget(clear_button)
        clear_row.addStretch(1)
        layout.addLayout(clear_row)

    def _log(self, text: str) -> None:
        time_text = datetime.now().strftime("%H:%M:%S")
        self.log_view.append(f"[{time_text}] {text}")

    def _set_status(self, text: str) -> None:
        self.status_label.setText(text)
        self._log(f"状态: {text}")

    def _is_connected(self) -> bool:
        return self.device_sock is not None

    def _set_feature_gate(self, connected: bool) -> None:
        # 未连接时，仅保留“设置页”可操作。
        for i in range(self.tabs.count()):
            page = self.tabs.widget(i)
            enabled = connected or (page is self.settings_page)
            self.tabs.setTabEnabled(i, enabled)
        if not connected and self.tabs.currentWidget() is not self.settings_page:
            self.tabs.setCurrentWidget(self.settings_page)
        self.pid_input.setEnabled(connected)
        self.sync_pid_button.setEnabled(connected)

    def _collect_local_ipv4(self) -> list[str]:
        ips: set[str] = set()

        try:
            infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            for info in infos:
                ip = info[4][0]
                if ip and not ip.startswith("127."):
                    ips.add(ip)
        except OSError:
            pass

        # 通过路由出口补充本机网卡 IPv4。
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("114.114.114.114", 53))
            ip = probe.getsockname()[0]
            if ip and not ip.startswith("127."):
                ips.add(ip)
            probe.close()
        except OSError:
            pass

        valid_ips: list[str] = []
        for ip_text in ips:
            try:
                ip_obj = ipaddress.IPv4Address(ip_text)
            except ipaddress.AddressValueError:
                continue
            if ip_obj.is_private and not ip_obj.is_loopback:
                valid_ips.append(ip_text)
        return sorted(valid_ips)

    def _collect_subnet_targets(self, local_ips: list[str]) -> tuple[set[str], set[str]]:
        targets: set[str] = set()
        local_set = set(local_ips)
        for ip_text in local_ips:
            try:
                network = ipaddress.ip_network(f"{ip_text}/24", strict=False)
            except ValueError:
                continue
            for host in network.hosts():
                host_text = str(host)
                if host_text not in local_set:
                    targets.add(host_text)
        return targets, local_set

    def _ping_host(self, ip_text: str) -> bool:
        create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "-w", "150", ip_text],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=2,
                creationflags=create_no_window,
            )
        except (OSError, subprocess.TimeoutExpired):
            return False
        return result.returncode == 0

    def _read_arp_table(self) -> dict[str, str]:
        arp_map: dict[str, str] = {}
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="ignore",
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return arp_map

        if result.returncode != 0:
            return arp_map

        pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9A-Fa-f-]{17})\s+\S+")
        for ip_text, mac_text in pattern.findall(result.stdout):
            arp_map[ip_text] = mac_text.lower()
        return arp_map

    def _discover_lan_devices(self) -> list[tuple[str, str]]:
        local_ips = self._collect_local_ipv4()
        if not local_ips:
            return []

        targets, local_set = self._collect_subnet_targets(local_ips)

        if targets:
            with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
                list(pool.map(self._ping_host, sorted(targets)))

        arp_map = self._read_arp_table()
        devices: list[tuple[str, str]] = []
        for ip_text, mac_text in arp_map.items():
            if ip_text in local_set:
                continue
            if targets and ip_text not in targets:
                continue
            devices.append((ip_text, mac_text))

        devices.sort(key=lambda item: int(ipaddress.IPv4Address(item[0])))
        return devices

    def _finish_scan_lan_devices(self, devices: list[tuple[str, str]], previous_ip: str, error_text: str | None = None) -> None:
        self.device_combo.clear()

        if error_text:
            self.device_combo.addItem("扫描失败，请重试", "")
            self._set_status(f"扫描失败：{error_text}")
        elif not devices:
            self.device_combo.addItem("未发现设备，请确认同网段后重试", "")
            self._set_status("扫描完成：未发现设备")
        else:
            selected_index = 0
            for idx, (ip_text, mac_text) in enumerate(devices):
                self.device_combo.addItem(f"{ip_text}    [{mac_text}]", ip_text)
                if previous_ip and previous_ip == ip_text:
                    selected_index = idx
            self.device_combo.setCurrentIndex(selected_index)
            self._set_status(f"扫描完成：发现 {len(devices)} 台设备")

        self.is_scanning = False
        self.scan_device_button.setEnabled(True)

    def _on_scan_lan_finished(self, devices_obj: object, previous_ip: str, error_obj: object) -> None:
        devices = devices_obj if isinstance(devices_obj, list) else []
        error_text = str(error_obj) if isinstance(error_obj, str) and error_obj else None
        self._finish_scan_lan_devices(devices, previous_ip, error_text)

    def on_scan_lan_devices(self) -> None:
        if self.is_scanning:
            return

        self.is_scanning = True
        self.scan_device_button.setEnabled(False)
        previous_ip = self.device_combo.currentData() if self.device_combo.count() > 0 else ""
        self.device_combo.clear()
        self.device_combo.addItem("正在扫描局域网设备，请稍候...", "")
        self._set_status("正在扫描局域网设备，请稍候...")

        def worker() -> None:
            try:
                devices = self._discover_lan_devices()
                error_text = None
            except Exception as exc:  # noqa: BLE001
                devices = []
                error_text = str(exc)
            self.scan_lan_finished.emit(devices, str(previous_ip), error_text)

        threading.Thread(target=worker, daemon=True).start()

    def _parse_endpoint(self) -> tuple[str, int] | None:
        host_data = self.device_combo.currentData()
        host = str(host_data).strip() if host_data is not None else ""
        if not host:
            QMessageBox.warning(self, "输入提示", "请先扫描并选择局域网设备。")
            return None

        port_text = self.port_input.text().strip()
        try:
            port = int(port_text, 10)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "端口必须是整数。")
            return None

        if not (1 <= port <= 65535):
            QMessageBox.warning(self, "输入提示", "端口范围必须在 1 到 65535 之间。")
            return None

        return host, port

    def _set_connection_ui(self, connected: bool) -> None:
        self.test_button.setText("断开连接" if connected else "连接到设备")
        self.device_combo.setEnabled(not connected)
        self.scan_device_button.setEnabled(not connected)
        self.port_input.setEnabled(not connected)
        self._set_feature_gate(connected)

    def _disconnect_device(self, reason: str | None = None) -> None:
        if self.device_sock is not None:
            try:
                self.device_sock.close()
            except OSError:
                pass
        self.device_sock = None
        self.rx_buffer = b""
        self._set_connection_ui(False)
        self.scan_live_refresh_enabled = False
        self.pointer_scan_running = False
        self.pointer_status_request_inflight = False
        self.hwbp_refresh_inflight = False
        self.global_pid_label.setText("--")
        self.pointer_status_label.setText("扫描状态: 未连接")
        self.hwbp_num_brps_label.setText("hwbp_info.num_brps: 0")
        self.hwbp_num_wrps_label.setText("hwbp_info.num_wrps: 0")
        self.hwbp_hit_addr_label.setText("hwbp_info.hit_addr: 0x0")
        self.hwbp_record_count_label.setText("hwbp_info.record_count: 0")
        self.hwbp_record_combo.clear()
        self.hwbp_record_combo.addItem("无记录", "-1")
        self.hwbp_tree.clear()
        if reason:
            self._set_status(reason)

    def _connect_device(self) -> None:
        endpoint = self._parse_endpoint()
        if endpoint is None:
            return

        host, port = endpoint
        try:
            sock = socket.create_connection((host, port), timeout=NETWORK_TIMEOUT_SECONDS)
            sock.settimeout(NETWORK_TIMEOUT_SECONDS)
        except (ConnectionRefusedError, TimeoutError):
            self._set_status(f"连接失败：无法连接到 {host}:{port}")
            return
        except socket.timeout:
            self._set_status("连接失败：套接字超时")
            return
        except OSError as exc:
            if exc.errno is not None:
                self._set_status(f"连接失败：网络异常（错误码 {exc.errno}）")
            else:
                self._set_status("连接失败：网络异常")
            return

        self.device_sock = sock
        self.rx_buffer = b""
        self._set_connection_ui(True)
        self._set_status(f"已连接到设备：{host}:{port}")

    def _read_response_line(self) -> str | None:
        if self.device_sock is None:
            return None

        while True:
            split_idx = self.rx_buffer.find(b"\n")
            if split_idx != -1:
                line = self.rx_buffer[:split_idx]
                self.rx_buffer = self.rx_buffer[split_idx + 1 :]
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue
                return text

            try:
                data = self.device_sock.recv(4096)
            except socket.timeout:
                self._disconnect_device("连接已断开：等待响应超时")
                return None
            except OSError as exc:
                if exc.errno is not None:
                    self._disconnect_device(f"连接已断开：网络异常（错误码 {exc.errno}）")
                else:
                    self._disconnect_device("连接已断开：网络异常")
                return None

            if not data:
                self._disconnect_device("连接已断开：服务端关闭连接")
                return None

            self.rx_buffer += data
            if len(self.rx_buffer) > 65536:
                self._disconnect_device("连接已断开：响应数据异常")
                return None

    def _send_tcp_command(self, command: str, *, log_enabled: bool = True) -> str | None:
        command_text = command.strip()
        if log_enabled:
            self._log(f"发送命令: {command_text}")
        if self.device_sock is None:
            self._set_status("未连接设备，请先点击“连接到设备”")
            return None

        parts = command_text.split()
        if not parts:
            return "err 空命令"
        request_obj = {"command": parts[0], "args": parts[1:]}
        request_text = json.dumps(request_obj, ensure_ascii=False)

        try:
            self.device_sock.sendall((request_text + "\n").encode("utf-8"))
        except OSError as exc:
            if exc.errno is not None:
                self._disconnect_device(f"连接已断开：发送失败（错误码 {exc.errno}）")
            else:
                self._disconnect_device("连接已断开：发送失败")
            return None

        text = self._read_response_line()
        if text is None:
            return None

        try:
            response_obj = json.loads(text)
        except json.JSONDecodeError:
            if log_enabled:
                self._log(f"收到非JSON响应: {text}")
            return f"err 非JSON响应: {text}"

        if not isinstance(response_obj, dict):
            return "err 响应格式异常"

        is_ok = bool(response_obj.get("ok", False))
        if not is_ok:
            error_text = str(response_obj.get("error", "未知错误"))
            legacy_response = f"err {error_text}"
            if log_enabled:
                self._log(f"收到响应: {legacy_response}")
            return legacy_response

        if "data" in response_obj:
            legacy_response = "ok " + json.dumps(response_obj["data"], ensure_ascii=False)
        else:
            message = str(response_obj.get("message", ""))
            legacy_response = f"ok {message}"

        if log_enabled:
            self._log(f"收到响应: {legacy_response}")
        return legacy_response

    @staticmethod
    def _extract_pid(response: str | None) -> int | None:
        if not response or "pid=" not in response:
            return None
        try:
            pid_text = response.split("pid=", 1)[1].split()[0].strip()
            pid = int(pid_text, 10)
        except (ValueError, IndexError):
            return None
        return pid if pid > 0 else None

    @staticmethod
    def _safe_int(value: object, default: int = 0) -> int:
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return default
            try:
                return int(text, 0)
            except ValueError:
                return default
        return default

    @staticmethod
    def _format_addr(value: object) -> str:
        addr = TcpTestWindow._safe_int(value, 0)
        return f"0x{addr:016X}"

    @staticmethod
    def _format_prot(prot_value: object) -> str:
        prot = TcpTestWindow._safe_int(prot_value, 0)
        return f"{'r' if (prot & 1) else '-'}{'w' if (prot & 2) else '-'}{'x' if (prot & 4) else '-'}({prot})"

    def _module_matches_keyword(self, module: object, keyword: str) -> bool:
        if not isinstance(module, dict):
            return keyword in str(module).lower()

        name = str(module.get("name", "")).lower()
        if keyword in name:
            return True

        segs_raw = module.get("segs")
        segs = segs_raw if isinstance(segs_raw, list) else []
        for seg in segs:
            if not isinstance(seg, dict):
                continue
            index_val = self._safe_int(seg.get("index"), 0)
            prot_val = self._safe_int(seg.get("prot"), 0)
            start_val = self._safe_int(seg.get("start"), 0)
            end_val = self._safe_int(seg.get("end"), 0)
            tokens = [
                str(index_val),
                str(prot_val),
                self._format_prot(prot_val).lower(),
                f"0x{start_val:x}",
                f"0x{end_val:x}",
                str(start_val),
                str(end_val),
            ]
            if any(keyword in token for token in tokens):
                return True
        return False

    def _region_matches_keyword(self, region: object, keyword: str) -> bool:
        if not isinstance(region, dict):
            return keyword in str(region).lower()
        start_val = self._safe_int(region.get("start"), 0)
        end_val = self._safe_int(region.get("end"), 0)
        tokens = [f"0x{start_val:x}", f"0x{end_val:x}", str(start_val), str(end_val)]
        return any(keyword in token for token in tokens)

    def _filter_memory_info(self, info: dict, keyword: str) -> dict:
        keyword_text = keyword.strip().lower()
        if not keyword_text:
            return info

        modules_raw = info.get("modules")
        regions_raw = info.get("regions")
        modules = modules_raw if isinstance(modules_raw, list) else []
        regions = regions_raw if isinstance(regions_raw, list) else []

        filtered_modules = [m for m in modules if self._module_matches_keyword(m, keyword_text)]
        filtered_regions = [r for r in regions if self._region_matches_keyword(r, keyword_text)]

        return {
            "status": info.get("status", 0),
            "module_count": len(filtered_modules),
            "region_count": len(filtered_regions),
            "modules": filtered_modules,
            "regions": filtered_regions,
            "_source_module_count": len(modules),
            "_source_region_count": len(regions),
            "_filter_keyword": keyword,
        }

    def _format_memory_info_text(self, info: dict) -> str:
        status = self._safe_int(info.get("status"), 0)
        module_count = self._safe_int(info.get("module_count"), 0)
        region_count = self._safe_int(info.get("region_count"), 0)
        source_module_count = self._safe_int(info.get("_source_module_count"), module_count)
        source_region_count = self._safe_int(info.get("_source_region_count"), region_count)
        filter_keyword = str(info.get("_filter_keyword", "")).strip()

        modules_raw = info.get("modules")
        regions_raw = info.get("regions")
        modules = modules_raw if isinstance(modules_raw, list) else []
        regions = regions_raw if isinstance(regions_raw, list) else []

        lines: list[str] = []
        lines.append("【内存信息概要】")
        lines.append(f"状态: {status}")
        if filter_keyword:
            lines.append(f"筛选关键字: {filter_keyword}")
        lines.append(f"模块数量(头部): {module_count}")
        lines.append(f"内存区域数量(头部): {region_count}")
        lines.append(f"模块数量(实际): {len(modules)}")
        lines.append(f"内存区域数量(实际): {len(regions)}")
        if filter_keyword:
            lines.append(f"模块总量(筛选前): {source_module_count}")
            lines.append(f"区域总量(筛选前): {source_region_count}")
        lines.append("")

        lines.append("【模块信息】")
        if not modules:
            lines.append("无模块数据。")
        else:
            for idx, module in enumerate(modules, start=1):
                if isinstance(module, dict):
                    name = str(module.get("name", ""))
                    segs_raw = module.get("segs")
                    segs = segs_raw if isinstance(segs_raw, list) else []
                    seg_count = self._safe_int(module.get("seg_count"), len(segs))
                else:
                    name = str(module)
                    segs = []
                    seg_count = 0

                lines.append(f"{idx}. 模块: {name if name else '(空名称)'}")
                lines.append(f"   段数量: {seg_count}")
                if not segs:
                    lines.append("   段列表: (空)")
                    continue

                for seg_idx, seg in enumerate(segs, start=1):
                    if not isinstance(seg, dict):
                        lines.append(f"   - 段{seg_idx}: 非法数据")
                        continue
                    seg_index = self._safe_int(seg.get("index"), -999)
                    prot_text = self._format_prot(seg.get("prot"))
                    start_text = self._format_addr(seg.get("start"))
                    end_text = self._format_addr(seg.get("end"))
                    lines.append(
                        f"   - 段{seg_idx}: index={seg_index} prot={prot_text} start={start_text} end={end_text}"
                    )
        lines.append("")

        lines.append("【可扫描内存区域】")
        if not regions:
            lines.append("无区域数据。")
        else:
            for idx, region in enumerate(regions, start=1):
                if not isinstance(region, dict):
                    lines.append(f"{idx}. 非法数据")
                    continue
                start_text = self._format_addr(region.get("start"))
                end_text = self._format_addr(region.get("end"))
                lines.append(f"{idx}. start={start_text} end={end_text}")

        return "\n".join(lines)

    def _render_memory_info(self) -> None:
        if self.memory_info_data is None:
            self.memory_view.setPlainText("暂无内存信息，请先点击“刷新内存信息”。")
            return

        keyword = self.memory_filter_input.text().strip()
        filtered_info = self._filter_memory_info(self.memory_info_data, keyword)
        self.memory_view.setPlainText(self._format_memory_info_text(filtered_info))

    def on_toggle_connection(self) -> None:
        if self._is_connected():
            self._disconnect_device("已断开连接")
            return
        self._connect_device()

    def _build_scan_command(self, is_first: bool) -> str | None:
        data_type_data = self.scan_type_combo.currentData()
        data_type = str(data_type_data).strip() if data_type_data is not None else self.scan_type_combo.currentText().strip()
        mode_data = self.scan_mode_combo.currentData()
        mode = str(mode_data).strip() if mode_data is not None else ""
        value = self.scan_value_input.text().strip()
        range_text = self.scan_range_input.text().strip()

        base = "scan.first" if is_first else "scan.next"
        if mode == "unknown":
            return f"{base} {data_type} {mode}"

        if not value:
            QMessageBox.warning(self, "输入提示", "当前扫描模式需要输入“值”。")
            return None

        if mode == "range":
            if not range_text:
                QMessageBox.warning(self, "输入提示", "range 模式需要输入“范围”。")
                return None
            return f"{base} {data_type} {mode} {value} {range_text}"

        if range_text and range_text != "0":
            return f"{base} {data_type} {mode} {value} {range_text}"
        return f"{base} {data_type} {mode} {value}"

    @staticmethod
    def _parse_ok_pairs(response: str) -> dict[str, str]:
        payload = response[3:].strip() if response.startswith("ok ") else response.strip()
        result: dict[str, str] = {}
        for token in payload.split():
            if "=" in token:
                key, value = token.split("=", 1)
                result[key.strip()] = value.strip()
        return result

    @staticmethod
    def _extract_ok_json(response: str | None) -> dict | list | None:
        if response is None or not response.startswith("ok "):
            return None
        payload = response[3:].strip()
        if not payload:
            return {}
        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            return None
        if isinstance(data, (dict, list)):
            return data
        return None

    @staticmethod
    def _append_hwbp_tree_field(parent: QTreeWidgetItem, text: str) -> QTreeWidgetItem:
        item = QTreeWidgetItem([text])
        parent.addChild(item)
        return item

    def _extract_hwbp_index_from_tree_item(self, item: QTreeWidgetItem | None) -> int | None:
        current = item
        while current is not None:
            data = current.data(0, Qt.UserRole)
            if data is not None:
                try:
                    idx = int(str(data), 10)
                except (TypeError, ValueError):
                    idx = -1
                if idx >= 0:
                    return idx
            current = current.parent()
        return None

    def _decode_hwbp_rw_text(self, rec: dict) -> str:
        rw_text = str(rec.get("rw", "")).lower()
        if rw_text == "write":
            return "写入"
        if rw_text == "read":
            return "读取"
        return "未知"

    def _render_hwbp_tree(self, records: list[dict]) -> None:
        prev_expanded_pc: set[int] = set()
        for i in range(self.hwbp_tree.topLevelItemCount()):
            top_item = self.hwbp_tree.topLevelItem(i)
            if top_item is None or not top_item.isExpanded():
                continue
            pc_val = self._safe_int(top_item.data(0, Qt.UserRole + 1), -1)
            if pc_val >= 0:
                prev_expanded_pc.add(pc_val)
        prev_selected_idx = self._extract_hwbp_index_from_tree_item(self.hwbp_tree.currentItem())

        self.hwbp_tree.clear()
        if not records:
            empty_item = QTreeWidgetItem(["暂无 hwbp_record 命中记录"])
            self.hwbp_tree.addTopLevelItem(empty_item)
            return

        grouped: dict[int, list[dict]] = {}
        for rec in records:
            pc = self._safe_int(rec.get("pc"), 0)
            grouped.setdefault(pc, []).append(rec)

        for pc, rec_list in sorted(grouped.items(), key=lambda kv: kv[0]):
            total_hit = sum(self._safe_int(r.get("hit_count"), 0) for r in rec_list)
            type_tags = sorted({self._decode_hwbp_rw_text(r) for r in rec_list})
            type_text = "/".join(type_tags) if type_tags else "未知"
            top = QTreeWidgetItem(
                [f"PC 0x{pc:X}  |  记录 {len(rec_list)} 条  |  总命中 {total_hit}  |  触发类型 {type_text}"]
            )
            top.setData(0, Qt.UserRole + 1, pc)
            self.hwbp_tree.addTopLevelItem(top)
            if pc in prev_expanded_pc:
                top.setExpanded(True)

            for rec in rec_list:
                idx = self._safe_int(rec.get("index"), -1)
                hit_count = self._safe_int(rec.get("hit_count"), 0)
                rw_text = self._decode_hwbp_rw_text(rec)
                entry = QTreeWidgetItem([f"[{idx}] 命中 {hit_count} 次  |  类型 {rw_text}"])
                entry.setData(0, Qt.UserRole, idx)
                top.addChild(entry)

                lr = self._safe_int(rec.get("lr"), 0)
                sp = self._safe_int(rec.get("sp"), 0)
                orig_x0 = self._safe_int(rec.get("orig_x0"), 0)
                syscallno = self._safe_int(rec.get("syscallno"), 0)
                pstate = self._safe_int(rec.get("pstate"), 0)
                self._append_hwbp_tree_field(entry, f"LR: 0x{lr:X}")
                self._append_hwbp_tree_field(entry, f"SP: 0x{sp:X}")
                self._append_hwbp_tree_field(entry, f"ORIG_X0: 0x{orig_x0:X}")
                self._append_hwbp_tree_field(entry, f"SYSCALLNO: {syscallno}")
                self._append_hwbp_tree_field(entry, f"PSTATE: 0x{pstate:X}")

                regs_raw = rec.get("regs")
                regs = regs_raw if isinstance(regs_raw, list) else []
                regs_item = QTreeWidgetItem(["寄存器快照 X0~X29"])
                entry.addChild(regs_item)
                for reg_idx, reg_val in enumerate(regs):
                    reg_hex = self._safe_int(reg_val, 0)
                    QTreeWidgetItem(regs_item, [f"X{reg_idx}: 0x{reg_hex:X}"])

                if rw_text == "写入":
                    write_item = QTreeWidgetItem(["写入寄存器候选"])
                    entry.addChild(write_item)
                    x0_val = self._safe_int(regs[0], 0) if len(regs) > 0 else 0
                    x1_val = self._safe_int(regs[1], 0) if len(regs) > 1 else 0
                    QTreeWidgetItem(write_item, [f"候选写入值(X0): 0x{x0_val:X}"])
                    QTreeWidgetItem(write_item, [f"候选写入地址(X1): 0x{x1_val:X}"])

        if prev_selected_idx is not None:
            for i in range(self.hwbp_tree.topLevelItemCount()):
                top = self.hwbp_tree.topLevelItem(i)
                if top is None:
                    continue
                for j in range(top.childCount()):
                    child = top.child(j)
                    if child is None:
                        continue
                    idx = self._safe_int(child.data(0, Qt.UserRole), -1)
                    if idx == prev_selected_idx:
                        self.hwbp_tree.setCurrentItem(child)
                        break

        self.hwbp_tree.resizeColumnToContents(0)

    def _render_hwbp_info(self, info: dict) -> None:
        num_brps = self._safe_int(info.get("num_brps"), 0)
        num_wrps = self._safe_int(info.get("num_wrps"), 0)
        hit_addr = self._safe_int(info.get("hit_addr"), 0)
        record_count = self._safe_int(info.get("record_count"), 0)
        self.hwbp_num_brps_label.setText(f"hwbp_info.num_brps: {num_brps}")
        self.hwbp_num_wrps_label.setText(f"hwbp_info.num_wrps: {num_wrps}")
        self.hwbp_hit_addr_label.setText(f"hwbp_info.hit_addr: 0x{hit_addr:X}")
        self.hwbp_record_count_label.setText(f"hwbp_info.record_count: {record_count}")
        self.hwbp_record_combo.clear()
        records_raw = info.get("records")
        records = records_raw if isinstance(records_raw, list) else []
        if not records:
            self.hwbp_record_combo.addItem("无记录", "-1")
        else:
            for item in records:
                if not isinstance(item, dict):
                    continue
                idx = self._safe_int(item.get("index"), -1)
                pc = self._safe_int(item.get("pc"), 0)
                hit_count = self._safe_int(item.get("hit_count"), 0)
                self.hwbp_record_combo.addItem(f"idx={idx} pc=0x{pc:X} hit={hit_count}", str(idx))
        self._render_hwbp_tree(records)

    @staticmethod
    def _format_sig_result(data: dict) -> str:
        lines: list[str] = []
        count = TcpTestWindow._safe_int(data.get("count"), 0)
        returned_count = TcpTestWindow._safe_int(data.get("returned_count"), 0)
        truncated = bool(data.get("truncated", False))
        changed_count = data.get("changed_count")
        total_count = data.get("total_count")
        if changed_count is not None and total_count is not None:
            lines.append(f"过滤变化: {changed_count}/{total_count}")
        lines.append(f"匹配数量: {count}")
        lines.append(f"返回数量: {returned_count}")
        lines.append(f"是否截断: {'是' if truncated else '否'}")
        if "file" in data:
            lines.append(f"文件: {data.get('file')}")
        if "pattern" in data and str(data.get("pattern", "")):
            lines.append(f"特征码: {data.get('pattern')}")
        if "range" in data:
            lines.append(f"偏移: {data.get('range')}")
        if "old_signature" in data:
            lines.append(f"旧特征: {data.get('old_signature')}")
        if "new_signature" in data:
            lines.append(f"新特征: {data.get('new_signature')}")
        lines.append("")
        lines.append("【匹配地址】")
        matches_raw = data.get("matches")
        matches = matches_raw if isinstance(matches_raw, list) else []
        if not matches:
            lines.append("无")
        else:
            for idx, item in enumerate(matches, start=1):
                if isinstance(item, dict):
                    lines.append(f"{idx:04d}. {item.get('addr_hex', '0x0')}")
                else:
                    lines.append(f"{idx:04d}. {item}")
        return "\n".join(lines)

    def _render_scan_page(self, payload: dict) -> None:
        start = self._safe_int(payload.get("start"), 0)
        items_raw = payload.get("items")
        items = items_raw if isinstance(items_raw, list) else []

        lines: list[str] = []
        if not items:
            lines.append("本页没有结果。")
        else:
            for idx, item in enumerate(items, start=1):
                if not isinstance(item, dict):
                    lines.append(f"{start + idx:08d} | 非法数据")
                    continue
                addr_hex = str(item.get("addr_hex", ""))
                value = str(item.get("value", ""))
                lines.append(f"{start + idx:08d} | {addr_hex:<18} | {value}")

        self._set_text_preserve_interaction(self.scan_view, "\n".join(lines))

    @staticmethod
    def _parse_scan_line(line: str) -> tuple[str, str] | None:
        match = re.match(r"^\s*\d+\s*\|\s*(0x[0-9A-Fa-f]+)\s*\|\s*(.*)$", line)
        if not match:
            return None
        addr = match.group(1).strip()
        value = match.group(2).strip()
        if not addr:
            return None
        return addr, value

    @staticmethod
    def _build_read_command_for_type(type_token: str, addr: str) -> str | None:
        mapping = {
            "I8": "mem.read_u8",
            "I16": "mem.read_u16",
            "I32": "mem.read_u32",
            "I64": "mem.read_u64",
            "Float": "mem.read_f32",
            "Double": "mem.read_f64",
        }
        cmd = mapping.get(type_token)
        if cmd is None:
            return None
        return f"{cmd} {addr}"

    @staticmethod
    def _extract_value_field(response: str | None) -> str | None:
        if response is None or not response.startswith("ok "):
            return None
        if "value=" not in response:
            return None
        return response.split("value=", 1)[1].strip()

    @staticmethod
    def _set_text_preserve_interaction(editor: QTextEdit, text: str) -> bool:
        if editor.toPlainText() == text:
            return True

        cursor = editor.textCursor()
        if editor.hasFocus() and cursor.hasSelection():
            return False

        old_scroll = editor.verticalScrollBar().value()
        old_pos = cursor.position()

        editor.setPlainText(text)

        new_cursor = editor.textCursor()
        new_cursor.setPosition(min(old_pos, len(text)))
        editor.setTextCursor(new_cursor)
        editor.verticalScrollBar().setValue(min(old_scroll, editor.verticalScrollBar().maximum()))
        return True

    def _refresh_saved_view(self, force: bool = False) -> None:
        self.saved_count_label.setText(f"已保存: {len(self.saved_items)}")
        if not self.saved_items:
            self._set_text_preserve_interaction(self.saved_view, "")
            return

        lines = []
        for idx, item in enumerate(self.saved_items, start=1):
            addr = item.get("addr", "")
            value = item.get("value", "")
            type_token = item.get("type", "")
            lock_text = "锁定" if item.get("locked", "0") == "1" else "未锁"
            lines.append(f"{idx}. {addr} | {value} | {type_token} | {lock_text}")
        text = "\n".join(lines)

        if force:
            # 强制刷新：保存滚动位置，直接设置文本
            scroll = self.saved_view.verticalScrollBar().value()
            self.saved_view.setPlainText(text)
            self.saved_view.verticalScrollBar().setValue(scroll)
        else:
            self._set_text_preserve_interaction(self.saved_view, text)

    def on_scan_view_context_menu(self, pos) -> None:
        cursor = self.scan_view.cursorForPosition(pos)

        # 检查是否有选中文本（支持多选）
        text_cursor = self.scan_view.textCursor()
        if text_cursor.hasSelection():
            # 用户已通过鼠标选中多行，使用选中的文本
            selected_text = text_cursor.selectedText()
            # Qt 使用 U+2029 作为段落分隔符
            lines = selected_text.replace('\u2029', '\n').split('\n')
        else:
            # 没有选中文本，选择当前行
            cursor.select(cursor.SelectionType.LineUnderCursor)
            lines = [cursor.selectedText().strip()]

        # 解析所有选中的行
        parsed_items = []
        for line_text in lines:
            line_text = line_text.strip()
            if not line_text:
                continue
            parsed = self._parse_scan_line(line_text)
            if parsed is not None:
                parsed_items.append(parsed)

        if not parsed_items:
            return

        menu = QMenu(self.scan_view)
        save_action = menu.addAction(f"保存到保存页 ({len(parsed_items)} 项)" if len(parsed_items) > 1 else "保存到保存页")
        action = menu.exec(self.scan_view.mapToGlobal(pos))
        if action != save_action:
            return

        type_data = self.scan_type_combo.currentData()
        type_token = str(type_data).strip() if type_data is not None else self.scan_type_combo.currentText().strip()

        for addr, value in parsed_items:
            self.saved_items.append({"addr": addr, "value": value, "type": type_token, "locked": "0"})

        self._refresh_saved_view()
        if len(parsed_items) == 1:
            self._set_status(f"已保存: {parsed_items[0][0]} -> {parsed_items[0][1]}")
        else:
            self._set_status(f"已保存 {len(parsed_items)} 项")

    def _saved_index_from_line(self, line_text: str) -> int | None:
        match = re.match(r"^\s*(\d+)\.", line_text)
        if not match:
            return None
        idx = int(match.group(1), 10) - 1
        if idx < 0 or idx >= len(self.saved_items):
            return None
        return idx

    def on_saved_view_context_menu(self, pos) -> None:
        # 检查是否有选中文本（支持多选）
        text_cursor = self.saved_view.textCursor()
        if text_cursor.hasSelection():
            # 用户已通过鼠标选中多行，使用选中的文本
            selected_text = text_cursor.selectedText()
            # Qt 使用 U+2029 作为段落分隔符
            lines = selected_text.replace('\u2029', '\n').split('\n')
        else:
            # 没有选中文本，选择当前行
            cursor = self.saved_view.cursorForPosition(pos)
            cursor.select(cursor.SelectionType.LineUnderCursor)
            lines = [cursor.selectedText().strip()]

        # 解析所有选中的行，获取索引
        item_indices = []
        for line_text in lines:
            line_text = line_text.strip()
            if not line_text:
                continue
            item_idx = self._saved_index_from_line(line_text)
            if item_idx is not None:
                item_indices.append(item_idx)

        if not item_indices:
            return

        # 检查选中项的锁定状态
        items = [self.saved_items[idx] for idx in item_indices]
        locked_count = sum(1 for item in items if item.get("locked", "0") == "1")
        unlocked_count = len(items) - locked_count

        menu = QMenu(self.saved_view)
        if len(items) == 1:
            # 单选：显示锁定/取消锁定
            locked = items[0].get("locked", "0") == "1"
            lock_action = menu.addAction("取消锁定" if locked else "锁定此项")
        else:
            # 多选：显示批量操作选项
            lock_action = None
            actions = {}
            if unlocked_count > 0:
                actions["lock"] = menu.addAction(f"锁定 ({unlocked_count} 项)")
            if locked_count > 0:
                actions["unlock"] = menu.addAction(f"取消锁定 ({locked_count} 项)")

        action = menu.exec(self.saved_view.mapToGlobal(pos))

        if len(items) == 1:
            if action != lock_action:
                return
            # 处理单项锁定/取消锁定
            item = items[0]
            locked = item.get("locked", "0") == "1"
            addr = item.get("addr", "")
            type_token = item.get("type", "")
            value = item.get("value", "")
            if not addr or not type_token:
                return

            if locked:
                response = self._send_tcp_command(f"lock.unset {addr}")
                if response is None or not response.startswith("ok "):
                    QMessageBox.warning(self, "锁定失败", f"取消锁定失败: {response}")
                    return
                item["locked"] = "0"
                self._set_status(f"已取消锁定: {addr}")
            else:
                response = self._send_tcp_command(f"lock.set {addr} {type_token} {value}")
                if response is None or not response.startswith("ok "):
                    QMessageBox.warning(self, "锁定失败", f"锁定失败: {response}")
                    return
                item["locked"] = "1"
                self._set_status(f"已锁定: {addr} = {value}")
        else:
            # 处理批量操作
            if action not in actions.values():
                return

            success_count = 0
            fail_count = 0

            if action == actions.get("lock"):
                # 批量锁定未锁定的项
                for item in items:
                    if item.get("locked", "0") == "1":
                        continue
                    addr = item.get("addr", "")
                    type_token = item.get("type", "")
                    value = item.get("value", "")
                    if not addr or not type_token:
                        fail_count += 1
                        continue
                    response = self._send_tcp_command(f"lock.set {addr} {type_token} {value}")
                    if response is not None and response.startswith("ok "):
                        item["locked"] = "1"
                        success_count += 1
                    else:
                        fail_count += 1
                self._set_status(f"已锁定 {success_count} 项" + (f"，失败 {fail_count} 项" if fail_count > 0 else ""))

            elif action == actions.get("unlock"):
                # 批量取消锁定
                for item in items:
                    if item.get("locked", "0") != "1":
                        continue
                    addr = item.get("addr", "")
                    if not addr:
                        fail_count += 1
                        continue
                    response = self._send_tcp_command(f"lock.unset {addr}")
                    if response is not None and response.startswith("ok "):
                        item["locked"] = "0"
                        success_count += 1
                    else:
                        fail_count += 1
                self._set_status(f"已取消锁定 {success_count} 项" + (f"，失败 {fail_count} 项" if fail_count > 0 else ""))

        # 清除选择后强制刷新显示
        cursor = self.saved_view.textCursor()
        cursor.clearSelection()
        self.saved_view.setTextCursor(cursor)
        self._refresh_saved_view(force=True)

    def on_clear_saved_items(self) -> None:
        self.saved_items.clear()
        self._refresh_saved_view()
        self._set_status("保存页已清空")

    def _get_scan_page_size(self, *, silent: bool = False) -> int | None:
        count_text = self.scan_page_count_input.text().strip()
        try:
            page_count = int(count_text, 10)
        except ValueError:
            if not silent:
                QMessageBox.warning(self, "输入提示", "分页数量必须是整数。")
            return None

        if page_count <= 0:
            if not silent:
                QMessageBox.warning(self, "输入提示", "分页数量必须大于 0。")
            return None
        return page_count

    def _fetch_scan_page(self, start: int, *, silent: bool = False) -> bool:
        page_count = self._get_scan_page_size(silent=silent)
        if page_count is None:
            return False

        type_data = self.scan_type_combo.currentData()
        type_token = str(type_data).strip() if type_data is not None else self.scan_type_combo.currentText().strip()

        response = self._send_tcp_command(f"scan.page {start} {page_count} {type_token}", log_enabled=not silent)
        if response is None:
            return False
        if not response.startswith("ok "):
            if not silent:
                QMessageBox.warning(self, "获取失败", response)
                self._set_status("获取扫描结果失败")
            return False

        payload = response[3:]
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            if not silent:
                QMessageBox.warning(self, "解析失败", f"扫描结果 JSON 解析失败: {exc}")
            return False

        if not isinstance(data, dict):
            if not silent:
                QMessageBox.warning(self, "解析失败", "扫描结果格式异常。")
            return False

        self._render_scan_page(data)
        self.scan_page_start = self._safe_int(data.get("start"), start)
        self.scan_total_count = self._safe_int(data.get("total_count"), 0)
        self.scan_total_label.setText(f"总结果数: {self.scan_total_count}")
        self.scan_live_refresh_enabled = True
        if not silent:
            total = self.scan_total_count
            self._set_status(f"扫描结果已刷新：start={self.scan_page_start}, total={total}")
        return True

    def on_scan_first(self) -> None:
        command = self._build_scan_command(is_first=True)
        if command is None:
            return
        response = self._send_tcp_command(command)
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "扫描失败", response)
            self._set_status("首次扫描失败")
            return
        self._set_status("首次扫描已执行")
        self.on_scan_status()
        self.scan_page_start = 0
        self._fetch_scan_page(self.scan_page_start)

    def on_scan_next(self) -> None:
        command = self._build_scan_command(is_first=False)
        if command is None:
            return
        response = self._send_tcp_command(command)
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "扫描失败", response)
            self._set_status("再次扫描失败")
            return
        self._set_status("再次扫描已执行")
        self.on_scan_status()
        self.scan_page_start = 0
        self._fetch_scan_page(self.scan_page_start)

    def on_scan_clear(self) -> None:
        response = self._send_tcp_command("scan.clear")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "清空失败", response)
            return
        self.scan_view.clear()
        self.scan_page_start = 0
        self.scan_total_count = 0
        self.scan_live_refresh_enabled = False
        self.scan_total_label.setText("总结果数: 0")
        self._set_status("扫描结果已清空")

    def on_scan_status(self) -> None:
        response = self._send_tcp_command("scan.status")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "状态失败", response)
            return
        pairs = self._parse_ok_pairs(response)
        scanning = pairs.get("scanning", "0")
        progress = pairs.get("progress", "0")
        count = pairs.get("count", "0")
        self.scan_total_label.setText(f"总结果数: {count}")
        self._set_status(f"扫描状态: scanning={scanning}, progress={progress}, count={count}")

    def on_scan_fetch_page(self) -> None:
        if self.scan_page_start < 0:
            self.scan_page_start = 0
        self._fetch_scan_page(self.scan_page_start)

    def on_scan_prev_page(self) -> None:
        page_count = self._get_scan_page_size()
        if page_count is None:
            return
        self.scan_page_start = max(0, self.scan_page_start - page_count)
        self._fetch_scan_page(self.scan_page_start)

    def on_scan_next_page(self) -> None:
        page_count = self._get_scan_page_size()
        if page_count is None:
            return
        if self.scan_total_count > 0 and self.scan_page_start + page_count >= self.scan_total_count:
            self._set_status("已经是最后一页")
            return
        self.scan_page_start = self.scan_page_start + page_count
        self._fetch_scan_page(self.scan_page_start)

    def _parse_browser_addr(self) -> int | None:
        text = self.browser_addr_input.text().strip()
        if not text:
            QMessageBox.warning(self, "输入提示", "请输入地址。")
            return None
        try:
            addr = int(text, 0)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "地址格式无效。")
            return None
        if addr < 0:
            QMessageBox.warning(self, "输入提示", "地址必须为非负数。")
            return None
        return addr

    def _parse_browser_size(self) -> int | None:
        text = self.browser_size_input.text().strip()
        try:
            size = int(text, 10)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "大小必须是整数。")
            return None
        if size <= 0 or size > 4096:
            QMessageBox.warning(self, "输入提示", "大小范围必须在 1 到 4096。")
            return None
        return size

    @staticmethod
    def _hex_to_bytes(hex_text: str) -> bytes | None:
        compact = re.sub(r"[^0-9A-Fa-f]", "", hex_text)
        if not compact or len(compact) % 2 != 0:
            return None
        try:
            return bytes.fromhex(compact)
        except ValueError:
            return None

    @staticmethod
    def _browser_mode_to_token(mode_text: str) -> str:
        mapping = {
            "Hex": "hex",
            "Hex64": "hex64",
            "I8": "i8",
            "I16": "i16",
            "I32": "i32",
            "I64": "i64",
            "Float": "f32",
            "Double": "f64",
            "Disasm": "disasm",
        }
        return mapping.get(mode_text, "hex")

    def _read_browser_bytes(self, addr: int, size: int) -> bytes | None:
        response = self._send_tcp_command(f"mem.read 0x{addr:X} {size}", log_enabled=False)
        if response is None or not response.startswith("ok "):
            QMessageBox.warning(self, "读取失败", f"读取内存失败: {response}")
            return None
        if "hex=" not in response:
            QMessageBox.warning(self, "读取失败", f"响应格式异常: {response}")
            return None
        hex_text = response.split("hex=", 1)[1].strip()
        data = self._hex_to_bytes(hex_text)
        if data is None:
            QMessageBox.warning(self, "读取失败", "HEX 数据解析失败。")
            return None
        return data

    @staticmethod
    def _render_hex_dump(addr: int, data: bytes) -> str:
        lines: list[str] = []
        for offset in range(0, len(data), 16):
            chunk = data[offset : offset + 16]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"0x{addr + offset:016X}  {hex_part:<47}  {ascii_part}")
        return "\n".join(lines)

    @staticmethod
    def _render_hex64_dump(addr: int, data: bytes) -> str:
        lines: list[str] = []
        for offset in range(0, len(data), 8):
            chunk = data[offset : offset + 8]
            if len(chunk) == 8:
                value = struct.unpack("<Q", chunk)[0]
                lines.append(f"0x{addr + offset:016X}  0x{value:016X}")
            else:
                raw_hex = " ".join(f"{b:02X}" for b in chunk)
                lines.append(f"0x{addr + offset:016X}  {raw_hex}")
        return "\n".join(lines)

    @staticmethod
    def _render_typed_dump(addr: int, data: bytes, fmt: str) -> str:
        mapping = {
            "i8": ("<b", 1),
            "i16": ("<h", 2),
            "i32": ("<i", 4),
            "i64": ("<q", 8),
            "f32": ("<f", 4),
            "f64": ("<d", 8),
            "I8": ("<b", 1),
            "I16": ("<h", 2),
            "I32": ("<i", 4),
            "I64": ("<q", 8),
            "Float": ("<f", 4),
            "Double": ("<d", 8),
        }
        if fmt not in mapping:
            return TcpTestWindow._render_hex_dump(addr, data)

        unpack_fmt, unit = mapping[fmt]
        lines: list[str] = []
        for offset in range(0, len(data) - (len(data) % unit), unit):
            chunk = data[offset : offset + unit]
            try:
                value = struct.unpack(unpack_fmt, chunk)[0]
            except struct.error:
                continue
            lines.append(f"0x{addr + offset:016X}  {value}")
        if not lines:
            lines.append("没有可显示的数据。")
        return "\n".join(lines)

    @staticmethod
    def _render_disasm_dump(snapshot: dict) -> str:
        lines: list[str] = []
        disasm_list_raw = snapshot.get("disasm")
        disasm_list = disasm_list_raw if isinstance(disasm_list_raw, list) else []
        if not disasm_list:
            return "没有可显示的反汇编结果。"

        for item in disasm_list:
            if not isinstance(item, dict):
                continue
            address_hex = str(item.get("address_hex", "0x0"))
            bytes_hex = str(item.get("bytes_hex", ""))
            mnemonic = str(item.get("mnemonic", "")).strip()
            op_str = str(item.get("op_str", "")).strip()
            if op_str:
                lines.append(f"{address_hex:<18} {bytes_hex:<24} {mnemonic} {op_str}")
            else:
                lines.append(f"{address_hex:<18} {bytes_hex:<24} {mnemonic}")

        return "\n".join(lines) if lines else "没有可显示的反汇编结果。"

    def _read_viewer_snapshot(self) -> dict | None:
        response = self._send_tcp_command("viewer.get", log_enabled=False)
        if response is None:
            return None
        if not response.startswith("ok "):
            QMessageBox.warning(self, "读取失败", f"内存浏览读取失败: {response}")
            return None
        payload = response[3:]
        try:
            data = json.loads(payload)
        except json.JSONDecodeError as exc:
            QMessageBox.warning(self, "解析失败", f"浏览器 JSON 解析失败: {exc}")
            return None
        if not isinstance(data, dict):
            QMessageBox.warning(self, "解析失败", "浏览器数据格式异常。")
            return None
        return data

    def _refresh_disasm_view(self, addr: int) -> None:
        mode_data = self.browser_view_combo.currentData()
        mode_token = str(mode_data).strip() if mode_data is not None else self._browser_mode_to_token(self.browser_view_combo.currentText().strip())
        open_resp = self._send_tcp_command(f"viewer.open 0x{addr:X} {mode_token}", log_enabled=False)
        if open_resp is None or not open_resp.startswith("ok "):
            QMessageBox.warning(self, "读取失败", f"打开浏览器失败: {open_resp}")
            return

        snapshot = self._read_viewer_snapshot()
        if snapshot is None:
            return

        base_addr = self._safe_int(snapshot.get("base"), addr)
        self.browser_base_addr = base_addr
        self.browser_addr_input.setText(f"0x{base_addr:X}")
        self.browser_view.setPlainText(self._render_disasm_dump(snapshot))

    def _move_disasm_view(self, lines: int) -> None:
        move_resp = self._send_tcp_command(f"viewer.move {lines}", log_enabled=False)
        if move_resp is None or not move_resp.startswith("ok "):
            QMessageBox.warning(self, "移动失败", f"反汇编移动失败: {move_resp}")
            return

        snapshot = self._read_viewer_snapshot()
        if snapshot is None:
            return
        base_addr = self._safe_int(snapshot.get("base"), 0)
        self.browser_base_addr = base_addr
        self.browser_addr_input.setText(f"0x{base_addr:X}")
        self.browser_view.setPlainText(self._render_disasm_dump(snapshot))

    def _refresh_browser_view(self, addr: int, size: int) -> None:
        data = self._read_browser_bytes(addr, size)
        if data is None:
            return

        mode_data = self.browser_view_combo.currentData()
        view_mode = str(mode_data).strip() if mode_data is not None else self._browser_mode_to_token(self.browser_view_combo.currentText().strip())
        if view_mode == "hex":
            text = self._render_hex_dump(addr, data)
        elif view_mode == "hex64":
            text = self._render_hex64_dump(addr, data)
        else:
            text = self._render_typed_dump(addr, data, view_mode)

        self.browser_base_addr = addr
        self.browser_addr_input.setText(f"0x{addr:X}")
        self.browser_view.setPlainText(text)

    def on_browser_read(self) -> None:
        mode_data = self.browser_view_combo.currentData()
        view_mode = str(mode_data).strip() if mode_data is not None else self._browser_mode_to_token(self.browser_view_combo.currentText().strip())
        if view_mode == "disasm":
            addr = self._parse_browser_addr()
            if addr is None:
                return
            self._refresh_disasm_view(addr)
            return

        addr = self._parse_browser_addr()
        if addr is None:
            return
        size = self._parse_browser_size()
        if size is None:
            return
        self._refresh_browser_view(addr, size)

    def on_browser_prev(self) -> None:
        mode_data = self.browser_view_combo.currentData()
        view_mode = str(mode_data).strip() if mode_data is not None else self._browser_mode_to_token(self.browser_view_combo.currentText().strip())
        if view_mode == "disasm":
            self._move_disasm_view(-10)
            return

        size = self._parse_browser_size()
        if size is None:
            return
        current = self._parse_browser_addr()
        if current is None:
            return
        next_addr = max(0, current - size)
        self._refresh_browser_view(next_addr, size)

    def on_browser_next(self) -> None:
        mode_data = self.browser_view_combo.currentData()
        view_mode = str(mode_data).strip() if mode_data is not None else self._browser_mode_to_token(self.browser_view_combo.currentText().strip())
        if view_mode == "disasm":
            self._move_disasm_view(10)
            return

        size = self._parse_browser_size()
        if size is None:
            return
        current = self._parse_browser_addr()
        if current is None:
            return
        self._refresh_browser_view(current + size, size)

    def _build_pointer_scan_command(self) -> str | None:
        target_text = self.pointer_target_input.text().strip()
        depth_text = self.pointer_depth_input.text().strip()
        max_offset_text = self.pointer_max_offset_input.text().strip()
        filter_text = self.pointer_filter_input.text().strip()

        try:
            target = int(target_text, 0)
            depth = int(depth_text, 10)
            max_offset = int(max_offset_text, 10)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "目标地址/深度/最大偏移格式无效。")
            return None

        if target <= 0 or depth <= 0 or max_offset <= 0:
            QMessageBox.warning(self, "输入提示", "目标地址、深度、最大偏移必须大于 0。")
            return None

        mode_data = self.pointer_mode_combo.currentData()
        mode = str(mode_data).strip() if mode_data is not None else "module"
        base_cmd = f"pointer.scan 0x{target:X} {depth} {max_offset}"

        if mode == "manual":
            manual_base_text = self.pointer_manual_base_input.text().strip()
            manual_offset_text = self.pointer_manual_offset_input.text().strip()
            try:
                manual_base = int(manual_base_text, 0)
                manual_offset = int(manual_offset_text, 10)
            except ValueError:
                QMessageBox.warning(self, "输入提示", "手动基址或手动范围格式无效。")
                return None
            if manual_base <= 0 or manual_offset <= 0:
                QMessageBox.warning(self, "输入提示", "手动基址和手动范围必须大于 0。")
                return None
            base_cmd = f"pointer.scan.manual 0x{target:X} {depth} {max_offset} 0x{manual_base:X} {manual_offset}"
        elif mode == "array":
            array_base_text = self.pointer_array_base_input.text().strip()
            array_count_text = self.pointer_array_count_input.text().strip()
            try:
                array_base = int(array_base_text, 0)
                array_count = int(array_count_text, 10)
            except ValueError:
                QMessageBox.warning(self, "输入提示", "数组基址或数组数量格式无效。")
                return None
            if array_base <= 0 or array_count <= 0:
                QMessageBox.warning(self, "输入提示", "数组基址和数组数量必须大于 0。")
                return None
            base_cmd = f"pointer.scan.array 0x{target:X} {depth} {max_offset} 0x{array_base:X} {array_count}"

        if filter_text:
            return f"{base_cmd} {filter_text}"
        return base_cmd

    def on_pointer_scan(self) -> None:
        command = self._build_pointer_scan_command()
        if command is None:
            return

        response = self._send_tcp_command(command)
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "指针扫描失败", response)
            self._set_status("指针扫描启动失败")
            return

        self.pointer_view.append(f"启动命令: {command}")
        self.pointer_scan_running = True
        self._set_status("指针扫描任务已启动")
        self.on_pointer_status()

    def _update_pointer_status_from_response(self, response: str, *, silent: bool = False) -> None:
        if not response.startswith("ok "):
            if not silent:
                QMessageBox.warning(self, "状态失败", response)
            return

        pairs = self._parse_ok_pairs(response)
        scanning = pairs.get("scanning", "0")
        progress = pairs.get("progress", "0")
        count = pairs.get("count", "0")
        self.pointer_scan_running = (scanning == "1")
        status_text = f"扫描状态: scanning={scanning}, progress={progress}, count={count}"
        self.pointer_status_label.setText(status_text)
        if not silent:
            self.pointer_view.append(status_text)
            self._set_status("指针状态已刷新")

    def on_pointer_status(self) -> None:
        response = self._send_tcp_command("pointer.status")
        if response is None:
            return
        self._update_pointer_status_from_response(response, silent=False)

    def _refresh_pointer_status_live(self) -> None:
        if not (self._is_pointer_tab_active() or self.pointer_scan_running):
            return
        if self.pointer_status_request_inflight:
            return

        self.pointer_status_request_inflight = True
        try:
            response = self._send_tcp_command("pointer.status", log_enabled=False)
            if response is None:
                return
            self._update_pointer_status_from_response(response, silent=True)
        finally:
            self.pointer_status_request_inflight = False

    def on_pointer_merge(self) -> None:
        response = self._send_tcp_command("pointer.merge")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "合并失败", response)
            return
        self.pointer_view.append("已触发 Pointer.bin 合并任务。")
        self._set_status("已触发合并任务")

    def on_pointer_export(self) -> None:
        response = self._send_tcp_command("pointer.export")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "导出失败", response)
            return
        self.pointer_view.append("已触发指针链文本导出。")
        self._set_status("已触发导出任务")

    def _refresh_saved_items_live(self) -> None:
        if not self.saved_items:
            return
        if not self._is_connected():
            return

        changed = False
        # 实时刷新时做上限保护，避免一次轮询过重。
        refresh_count = min(len(self.saved_items), 300)
        for i in range(refresh_count):
            item = self.saved_items[i]
            addr = item.get("addr", "")
            type_token = item.get("type", "")
            command = self._build_read_command_for_type(type_token, addr)
            if command is None:
                continue
            response = self._send_tcp_command(command, log_enabled=False)
            value = self._extract_value_field(response)
            if value is None:
                continue
            if item.get("value", "") != value:
                item["value"] = value
                changed = True

        if changed:
            self._refresh_saved_view()

    def on_live_refresh_tick(self) -> None:
        if not self._is_connected():
            return

        if self.scan_live_refresh_enabled:
            self._fetch_scan_page(self.scan_page_start, silent=True)

        self._refresh_saved_items_live()
        self._refresh_pointer_status_live()
        self._refresh_hwbp_info_live()

    def on_sync_pid(self) -> None:
        input_text = self.pid_input.text().strip()
        if not input_text:
            QMessageBox.warning(self, "输入提示", "请输入 PID 或包名。")
            return

        pid_value: int | None = None
        if input_text.isdigit():
            pid_value = int(input_text, 10)
            if pid_value <= 0:
                QMessageBox.warning(self, "输入提示", "PID 必须大于 0。")
                return
        else:
            get_response = self._send_tcp_command(f"pid.get {input_text}")
            pid_value = self._extract_pid(get_response)
            if pid_value is None:
                QMessageBox.warning(self, "同步失败", "包名获取 PID 失败。")
                self._set_status("同步失败：包名获取 PID 失败")
                return

        set_response = self._send_tcp_command(f"pid.set {pid_value}")
        if set_response is None or not set_response.startswith("ok"):
            QMessageBox.warning(self, "同步失败", "设置全局 PID 失败。")
            self._set_status("同步失败：设置全局 PID 失败")
            return

        current_response = self._send_tcp_command("pid.current")
        current_pid = self._extract_pid(current_response)
        if current_pid is None:
            self.global_pid_label.setText("--")
            self._set_status("同步后读取全局 PID 失败")
            return

        self.global_pid_label.setText(str(current_pid))
        self._set_status(f"同步成功：全局PID={current_pid}")

    def on_refresh_memory_info(self) -> None:
        response = self._send_tcp_command("memory.info.full")
        if response is None:
            return

        if not response.startswith("ok "):
            self.memory_view.setPlainText(f"刷新失败：\n{response}")
            self._set_status("刷新内存信息失败")
            QMessageBox.warning(self, "刷新失败", f"内存信息刷新失败：{response}")
            return

        payload = response[3:]
        try:
            info = json.loads(payload)
        except json.JSONDecodeError as exc:
            self.memory_view.setPlainText(f"JSON 解析失败：{exc}\n\n原始内容：\n{payload[:4000]}")
            self._set_status("刷新内存信息失败：JSON解析失败")
            return

        self.memory_info_data = info
        self._render_memory_info()

        module_count = info.get("module_count", "未知")
        region_count = info.get("region_count", "未知")
        self._set_status(f"内存信息刷新成功：模块={module_count}，区域={region_count}")

    def on_filter_memory_info(self) -> None:
        if self.memory_info_data is None:
            QMessageBox.warning(self, "提示", "暂无内存信息，请先点击“刷新内存信息”。")
            return
        self._render_memory_info()
        keyword = self.memory_filter_input.text().strip()
        if keyword:
            self._set_status(f"已应用筛选：{keyword}")
        else:
            self._set_status("已取消筛选，显示全部数据")

    def on_clear_memory_filter(self) -> None:
        self.memory_filter_input.clear()
        if self.memory_info_data is not None:
            self._render_memory_info()
        self._set_status("已清空筛选条件")

    def on_hwbp_refresh(self, silent: bool = False) -> None:
        response = self._send_tcp_command("hwbp.info", log_enabled=not silent)
        if response is None:
            return
        data = self._extract_ok_json(response)
        if not isinstance(data, dict):
            if not silent:
                QMessageBox.warning(self, "刷新失败", f"断点信息响应异常: {response}")
                self._set_status("断点信息刷新失败")
            return
        self.hwbp_info_data = data
        self._render_hwbp_info(data)
        if not silent:
            self._set_status("断点信息已刷新")

    def on_hwbp_set(self) -> None:
        addr_text = self.hwbp_addr_input.text().strip()
        len_text = self.hwbp_len_input.text().strip()
        type_data = self.hwbp_type_combo.currentData()
        scope_data = self.hwbp_scope_combo.currentData()
        try:
            addr = int(addr_text, 0)
            length = int(len_text, 10)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "断点地址或长度格式无效。")
            return
        if addr <= 0:
            QMessageBox.warning(self, "输入提示", "断点地址必须大于 0。")
            return
        if length <= 0:
            QMessageBox.warning(self, "输入提示", "长度必须大于 0。")
            return
        bp_type = str(type_data) if type_data is not None else "0"
        bp_scope = str(scope_data) if scope_data is not None else "0"
        response = self._send_tcp_command(f"hwbp.set 0x{addr:X} {bp_type} {bp_scope} {length}")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "设置失败", response)
            self._set_status("设置硬件断点失败")
            return
        self._set_status("设置硬件断点成功")
        self.on_hwbp_refresh(silent=True)

    def on_hwbp_remove_all(self) -> None:
        response = self._send_tcp_command("hwbp.remove")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "移除失败", response)
            return
        self._set_status("已移除进程硬件断点")
        self.on_hwbp_refresh(silent=True)

    def on_hwbp_remove_record(self) -> None:
        text = self.hwbp_record_index_input.text().strip()
        if text:
            try:
                index = int(text, 10)
            except ValueError:
                QMessageBox.warning(self, "输入提示", "记录索引必须是整数。")
                return
        else:
            combo_data = self.hwbp_record_combo.currentData()
            try:
                index = int(str(combo_data), 10)
            except (TypeError, ValueError):
                QMessageBox.warning(self, "输入提示", "请选择有效的 hwbp_record 索引。")
                return
        if index < 0:
            QMessageBox.warning(self, "输入提示", "记录索引不能小于 0。")
            return
        response = self._send_tcp_command(f"hwbp.record.remove {index}")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "删除失败", response)
            return
        self._set_status(f"已删除断点记录索引 {index}")
        self.on_hwbp_refresh(silent=True)

    def on_hwbp_tree_current_item_changed(self, current: QTreeWidgetItem | None, _previous: QTreeWidgetItem | None) -> None:
        idx = self._extract_hwbp_index_from_tree_item(current)
        if idx is None:
            return
        self.hwbp_record_index_input.setText(str(idx))

    def on_hwbp_record_combo_changed(self, _index: int) -> None:
        data = self.hwbp_record_combo.currentData()
        try:
            idx = int(str(data), 10)
        except (TypeError, ValueError):
            return
        if idx >= 0:
            self.hwbp_record_index_input.setText(str(idx))

    def on_hwbp_tree_context_menu(self, pos) -> None:
        item = self.hwbp_tree.itemAt(pos)
        idx = self._extract_hwbp_index_from_tree_item(item)

        menu = QMenu(self.hwbp_tree)
        fill_action = menu.addAction("填入当前索引")
        delete_action = menu.addAction("删除当前 hwbp_record")
        menu.addSeparator()
        expand_action = menu.addAction("展开当前节点")
        collapse_action = menu.addAction("折叠当前节点")
        expand_all_action = menu.addAction("全部展开")
        collapse_all_action = menu.addAction("全部折叠")

        if idx is None:
            fill_action.setEnabled(False)
            delete_action.setEnabled(False)
        if item is None:
            expand_action.setEnabled(False)
            collapse_action.setEnabled(False)

        action = menu.exec(self.hwbp_tree.mapToGlobal(pos))
        if action is None:
            return

        if action == expand_all_action:
            self.hwbp_tree.expandAll()
            return
        if action == collapse_all_action:
            self.hwbp_tree.collapseAll()
            return
        if action == expand_action and item is not None:
            item.setExpanded(True)
            return
        if action == collapse_action and item is not None:
            item.setExpanded(False)
            return
        if idx is None:
            return
        if action == fill_action:
            self.hwbp_record_index_input.setText(str(idx))
            self._set_status(f"已填入 hwbp_record 索引 {idx}")
            return
        if action != delete_action:
            return

        response = self._send_tcp_command(f"hwbp.record.remove {idx}")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "删除失败", response)
            return

        self.hwbp_record_index_input.setText(str(idx))
        self._set_status(f"已删除 hwbp_record[{idx}]")
        self.on_hwbp_refresh(silent=True)

    def _refresh_hwbp_info_live(self) -> None:
        if not self._is_breakpoint_tab_active():
            return
        if self.hwbp_refresh_inflight:
            return
        self.hwbp_refresh_inflight = True
        try:
            self.on_hwbp_refresh(silent=True)
        finally:
            self.hwbp_refresh_inflight = False

    def _render_signature_data(self, data: dict, status_text: str) -> None:
        self.sig_status_label.setText(status_text)
        self._set_text_preserve_interaction(self.sig_view, self._format_sig_result(data))

    def on_sig_scan_address(self) -> None:
        addr_text = self.sig_addr_input.text().strip()
        range_text = self.sig_range_input.text().strip()
        file_name = self.sig_file_input.text().strip() or "Signature.txt"
        try:
            addr = int(addr_text, 0)
            scan_range = int(range_text, 10)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "目标地址或范围格式无效。")
            return
        response = self._send_tcp_command(f"sig.scan.addr 0x{addr:X} {scan_range} {file_name}")
        if response is None:
            return
        if not response.startswith("ok "):
            QMessageBox.warning(self, "执行失败", response)
            self.sig_status_label.setText("特征码状态: 扫描并保存失败")
            return
        self.sig_status_label.setText("特征码状态: 扫描并保存成功")
        self._set_status(f"特征码已保存到 {file_name}")

    def on_sig_filter(self) -> None:
        addr_text = self.sig_verify_addr_input.text().strip()
        file_name = self.sig_file_input.text().strip() or "Signature.txt"
        try:
            addr = int(addr_text, 0)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "过滤地址格式无效。")
            return
        response = self._send_tcp_command(f"sig.filter 0x{addr:X} {file_name}")
        if response is None:
            return
        data = self._extract_ok_json(response)
        if not isinstance(data, dict):
            QMessageBox.warning(self, "执行失败", f"过滤响应异常: {response}")
            return
        success = bool(data.get("success", False))
        self._render_signature_data(data, "特征码状态: 过滤成功" if success else "特征码状态: 过滤失败")
        self._set_status("特征码过滤已完成")

    def on_sig_scan_file(self) -> None:
        file_name = self.sig_file_input.text().strip() or "Signature.txt"
        response = self._send_tcp_command(f"sig.scan.file {file_name}")
        if response is None:
            return
        data = self._extract_ok_json(response)
        if not isinstance(data, dict):
            QMessageBox.warning(self, "执行失败", f"文件扫描响应异常: {response}")
            return
        self._render_signature_data(data, "特征码状态: 文件扫描完成")
        self._set_status("特征码文件扫描已完成")

    def on_sig_scan_pattern(self) -> None:
        pattern = self.sig_pattern_input.text().strip()
        if not pattern:
            QMessageBox.warning(self, "输入提示", "请输入特征码。")
            return
        range_text = self.sig_pattern_range_input.text().strip()
        try:
            range_offset = int(range_text, 10)
        except ValueError:
            QMessageBox.warning(self, "输入提示", "偏移必须是整数。")
            return
        response = self._send_tcp_command(f"sig.scan.pattern {range_offset} {pattern}")
        if response is None:
            return
        data = self._extract_ok_json(response)
        if not isinstance(data, dict):
            QMessageBox.warning(self, "执行失败", f"特征码扫描响应异常: {response}")
            return
        self._render_signature_data(data, "特征码状态: 按特征码扫描完成")
        self._set_status("按特征码扫描已完成")

    def closeEvent(self, event) -> None:  # type: ignore[override]
        self.live_refresh_timer.stop()
        self._disconnect_device()
        super().closeEvent(event)


def main() -> int:
    app = QApplication(sys.argv)
    window = TcpTestWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
