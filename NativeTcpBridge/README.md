# NativeTcpBridge

这是 `Kernel` 目录下的跨平台 TCP 示例项目：
- Android 端：原生可执行服务端（被动监听）
- Windows 端：PySide6 图形客户端（主动连接并发送命令）

## 目录结构

```text
NativeTcpBridge/
  android/
    Android.mk
    Application.mk
    include/DriverMemory.h
    src/main.cpp
  windows/
    tcp_client.py
    tcp_client.pyw
```

## Android 端编译与运行

在 `NativeTcpBridge/android` 目录执行：

```powershell
E:\android-ndk-r29\ndk-build.cmd NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./Android.mk APP_STL=c++_static APP_ABI=arm64-v8a APP_PLATFORM=android-24 -j12
```

该命令会自动完成：
- 编译 `tcp_server`
- 推送到设备 `/data/akernel/tcp_server`
- 后台启动服务端并打印进程状态

服务端固定端口：`9494`

## Windows 端（纯图形界面）

安装依赖：

```powershell
pip install PySide6
```

启动（不需要命令行参数）：
- 双击 `windows/tcp_client.pyw`

可选：

```powershell
pythonw windows/tcp_client.pyw
```

## 页面说明

- 模块页：留空
- 搜索页：留空
- 保存页：留空
- 设置页：仅保留 `IP` 输入、`端口` 输入、`测试连通性` 按钮和状态显示

## 常用协议命令

- `help`
- `pid.get <包名>`
- `pid.attach <包名>`
- `pid.set <pid>`
- `pid.current`
- `memory.refresh`
- `memory.summary`
- `module.addr <模块名> <段索引> <start|end>`
- `mem.read <地址> <大小>`
- `mem.write <地址> <HEX字节流>`
- `mem.read_u32 <地址>` / `mem.write_u32 <地址> <值>`
- `mem.read_str <地址> [最大长度]`
- `touch.down <x> <y> <屏宽> <屏高>` / `touch.move ...` / `touch.up`

## 可选：adb 端口转发

```powershell
adb forward tcp:9494 tcp:9494
```

使用 `127.0.0.1` 即可在 Windows 端连到 Android 服务端。
