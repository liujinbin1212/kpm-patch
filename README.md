# kpm-patch

KPM (KernelPatch Module) 模块仓库，由 GitHub Actions 云端自动编译。

- 目标设备：Xiaomi 15 Pro（haotian / sm8750）
- 目标内核：`6.6.118-android15-8`（GKI 2.0，android15-6.6）
- 加载方式：SukiSU Ultra 管理器 → 模块 → KPM 加载
- KP 源码：编译时自动拉取 [ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)

## 模块列表

### 1. kpm-hide.kpm — 内核级隐藏模块

仅对普通应用（uid >= 10000）生效，root/系统进程不受影响：

| 功能 | 说明 |
|---|---|
| 文件隐藏 | openat / faccessat / fstatat / statx / readlinkat 对隐藏路径返回 ENOENT |
| 目录隐藏 | getdents64 目录列表过滤隐藏条目 |
| 调试痕迹 | TracerPid 归零、"tracing stop" 状态伪装、wchan/stat 伪装 |
| mountinfo | /proc/[pid]/mountinfo 中 root 相关挂载行被过滤 |
| maps | /proc/[pid]/maps 中 zygisk/lsposed/frida 注入库被隐藏 |
| 动态配置 | CTL0 接口运行时增删隐藏规则 |

默认隐藏规则涵盖：magisk、kpatch、kpimg、/data/adb、ksu/ksud、shamiko、zygisk、supersu 等。

**控制接口**（SukiSU 终端 / adb shell 中使用 kpatch 命令）：

```
kpatch kpm unlock <superkey>
kpatch kpm ctl kpm-hide "status"          # 查看钩子安装情况
kpatch kpm ctl kpm-hide "list"            # 查看动态隐藏规则
kpatch kpm ctl kpm-hide "add <字符串>"     # 增加隐藏规则（路径/文件名子串）
kpatch kpm ctl kpm-hide "del <字符串>"     # 删除规则
kpatch kpm ctl kpm-hide "clear"           # 清空动态规则
```

### 2. hosts_file_redirect.kpm — hosts 重定向

把 netd 对 `/system/etc/hosts` 的读取重定向到 `/data/adb/hosts`（无需修改 /system）。
使用：创建 `/data/adb/hosts` 文件写入域名屏蔽/解析规则即可；CTL0 支持 `enable` / `disable`。

### 3. hello.kpm — 流水线验证模块

最小示例模块，仅用于验证加载/卸载/控制链路。

## 云端编译

1. 仓库 **Actions** → **Build KPM** → **Run workflow**（push 相关文件也会自动触发）
2. 运行完成后在 Artifacts 下载 `kpm-modules`，解压得到全部 `.kpm`
3. 传入手机，在 SukiSU Ultra 中以 KPM 方式加载

## 本地编译（可选）

```bash
git clone --depth=1 https://github.com/ShirkNeko/SukiSU_KernelPatch_patch KernelPatch
NDK_PATH=/path/to/ndk make
```

## 风险提示

- 内核模块加载在主线上，先在能恢复的环境测试；保留可用的 boot.img 备份
- 银行/游戏风控持续更新，隐藏模块需配合 SukiSU 内置 susfs、DenyList 使用
- 修改 `hello.c` / `kpm-hide.c` / `hosts_file_redirect.c` 后 push 即自动重新编译

## 许可证

GPL-2.0
