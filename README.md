# kpm-patch

KPM (KernelPatch Module) 基座模块，由 GitHub Actions 云端自动编译。

- 目标设备：Xiaomi 15 Pro（haotian / sm8750）
- 目标内核：`6.6.118-android15-8`（GKI 2.0，android15-6.6）
- 加载方式：SukiSU Ultra 管理器 → 模块 → KPM 加载
- KP 源码：编译时自动拉取 [ShirkNeko/SukiSU_KernelPatch_patch](https://github.com/ShirkNeko/SukiSU_KernelPatch_patch)

## 使用

1. 打开仓库 **Actions** → 选择 **Build KPM** → **Run workflow**（push 到 main 也会自动触发）
2. 运行完成后在 Artifacts 下载 `kpm-base`，解压得到 `hello.kpm`
3. 传入手机，在 SukiSU Ultra 中以 KPM 方式加载

## 本地编译（可选）

```bash
# 依赖 Android NDK（设置 NDK_PATH 环境变量）
git clone --depth=1 https://github.com/ShirkNeko/SukiSU_KernelPatch_patch KernelPatch
NDK_PATH=/path/to/ndk make
```

## 开发

修改 `hello.c` 实现 KPM_INIT / KPM_CTL0 / KPM_CTL1 / KPM_EXIT 回调即可。
API 文档见 KernelPatch 仓库 `doc/` 目录及 `kernel/kpm/include/` 下的头文件。

## 许可证

GPL-2.0
