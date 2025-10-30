## Nodogsplash 项目

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/lmq8267/nodogsplash)

### UI：

<img width="363" height="474" alt="image" src="https://github.com/user-attachments/assets/37e4b0c8-734a-4653-8019-7cd370491ebb" />

<img width="364" height="447" alt="image" src="https://github.com/user-attachments/assets/af1f55a2-14ca-4ac4-b22d-8ae8e7aeefd5" />

<img width="1084" height="301" alt="image" src="https://github.com/user-attachments/assets/5b381332-f88c-4412-b7d6-a158da745bd9" />

Nodogsplash 是一个强制门户（Captive Portal），它提供了一种简单的方法，通过在用户获得互联网访问权限之前显示欢迎页（splash page），以实现受限访问互联网的功能。

它最初是从 Wifi Guard Dog 项目的代码库派生而来的。

Nodogsplash 依据 GNU 通用公共许可证（GPL）发布。

* 原始主页: [http://kokoro.ucsd.edu/nodogsplash](https://web.archive.org/web/20120108100828/http://kokoro.ucsd.edu/nodogsplash)
* Wifidog: https://github.com/wifidog
* GNU GPL: http://www.gnu.org/copyleft/gpl.html

以下内容描述了 Nodogsplash 的功能、获取与运行方式，
以及如何为你的应用自定义其行为。

## 概述

**Nodogsplash**（NDS）是一个高性能、小体积的强制门户，提供了一个简单的带欢迎页（splash page）的受限互联网连接。

NoDogSplash 针对资源有限的目标设备进行了优化。

**如果你需要一个更复杂的认证系统**，提供动态 Web 界面，那么你需要使用 [openNDS](https://github.com/openNDS/openNDS)，而不是 NoDogSplash。

**所有现代移动设备**、大多数桌面操作系统以及大多数浏览器现在都具有“强制门户检测”（CPD）机制，该机制会在连接到网络时自动发出一个端口 80 的请求。Nodogsplash 会检测到这一点，并提供其“欢迎页”网页。

最基本形式的欢迎页包含一个 *继续（Continue）* 按钮。当用户点击该按钮后，将获得互联网访问权限，时间受预设间隔限制。

Nodogsplash 目前不支持流量控制，但与其他独立系统（如智能队列管理 SQM）完全兼容。

## Nodogsplash 的分支

Nodogsplash 已拆分为两个项目：

* [OpenNDS](https://github.com/openNDS/openNDS)：包含 FAS（前向认证服务，Forward Authentication Service）
* [Nodogsplash](https://github.com/nodogsplash/nodogsplash)：包含一个精简版本。

OpenNDS 从 4.x 版本（提交号 4bd2f00166ed17ac14f9b78037fce5725bd894ce）分叉而来。
Nodogsplash 从 3.x 版本（提交号 28541e787c989589bcd0939d3affd4029a235a3a）分叉而来。

第一个代码库不同的版本是 5.0。

## 文档

完整文档请参阅 https://nodogsplash.readthedocs.io/en/latest/

你可以选择 *Stable*（稳定版）或 *Latest*（最新）文档。
