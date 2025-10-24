## Nodogsplash 项目

### 为了在Padavan里能正常运行，主要修改如下：（从后往前介绍，图中代码里的 `//` 符号表示注释不会生效）

#   
**1. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L878) 的第878行后添加以下代码**

```
	// 取消认证的设备时 删除ipv6放行命令，设备不可以访问ipv6互联网
	execute("ip6tables -D FORWARD -m mac --mac-source %s -j ACCEPT > /dev/null 2>&1", client->mac);
	// 取消认证的设备时 删除http的80端口nat规则 
	iptables_do_command("-t nat -D " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN", client->mac);
```
 
- 修改后 如图：    
    <img width="1012" height="197" alt="image" src="https://github.com/user-attachments/assets/db425b4f-2639-432a-ac61-9dd44f783be9" />

#    
**2. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L840) 的第840行后添加以下代码**

```
	// 通过认证的设备 添加http的80端口nat规则，避免认证后打开http网页一直刷新，打不开
	iptables_do_command("-t nat -I " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN", client->mac);
	// 通过认证的设备 添加ipv6放行命令，设备可以访问ipv6互联网
	execute("ip6tables -I FORWARD -m mac --mac-source %s -j ACCEPT", client->mac);
```

- 修改后 如图：   
    <img width="1123" height="284" alt="image" src="https://github.com/user-attachments/assets/92497f14-528f-4879-83b1-134a62244afb" />

**3. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L702) 的第702行后添加以下代码**

```
	// 删除禁止网关接口的ipv6转发命令
	execute("ip6tables -D FORWARD -i %s -j  DROP > /dev/null 2>&1", config->gw_interface);
```

- 修改后 如图：   
    <img width="643" height="248" alt="image" src="https://github.com/user-attachments/assets/422bfc83-8b93-4c74-be8a-7fc615c4f866" />

#    
**4. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L505) 的第505行后添加以下代码**

```
		// 禁止所有网关接口的ipv6数据转发，防止设备通过ipv6访问互联网服务
		execute("ip6tables -I FORWARD -i %s -j DROP", gw_interface);
```

- 修改后 如图： 
<img width="790" height="262" alt="image" src="https://github.com/user-attachments/assets/7e91db89-56b2-4419-986a-c6bd6bc81bf4" />

#    
**5. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L338) 的第338行后添加以下代码**

```
	// 取消信任时  删除http的80端口nat规则
	iptables_do_command("-t nat -D " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN > /dev/null 2>&1", mac);
	// 取消信任时  删除放行ipv6命令，设备不可访问ipv6互联网
	execute("ip6tables -D FORWARD -m mac --mac-source %s -j ACCEPT > /dev/null 2>&1", mac);
```

- 修改后 如图：
<img width="979" height="228" alt="image" src="https://github.com/user-attachments/assets/dcace1f4-a908-4f51-9c73-2a8e4f45ec73" />

#    
**6. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L332) 的第332行后添加以下代码**

```
	// 信任设备时 添加http的80端口的nat规则，防止网页一直刷新
	iptables_do_command("-t nat -I " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN", mac);
	// 信任设备时 添加放行命令，设备可以访问ipv6互联网
	execute("ip6tables -I FORWARD -m mac --mac-source %s -j ACCEPT", mac);
```

- 修改后 如图：
<img width="937" height="228" alt="image" src="https://github.com/user-attachments/assets/1a47652c-1f7f-4fa0-9d49-65f38342d132" />

#    
**7. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L326) 的第326行后添加以下代码**

```
	// 取消允许设备时 删除http的80端口nat规则
	iptables_do_command("-t nat -D " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN > /dev/null 2>&1", mac);
	// 取消允许时 删除放行命令，设备不可访问ipv6互联网
	execute("ip6tables -D FORWARD -m mac --mac-source %s -j ACCEPT > /dev/null 2>&1", mac);
```

- 修改后 如图：
<img width="976" height="228" alt="image" src="https://github.com/user-attachments/assets/d082189f-f13e-4db2-acc2-d6a6fa7ae245" />

#    
**8. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L320) 的第320行后添加以下代码**

```
	// 允许设备时 添加http的80端口的nat规则，防止网页一直刷新
	iptables_do_command("-t nat -I " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN", mac);
	// 设置允许时 添加放行命令，设备可以访问ipv6互联网
	execute("ip6tables -I FORWARD -m mac --mac-source %s -j ACCEPT", mac);
```

- 修改后 如图：
<img width="799" height="237" alt="image" src="https://github.com/user-attachments/assets/dee0ea4b-369f-48af-bf81-45e93de2f4e1" />

#    
**9. 在 [src/fw_iptables.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/fw_iptables.c#L308) 的第308行后添加以下代码**

```
	// 拉黑设备时 删除http的80端口nat规则
	iptables_do_command("-t nat -D " CHAIN_OUTGOING " -m mac --mac-source %s -p tcp --dport 80 -j RETURN > /dev/null 2>&1", mac);
	// 拉黑设备时删掉放行的命令
	execute("ip6tables -D FORWARD -m mac --mac-source %s -j ACCEPT > /dev/null 2>&1", mac);
```

- 修改后 如图：
<img width="942" height="232" alt="image" src="https://github.com/user-attachments/assets/cc73fc59-8d22-41a9-9eda-b1ca5f19b18b" />

#     
**10. 如果你想在线github云编译出程序，可以复制 [cd.yml](./github/workflows/cd.yml) 全部内容，覆盖修改到你fork的仓库的这个文件里，然后点击顶部的`Actions`开始在线编译**    
1.    
<img width="1891" height="122" alt="image" src="https://github.com/user-attachments/assets/8bf1cf37-a757-4907-b877-f4e117e394fb" />    
2.    
<img width="367" height="487" alt="image" src="https://github.com/user-attachments/assets/7c7a09bc-eea9-4de0-a4a9-5120958a505b" />

#      
**11. 如果你使用的是[Hiboy](https://opt.cn2qq.com/padavan/)的Padavan固件，需要额外修改 去掉端口复用，或出现无法启动 报错如下**    
1.     
<img width="1223" height="156" alt="image" src="https://github.com/user-attachments/assets/bf5e6eb2-adaa-4f60-9eed-fcc5fe4957b0" />
2.     
<img width="1160" height="108" alt="image" src="https://github.com/user-attachments/assets/a46ff5d5-922c-489f-8677-8ecb70e95544" />

**这个需要修改 [src/main.c](https://github.com/nodogsplash/nodogsplash/blob/9b2bc7be4a9111d0b27ec2783ca4b9e38d32c549/src/main.c#L293) 的第293行添加双斜线`//`注释掉****  
<img width="655" height="251" alt="image" src="https://github.com/user-attachments/assets/b2befcae-3923-4100-969f-ae2d7f358e89" />
   
**低版本`iptables`还需要替换为高版本的，[点此下载](./resources/xtables-multi)1.8.7版本的**   
**附带教程[【nodogsplash】分享一个Padavan可用的web认证程序，采用静态编译的](https://www.right.com.cn/forum/forum.php?mod=viewthread&tid=8452192&fromuid=479735)**    

-----

### 以下为原仓库说明：


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
