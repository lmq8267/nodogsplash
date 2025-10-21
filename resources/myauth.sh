#!/bin/sh  
# ============================================================================  
# NoDogSplash BinAuth 外部认证脚本示例  
# 该脚本处理客户端认证请求和各种认证状态变化事件通知  
# ============================================================================  
  
# ----------------------------------------------------------------------------  
# 参数说明：  
# 第一个参数 ($1) 是方法名，决定了脚本的行为模式  
# ----------------------------------------------------------------------------  
METHOD="$1"  
MAC="$2"  
  
# ============================================================================  
# 方法类型 1: auth_client - 客户端认证请求  
# ============================================================================  
# 当用户提交认证表单时被调用  
# 调用格式：$BinAuth auth_client <client_mac> '<username>' '<password>'  
#   
# 参数详解：  
#   $1 (METHOD)  : "auth_client" - 方法标识符  
#   $2 (MAC)     : 客户端MAC地址，格式如 "12:34:56:78:90:AB"  
#   $3 (USERNAME): 用户名，URL编码格式，可能为空字符串 ""  
#   $4 (PASSWORD): 密码，URL编码格式，可能为空字符串 ""  
#  
# 期望输出格式：  
#   <seconds> <upload_limit> <download_limit>  
#   - seconds: 认证时长（秒），0或负数表示拒绝认证  
#   - upload_limit: 上传限制（字节），0表示无限制（可选参数）  
#   - download_limit: 下载限制（字节），0表示无限制（可选参数）  
#  
# 退出码：  
#   0: 认证成功  
#   非0: 认证失败  
# ============================================================================  
  
case "$METHOD" in  
  auth_client)  
    # 获取用户提交的用户名和密码（已经过URL编码）  
    USERNAME="$3"  
    PASSWORD="$4"  
      
    # --------------------------------------------------------------------  
    # 示例1：简单的用户名密码验证  
    # --------------------------------------------------------------------  
    if [ "$USERNAME" = "admin" -a "$PASSWORD" = "password123" ]; then  
      # 认证成功：允许客户端访问互联网  
      # 参数1: 3600秒（1小时）的会话时长  
      # 参数2: 0 = 无上传限制  
      # 参数3: 0 = 无下载限制  
      echo 3600 0 0  
      exit 0  
    fi  
      
    # --------------------------------------------------------------------  
    # 示例2：不同用户不同权限  
    # --------------------------------------------------------------------  
    if [ "$USERNAME" = "guest" ]; then  
      # 访客用户：30分钟会话，限速  
      # 参数1: 1800秒（30分钟）  
      # 参数2: 1048576 字节（1MB/s 上传限制）  
      # 参数3: 2097152 字节（2MB/s 下载限制）  
      echo 1800 1048576 2097152  
      exit 0  
    fi  
      
    # --------------------------------------------------------------------  
    # 示例3：基于MAC地址的白名单认证  
    # --------------------------------------------------------------------  
    if [ "$MAC" = "AA:BB:CC:DD:EE:FF" ]; then  
      # 特定MAC地址：无限制访问  
      # 参数1: 0 = 无时间限制（需要手动注销）  
      # 参数2: 0 = 无上传限制  
      # 参数3: 0 = 无下载限制  
      echo 0 0 0  
      exit 0  
    fi  
      
    # --------------------------------------------------------------------  
    # 示例4：调用外部API进行认证  
    # --------------------------------------------------------------------  
    # 可以使用 curl、wget 等工具调用外部认证服务器  
    # RESPONSE=$(curl -s "https://auth.example.com/validate?user=$USERNAME&pass=$PASSWORD&mac=$MAC")  
    # if [ "$RESPONSE" = "OK" ]; then  
    #   echo 7200 0 0  
    #   exit 0  
    # fi  
      
    # --------------------------------------------------------------------  
    # 示例5：记录认证尝试日志  
    # --------------------------------------------------------------------  
    # 将认证尝试记录到日志文件  
    logger -t nodogsplash "Auth attempt: MAC=$MAC, User=$USERNAME"  
    echo "$(date '+%Y-%m-%d %H:%M:%S') - MAC: $MAC, User: $USERNAME" >> /var/log/nds_auth.log  
      
    # 认证失败：拒绝访问  
    exit 1  
    ;;  
  
  # ==========================================================================  
  # 方法类型 2: 事件通知 - 认证状态变化通知  
  # ==========================================================================  
  # 当客户端认证状态发生变化时被调用  
  # 调用格式：$BinAuth <event_type> <client_mac> <incoming_bytes> <outgoing_bytes> <session_start> <session_end>  
  #  
  # 参数详解：  
  #   $1 (METHOD)         : 事件类型（见下文详细说明）  
  #   $2 (MAC)            : 客户端MAC地址  
  #   $3 (INCOMING_BYTES) : 客户端下载的总字节数  
  #   $4 (OUTGOING_BYTES) : 客户端上传的总字节数  
  #   $5 (SESSION_START)  : 会话开始时间（Unix时间戳，自1970年1月1日以来的秒数），0表示未知  
  #   $6 (SESSION_END)    : 会话结束时间（Unix时间戳），0表示无限制或未知  
  #  
  # 事件类型说明：  
  #   - client_auth       : 客户端通过此脚本成功认证后立即触发  
  #   - client_deauth     : 客户端通过splash页面主动注销  
  #   - idle_deauth       : 客户端因不活动超时被自动注销  
  #   - timeout_deauth    : 客户端会话时间到期被自动注销  
  #   - ndsctl_auth       : 客户端通过ndsctl工具手动认证  
  #   - ndsctl_deauth     : 客户端通过ndsctl工具手动注销  
  #   - shutdown_deauth   : NoDogSplash服务终止时注销所有客户端  
  #  
  # 注意：这些事件通知调用不需要返回值，退出码也会被忽略  
  # ==========================================================================  
  
  client_auth)  
    # --------------------------------------------------------------------  
    # 事件：客户端认证成功  
    # 触发时机：在 auth_client 返回成功后立即调用  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  # 下载字节数（此时通常为0或很小）  
    OUTGOING_BYTES="$4"  # 上传字节数（此时通常为0或很小）  
    SESSION_START="$5"   # 会话开始时间戳  
    SESSION_END="$6"     # 会话结束时间戳  
      
    # 记录认证成功事件  
    logger -t nodogsplash "Client authenticated: MAC=$MAC, SessionStart=$SESSION_START, SessionEnd=$SESSION_END"  
      
    # 发送通知到外部系统  
    # curl -s -X POST "https://api.example.com/auth/notify" \  
    #   -d "event=auth&mac=$MAC&start=$SESSION_START&end=$SESSION_END" &  
      
    # 更新数据库记录  
    # mysql -e "INSERT INTO sessions (mac, start_time, end_time) VALUES ('$MAC', $SESSION_START, $SESSION_END)"  
    ;;  
  
  client_deauth)  
    # --------------------------------------------------------------------  
    # 事件：客户端主动注销  
    # 触发时机：用户点击splash页面的"断开连接"按钮  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  
    OUTGOING_BYTES="$4"  
    SESSION_START="$5"  
    SESSION_END="$6"  
      
    # 计算会话持续时间和流量统计  
    DURATION=$((SESSION_END - SESSION_START))  
    TOTAL_MB=$(((INCOMING_BYTES + OUTGOING_BYTES) / 1048576))  
      
    logger -t nodogsplash "Client deauth: MAC=$MAC, Duration=${DURATION}s, Traffic=${TOTAL_MB}MB"  
      
    # 记录用户主动注销信息  
    echo "$(date '+%Y-%m-%d %H:%M:%S') - Deauth: MAC=$MAC, In=$INCOMING_BYTES, Out=$OUTGOING_BYTES" >> /var/log/nds_sessions.log  
    ;;  
  
  idle_deauth)  
    # --------------------------------------------------------------------  
    # 事件：空闲超时自动注销  
    # 触发时机：客户端在 AuthIdleTimeout 时间内无网络活动  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  
    OUTGOING_BYTES="$4"  
    SESSION_START="$5"  
    SESSION_END="$6"  
      
    logger -t nodogsplash "Idle timeout: MAC=$MAC, Downloaded=${INCOMING_BYTES}B, Uploaded=${OUTGOING_BYTES}B"  
      
    # 可以发送空闲超时警告  
    # send_notification "User $MAC disconnected due to inactivity"  
    ;;  
  
  timeout_deauth)  
    # --------------------------------------------------------------------  
    # 事件：会话时间到期自动注销  
    # 触发时机：达到 auth_client 返回的 seconds 时长限制  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  
    OUTGOING_BYTES="$4"  
    SESSION_START="$5"  
    SESSION_END="$6"  
      
    logger -t nodogsplash "Session timeout: MAC=$MAC, TotalDownload=${INCOMING_BYTES}B, TotalUpload=${OUTGOING_BYTES}B"  
      
    # 生成使用报告  
    # generate_usage_report "$MAC" "$INCOMING_BYTES" "$OUTGOING_BYTES" "$SESSION_START" "$SESSION_END"  
    ;;  
  
  ndsctl_auth)  
    # --------------------------------------------------------------------  
    # 事件：通过ndsctl命令行工具手动认证  
    # 触发时机：管理员执行 ndsctl auth <MAC> 命令  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  
    OUTGOING_BYTES="$4"  
    SESSION_START="$5"  
    SESSION_END="$6"  
      
    logger -t nodogsplash "Manual auth via ndsctl: MAC=$MAC"  
      
    # 记录管理员操作  
    # audit_log "Admin authorized MAC: $MAC at $(date)"  
    ;;  
  
  ndsctl_deauth)  
    # --------------------------------------------------------------------  
    # 事件：通过ndsctl命令行工具手动注销  
    # 触发时机：管理员执行 ndsctl deauth <MAC> 命令  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  
    OUTGOING_BYTES="$4"  
    SESSION_START="$5"  
    SESSION_END="$6"  
      
    logger -t nodogsplash "Manual deauth via ndsctl: MAC=$MAC"  
      
    # 记录管理员操作  
    # audit_log "Admin deauthorized MAC: $MAC at $(date)"  
    ;;  
  
  shutdown_deauth)  
    # --------------------------------------------------------------------  
    # 事件：NoDogSplash服务关闭时注销所有客户端  
    # 触发时机：NoDogSplash进程终止时（重启、停止等）  
    # --------------------------------------------------------------------  
    INCOMING_BYTES="$3"  
    OUTGOING_BYTES="$4"  
    SESSION_START="$5"  
    SESSION_END="$6"  
      
    logger -t nodogsplash "Shutdown deauth: MAC=$MAC"  
      
    # 保存会话数据以便服务重启后恢复  
    # save_session_state "$MAC" "$INCOMING_BYTES" "$OUTGOING_BYTES"  
    ;;  
  
  *)  
    # --------------------------------------------------------------------  
    # 未知方法类型  
    # --------------------------------------------------------------------  
    logger -t nodogsplash "Unknown BinAuth method: $METHOD"  
    exit 1  
    ;;  
esac  
  
# 事件通知处理完成，正常退出  
exit 0
