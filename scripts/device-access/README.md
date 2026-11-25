# 802.1X 设备证书与用户凭据组合准入

这套配置在 FreeRADIUS v4 现有 virtual server 上增加设备证书准入，不新建一套
独立认证服务。

## 协议边界

纯 EAP-TLS 只证明设备/证书身份，不承载用户密码。需要“设备证书 + 用户密码”
时，参考实现使用 EAP-TTLS/PAP（也可换成 PEAP/MSCHAPv2）：

1. 外层 TLS 必须出示设备证书，FreeRADIUS 校验信任链、有效期和 CRL。
2. `tls-session` 中的 `device_access_certificate` 按证书 CN/序列号查设备表。
3. 内层 PAP/MSCHAPv2 继续使用现有 `inner-tunnel`、`files`、LDAP 或 SQL。
4. `device_access_user_binding` 校验内层用户名必须是该设备的绑定使用人。
5. 会计 Start/Interim/Stop 维护活动会话；吊销后立即发送 RFC 5176
   Disconnect-Request。

直连 EAP-TLS 也会执行第 1、2 步，但它没有内层密码可校验；这种模式只能验证
“注册设备”和证书绑定身份，不能声称校验了密码。

## 新增/修改的配置

- `raddb/policy.d/device-access`：证书映射、序列号和用户绑定策略。
- `raddb/mods-available/device_access_devices`：CN -> 用户/序列号 CSV。
- `raddb/mods-config/csv/device_access_devices.csv`：设备表示例。
- `raddb/mods-available/device_crl` 与
  `raddb/sites-available/device-crl`：本地 CRL 读取和 `crl` 虚机。
- `raddb/mods-available/device_access_accounting`：会计事件写入会话表。
- `raddb/sites-available/tls-session`：调用设备证书策略。
- `raddb/sites-available/inner-tunnel`：有外层证书时校验用户绑定。
- `raddb/sites-available/default`：会计请求调用会话记录。
- `raddb/mods-available/eap`：启用 `tls-session`，并要求 TTLS 外层证书。

干净源码构建时，`raddb/all.mk` 会自动启用上述站点和模块。已有安装需要按发行版
方式创建 `mods-enabled`/`sites-enabled` 符号链接。

## 设备表

CSV 字段：

```csv
serial,cn,user,nas_ip
1234ABCD,device-001,alice,192.0.2.10
```

`serial` 使用 OpenSSL 输出的大写/小写十六进制均可，策略会转小写比较。生产环境
建议把 CSV 后端替换为 SQL/LDAP 映射，策略结构不需要变化。

## 一键验收

```sh
./acceptance.sh
```

验收脚本生成临时 CA 和三种证书：

- 证书正确、凭据正确：`allow`。
- 证书错误（同 CA 但未注册/绑定错误）、凭据正确：`device_unregistered`。
- 证书过期、凭据正确：`cert_expired`。

随后吊销正确证书、重建 CRL，并启动模拟 NAS 的 Disconnect-Request 接收端，验证
RFC 5176 报文、共享密钥签名和 Disconnect-ACK，耗时阈值为 2 秒。

如果已构建源码，脚本还会运行：

```sh
build/install/sbin/radiusd -C -d "$PWD/raddb"
```

## 吊销和及时断开

安装控制工具：

```sh
install -m 0755 scripts/device-access/device_access.py \
  /usr/local/sbin/device-accessctl
mkdir -p /var/lib/freeradius/device-access
```

会计钩子默认调用：

```text
/usr/local/sbin/device-accessctl --home \
  /var/lib/freeradius/device-access accounting
```

吊销并断开该证书对应用户的全部活动会话：

```sh
device-accessctl --home /var/lib/freeradius/device-access \
  revoke --serial 1234ABCD \
  --disconnect --secret "$RADIUS_COA_SECRET"
```

该命令先把序列号加入吊销表，再向会计记录中的 NAS 地址和 RFC 3576/5176 端口
（默认 UDP/3799）发送 Disconnect-Request。NAS 必须启用 CoA/DM、配置相同共享
密钥，并允许 FreeRADIUS 服务器作为动态授权客户端。

PKI 侧还必须发布 CRL。示例：

```sh
openssl ca -config pki/ca.cnf -revoke device-001.crt
openssl ca -config pki/ca.cnf -gencrl \
  -out raddb/certs/device-access/ca.crl
```

如果证书包含 CRL Distribution Point，FreeRADIUS 的 `device_crl` 会通过
`device-crl` 虚机读取该 CRL；也可以启用 `raddb/mods-available/ocsp` 做实时
OCSP。CRL 刷新后可调用 `%crl.refresh("<cdp-url>")` 通知 rlm_crl 重新加载。

## 兼容性说明

- 没有外层 TLS 证书的本地 `radtest`/PAP 请求不会进入设备绑定分支，保留旧虚拟
  服务器的用户名密码用法。
- 真实 802.1X 设备准入应保持 `ttls { require_client_cert = yes }`，否则客户端
  可以不提供设备证书。
- EAP-TLS、EAP-TTLS/PAP、PEAP/MSCHAPv2 共用同一个 `tls-session` 证书策略。
- 上游 FreeRADIUS EAP 测试使用独立的最小配置，不会强制加载本设备表。

## AI 辅助披露

本目录中的脚本和策略由 AI 辅助生成，尚未作为上游 PR 提交。任何上线或上游贡献
前都应由人类管理员审阅、按实际 NAS/CA 环境测试，并遵循仓库根 `AGENTS.md` 的
AI 贡献披露要求。
