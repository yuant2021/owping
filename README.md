# owping

[![Build](https://github.com/yuant2021/owping/actions/workflows/build.yml/badge.svg)](https://github.com/yuant2021/owping/actions/workflows/build.yml)

用 Go 实现的 OWAMP（One-Way Active Measurement Protocol，[RFC 4656](https://www.rfc-editor.org/rfc/rfc4656)）单向 ping 工具。一个静态链接的单文件同时包含客户端（owping）和服务端（相当于 owampd），在 Linux 上直接运行，可与 [perfSONAR owamp](https://github.com/perfsonar/owamp) 的 owping / owampd 互通。

普通 ping 只能测往返时间；owping 分别测量去程和回程的单向时延、丢包、重复、乱序、抖动和跳数，适合定位不对称路径或只在一个方向上出现的拥塞。

## 特性

- 去程、回程各一个测试会话，输出格式与 perfSONAR owping 一致（包括 `-v`、`-R`、`-M`）
- 支持 open、authenticated、encrypted 三种模式（AES-128 + HMAC-SHA1），已与 perfSONAR owping / owampd 在三种模式下双向互通测试
- 泊松（指数分布）或固定间隔发包，发包时刻与计划的偏差在微秒级
- 接收端使用内核时间戳（`SO_TIMESTAMPNS`），并记录 TTL / Hop Limit 计算跳数
- 时钟误差和同步状态取自内核的 NTP 状态（`adjtimex`）
- 只依赖 Go 标准库，`CGO_ENABLED=0` 静态编译

## 安装

### 下载预编译文件

从 [Releases](https://github.com/yuant2021/owping/releases) 下载对应架构的文件，例如：

```sh
curl -fLo owping https://github.com/yuant2021/owping/releases/latest/download/owping-linux-amd64
chmod +x owping
sudo mv owping /usr/local/bin/
```

提供的架构：`amd64`、`386`、`arm64`、`armv7`、`armv6`、`riscv64`、`loong64`、`ppc64le`、`s390x`、`mips-softfloat`、`mipsle-softfloat`、`mips64`、`mips64le`。可以用同一页面的 `SHA256SUMS` 校验。

### go install

需要 Go 1.24 或更新版本：

```sh
go install github.com/yuant2021/owping@latest
```

### 从源码编译

```sh
git clone https://github.com/yuant2021/owping.git
cd owping
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" .
```

## 快速开始

在一端启动服务端。默认监听 TCP 861，绑定 1024 以下的端口需要 root 或 `CAP_NET_BIND_SERVICE`：

```sh
sudo owping -server
owping -server -listen :8861     # 或者使用非特权端口
```

在另一端运行客户端：

```sh
owping server.example.com
owping server.example.com:8861   # 非默认端口
owping '[2001:db8::1]:8861'      # IPv6 地址带端口时要加方括号
```

服务端也可以是任何 OWAMP 服务器，例如 perfSONAR 节点上的 owampd。

输出示例（本机回环，`owping -c 100 -i 0.01 -a 99 127.0.0.1:8865`）：

```
Approximately 4.0 seconds until results available

--- owping statistics from [127.0.0.1]:9279 to [127.0.0.1]:41586 ---
SID:	7f000001ee71c954b994d23033bb8567
first:	2026-10-08T15:48:37.748
last:	2026-10-08T15:48:38.715
100 sent, 0 lost (0.000%), 0 duplicates
one-way delay min/median/max = 0.00602/0.0246/0.0713 ms, (err=0.00201 ms)
one-way jitter = 0.0311 ms (P95-P50)
Percentiles:
	99.0: 0.0654 ms
hops = 0 (consistently)
no reordering


--- owping statistics from [127.0.0.1]:47448 to [127.0.0.1]:8963 ---
SID:	7f000001ee71c954b99e4126785d3f6f
first:	2026-10-08T15:48:37.730
last:	2026-10-08T15:48:38.510
100 sent, 0 lost (0.000%), 0 duplicates
one-way delay min/median/max = 0.00465/0.0242/0.138 ms, (err=0.00201 ms)
one-way jitter = 0.0406 ms (P95-P50)
Percentiles:
	99.0: 0.0995 ms
hops = 0 (consistently)
no reordering
```

第一段是去程（本机到服务端），第二段是回程（服务端到本机）。

| 字段 | 含义 |
|---|---|
| `sent` / `lost` / `duplicates` | 发出的包数（不含发送端来不及发而跳过的）、超时未到达的包数、重复到达的次数 |
| `one-way delay min/median/max` | 单向时延的最小值、中位数、最大值 |
| `err=` | 发送端与接收端时钟误差估计之和的最大值；任一端时钟未同步时显示 `(unsync)` |
| `one-way jitter` | 时延的 P95 减去 P50 |
| `hops` | 按收到的 TTL 推算的跳数（发送端固定把 TTL 设为 255） |
| `n-reordering` | RFC 4737 定义的 n 阶乱序比例 |

## 客户端选项

完整说明见 `owping -h`，常用选项：

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-c count` | 100 | 每个方向的包数 |
| `-i wait` | 0.1 | 平均发包间隔（秒）。也可以写成逗号分隔的发送计划：`e` 为指数分布（默认），`f` 为固定间隔，例如 `0.1e,0f` 表示泊松到达的背靠背包对 |
| `-s padding` | 0 | 每个包的填充字节数 |
| `-L timeout` | RTT + 2 | 包超过多少秒未到达算丢失 |
| `-z delay` | | 推迟多少秒开始测试 |
| `-t` / `-f` | 双向 | 只测去程 / 只测回程 |
| `-D dscp` | | DSCP 值：数字，或 `default`、`ef`、`cs0`–`cs7`、`af11`–`af43` |
| `-P range` | 8760-9960 | 测试包使用的本地 UDP 端口范围，`0` 表示任意端口 |
| `-S addr` | | 本地 IP 地址，控制连接和测试包都使用它 |
| `-4` / `-6` | | 只用 IPv4 / 只用 IPv6 |
| `-v` | | 打印每个包的记录 |
| `-a list` | | 额外输出的时延百分位，如 `50,90,99` |
| `-n unit` | `m` | 时延单位：`n`、`u`、`m`、`s` |
| `-M` / `-R` / `-Q` | | 机器可读汇总 / 原始包记录 / 不输出，只看退出码 |

测试进行中第一次按 Ctrl-C 会提前结束测试并输出已收集的结果，再按一次直接退出。

退出码：`0` 成功；`1` 连接或测试失败；`2` 参数错误或被中断。

## 认证和加密

口令文件与 owamp `pfstore` 的格式相同：每行一个身份和十六进制编码的口令，`#` 开头的行是注释。

```sh
printf 'alice %s\n' "$(printf '%s' 'my secret' | od -An -tx1 | tr -d ' \n')" >> owping.pfs
chmod 600 owping.pfs
```

服务端加载口令文件后默认同时提供三种模式，可以用 `-A` 限制，例如只允许加密：`-A E`。

```sh
owping -server -k owping.pfs
```

客户端用 `-u` 指定身份，在双方都支持的模式中按 encrypted、authenticated、open 的顺序选择；不带 `-k` 时在终端提示输入口令：

```sh
owping -u alice -k owping.pfs server.example.com
owping -u alice -A E server.example.com   # 只接受加密模式
```

authenticated 模式加密控制连接，测试包的序号加密并做 HMAC 认证、时间戳不加密；encrypted 模式在此基础上把测试包的时间戳也加密。

## 服务端

| 选项 | 默认值 | 说明 |
|---|---|---|
| `-listen addr` | `:861` | 控制连接的监听地址 |
| `-P range` | `0` | 测试包使用的 UDP 端口范围，`0` 表示任意端口；有防火墙时建议指定 |
| `-A modes` | 有 `-k` 时为 `AEO`，否则 `O` | 提供的模式 |
| `-k file` | | 口令文件，其中所有身份都可登录 |
| `-max-packets n` | 100000 | 单个会话的最大包数 |
| `-max-conns n` | 64 | 并发控制连接数 |

防火墙需要放行控制端口（默认 TCP 861）和 `-P` 范围内的 UDP 端口。

其他限制：

- 会话的开始时间与当前时间相差不超过 24 小时，整个发包计划加上丢包超时也不超过 24 小时
- 每个控制连接最多 16 个待启动的会话，整个服务端同时最多 256 个发送会话
- open 模式下只向控制连接的客户端地址发送测试包，避免被用来攻击第三方（RFC 4656 §6.2）
- 测试结果保存在内存中，只能在同一个控制连接里取回（owping 就是这样使用的）

用 systemd 运行（`/etc/systemd/system/owping.service`）：

```ini
[Unit]
Description=OWAMP server (owping)
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/owping -server -P 8760-9960
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now owping
journalctl -u owping -f
```

## 时钟同步

单向时延是接收时间戳减去发送时间戳，两端时钟必须同步（NTP、chrony 或 PTP），否则时延里会混入两端的时钟偏差，甚至出现负值。`err=` 来自两端内核报告的时钟误差估计；`(unsync)` 表示至少一端的内核认为时钟没有与外部时间源同步。丢包、重复和乱序不受时钟偏差影响。

## 与 perfSONAR owping 的差异

- 中位数、抖动和百分位按实际样本精确计算；原版按 0.1 ms 宽的直方图桶取值，所以原版常显示 `median 0.1 ms`
- 未实现 `-T` / `-F`（保存 .owp 文件）、`-v N`、`-B`、`-U`；`-S` 只接受 IP 地址
- 只支持 Linux

## 开发

```sh
go vet ./...
go test -race ./...
```

测试包括 RFC 4656 附录 B 的指数分布测试向量，以及三种模式下客户端和服务端在本机回环上的完整测试。

GitHub Actions 在每次 push 和 pull request 时检查格式、运行测试并交叉编译所有架构；推送 `v` 开头的标签时自动发布 Release：

```sh
git tag -a v0.1.0 -m "owping v0.1.0"
git push origin v0.1.0
```
