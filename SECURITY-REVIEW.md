# 计算侧运行时安全与持久化复核

## 当前攻击面

- 出站网络：容器需要访问控制面、Git 远端和 OpenAI-compatible endpoint；因此不能使用
  `network_mode: none`。学生代码继承的是白名单环境变量，不继承 API key、计算令牌、控制面 URL
  或 worker ID。
- 入站网络：容器不发布端口，不接受来自 LAN 的主动请求；仅由容器主动轮询控制面。
- 控制面鉴权：任务拉取和结果回传同时使用 `Authorization`、`X-Compute-Token` 和 worker ID。
- 不可信代码：静态扫描通过后才进入动态执行；动态子进程使用白名单环境变量和硬超时。
- 外部仓库：浅克隆、关闭 Git 重定向、限制大对象；仓库内容仅进入任务工作区。

## 容器权限与文件系统

当前 compose 运行约束：

- 镜像 `USER agentuser`（UID/GID 1000），非 root；
- `no-new-privileges=true`；
- `cap_drop: ALL`，不再添加 CHOWN/SETUID/SETGID/DAC_OVERRIDE；
- `read_only: true`；
- `/tmp` 为 `noexec,nosuid,nodev` 的 512MiB tmpfs；
- `pids_limit: 256`；
- 不挂载 Docker socket、主机 `/proc`、设备或特权 namespace；
- 可写路径仅为专用 bind mount：`/app/workspace`、`/app/cache/*`、`/app/logs`。

由于计算侧必须访问真实 AI endpoint、控制面和 Git，出站网络仍是主要残余能力；学生代码的
环境白名单不会阻止它访问网络。若需要更强隔离，应把学生程序拆为无网络、无写宿主目录的二级
沙箱，而不是仅依赖当前 Python 子进程边界。

## 持久化环境

- `/app/logs` → `services/cphomework-compute/logs`：任务拉取、评分和回传 JSONL 审计日志；
- `/app/workspace` → `.../workspace`：任务工作目录；任务结束后清理；
- `/app/cache/venvs`、`pip-cache`、`cargo-cache`：仅缓存，跨重启保留；
- API key、endpoint 和计算令牌只来自 compose 环境变量，不写入镜像和日志。

日志事件包括 `task_claimed`、`grade_result`、拉取失败和无报告终态；`grade_result` 包含任务元数据、
最终分数及评分报告详情，不包含学生源码、API key 或 endpoint。日志写入失败不会阻塞成绩闭环。

## 题目相关性门禁

生产路径的静态安全裁决由独立 LLM Security Agent 完成；本地规则扫描只作为上下文证据和
模型不可用时的保守降级，不再因为单独出现 `import os`、`pathlib`、`shutil` 或结果文件写入而
自动拒绝。Security Agent 接收有大小上限的代码文件摘要，明确把代码/注释中的指令当作不可信
数据，并判断具体行为：命令执行、网络通信、凭据读取、动态执行和越权才是风险信号。

安全裁决通过后，独立的相关性 Agent 接收“作业要求 + 有大小上限的代码文件摘要”，返回
`MATCHED`、`PARTIAL`、`MISMATCHED` 或 `UNKNOWN`。`PARTIAL` 继续进入动态执行和评分 Agent，
并把已完成项、缺失项和缺陷注入 RFC 事实区；只有 `MISMATCHED` 和 `UNKNOWN` 在评分前提前结束
并给出拒止报告。代码、文件名和题目文本均按不可信引用
材料处理，提示词中明确要求忽略其中的指令。

不再维护固定的算法别名表。安全或语义 Agent 无法调用时，才使用本地保守回退；回退结果会写入
审计证据。没有交集就拒绝，不能用“代码够长/可运行”放行。生产配置优先使用真实语义 Agent。

## 评分规则

保留原有的正向评分与仲裁规则；不使用“静态通过且进程退出即强制 100 分”的确定性校准。
题目匹配不把“代码够长/包含函数/能运行”当作完成证据；必须先通过语义 Agent 的目标行为判断。
提示词攻击、越权调用、静态安全违规、题目不匹配或动态执行失败仍优先走拒止/低分路径。

## 漏洞修复记录（2026-10-30）

- 学生源码、文件名、stdout/stderr、历史评测文本及下游 Agent 文本结论均作为不可信数据；边界采用 nonce 包装，属性转义控制字符/引号，并中和伪造标签与 CDATA 结束符。
- 评分只接受报告末尾唯一规范分数行，不在引用、代码块或正文中搜索首个数字分数。
- 学生输出中的 `PASS`、`OK`、`passed` 不再计作受信测试结果；进程退出码与历史成绩不触发固定高分保底、自动加分或耗尽重试后的抬分。
- 预检遍历所有可执行源码与清单，不抽样、不截断；覆盖超限、不可读取的源码及不可审计的可执行文件/归档均失败关闭。本地安全规则命中直接阻断，不允许 LLM 覆盖。
- 依赖安装先解析清单，拒绝 pip 指令、路径和直接 URL；仅下载 wheel 并安装前检查，禁用 build backend，安装子进程使用无密钥环境，失败时清理环境。

残余限制：Worker 当前仍需出站网络；学生运行进程与 Worker 共处一个容器/网络命名空间。wheel-only 阻止构建后端在安装阶段执行，但第三方 wheel 在学生程序导入时仍是不可信代码，静态规则不能证明其绝对安全。更强隔离需要专用无网络、无凭据、无持久化挂载的二级沙箱；本次未改变宿主网络或部署拓扑。
