# RFC Audit Agent (LangGraph 计算物理/通用作业审计 Agent)

基于 **LangGraph** 构建的高权限严谨、安全隔离的 **RFC 审计 Agent (RFC Audit Agent)**。系统专为通用作业批改及计算物理实验设计，与控制层系统（Cloudflare Serverless `cphomework`）实现物理与架构层面的完全解耦。

---

## 架构概览与核心设计理念

```
[ 控制层 cphomework (Cloudflare Workers + KV) ]
               │                ▲
   GET /task   │ (心跳长轮询)    │ POST /report (带重试幂等回传)
 (空队列等 15s) │                │ (任务完结冷却 10s)
               ▼                │
 ┌───────────────────────────────────────────────────────────┐
 │             衔尾蛇 (Ouroboros) 持续生命周期守护进程          │
 │                      Zero-Zombie SLA                      │
 └─────────────────────────────┬─────────────────────────────┘
                               │
 ┌─────────────────────────────▼─────────────────────────────┐
 │                LangGraph RFC 审计状态图                    │
 ├───────────────────────────────────────────────────────────┤
 │ 阶段 0: 远端预检与资产过滤 (Remote Preflight)              │
 │   - Metadata 与文件树安全核验 (总文件数 <= 500, 代码 <= 2MB)│
 │   - 自动过滤大型数据集 (.h5, .bin, .pt) 与图片媒体文件     │
 ├───────────────────────────────────────────────────────────┤
 │ 阶段 1: 静态安全审计与边界隔离 (Static Security Audit)     │
 │   - 高熵随机 Nonce 边界隔离与 Prompt Injection 中和转义   │
 │   - 语法树 AST 与危险特征扫描 (命令执行/系统调用拦截)     │
 │   - 题目契约宽松匹配 (仅核验“写的是该题”即放行)            │
 ├───────────────────────────────────────────────────────────┤
 │ 阶段 2: 沙箱动态执行与旁路监控 (Sandbox & Sidecar)        │
 │   - requirements.txt SHA256 哈希持久化虚拟环境复用        │
 │   - 支持 Python, C/C++, Rust 多语言工具链                │
 │   - 动态执行由 Agent 意图调起 (LangGraph Tool 行为)       │
 │   - Sidecar 旁路进程高频采样物理资源 (CPU/RSS/CUDA 显存)  │
 ├───────────────────────────────────────────────────────────┤
 │ 阶段 3: RFC 多轮裁决与慷慨评分 (RFC 2119 Arbitration)     │
 │   - RFC 2119 规范结构化备忘录 (MUST, SHOULD, MAY)         │
 │   - 基于 historyPrompt 深度对比历史版本，正向奖励迭代改进   │
 │   - 慷慨评分机制 (基准 85~95，多轮递增)                    │
 └───────────────────────────────────────────────────────────┘
```

---

## 审计方法论与核心保障

### 1. 阶段 0：远端预检与文件过滤 (Preflight)
- **安全阈值拦截**：克隆前核验远端仓库元数据与文件树。限制总文件数 $\le 500$、代码文件总上限 $\le 2\text{MB}$。
- **资产暂缓机制**：自动过滤超大数据集（`.h5`, `.parquet`, `.bin`, `.pt` 等）与大体积多媒体（`.png`, `.jpg`, `.zip` 等），保护计算节点 IO 与磁盘配额。
- **路径穿越防御**：严格排查文件名中可能包含的 `../` 或危险符号。

### 2. 阶段 1：静态审计与边界隔离 (Static Audit)
- **高熵 Nonce 边界符隔离**：
  学生代码在投喂给大语言模型前，外层均被动态生成的 `<UNTRUSTED_STUDENT_CODE nonce="...">` 标签包裹，并在系统提示词中声明内容不可信，严防 Prompt Injection。
- **多语言语法级扫描**：
  使用 Python `ast` 解析树扫描危险节点（`os.system`, `subprocess`, `eval`, `exec` 等），同时支持 C/C++/Rust 危险系统调用正则分析。
- **题目契约宽松放行**：
  仅核验学生提交的代码是否与题目主题或科学实验背景相关，或代码具备实质解题逻辑结构，只要确认“写的是该题”即放行进入动态评测，不设严苛签名卡口。

### 3. 阶段 2：环境装配与沙箱动态运行 (Sandbox & Sidecar)
- **SHA256 虚拟环境持久化复用**：
  根据仓库中的 `requirements.txt` 计算哈希值，缓存在 `/cache/venvs/{hash}`。首次拉取安装后持久化沉淀，后续复用无需重复下载依赖。
- **Agent 工具调起机制**：
  沙箱动态执行是 Agent 在思考过程中按需调起的 Tool（`execute_sandbox_code`），由 Agent 自主控制测试入参和执行脚本。
- **Sidecar 旁路监视进程**：
  在动态运行生命周期内，独立后台线程高频采样目标进程树的物理资源：
  - CPU 峰值利用率与运行耗时
  - 物理内存 RSS 峰值
  - CUDA GPU 显存占用与显存利用率（支持无 GPU 环境自适应降级）
  采集到的硬件指标直接反哺给评分 Agent。

### 4. 阶段 3：RFC 2119 多轮裁决与慷慨评分 (RFC Arbitration)
- **RFC 2119 标准备忘录**：
  输出遵循 RFC 2119 规范标准的结构化备忘录：
  - `[MUST]` 核心正确性与数学/物理逻辑验证
  - `[SHOULD]` 性能优化与资源效率建议
  - `[MAY]` 架构拓展与扩展实验建议
- **迭代递增加分**：
  拉取任务时自动合并前端传来的 `historyPrompt`。Agent 对比前序版本修改后，针对每次迭代给予正向激励，推动分数稳步提升。
- **慷慨打分**：
  对于实质完成算法逻辑且未触发安全红线的作业，给予 85~95 分的基准分。

### 5. 阶段 4：衔尾蛇持续生命周期与 Zero-Zombie SLA
- **解耦轮询调度**：
  - 当队列为空时，静默休眠 **15 秒 (15s)** 再发起下一次拉取；
  - 当完成一个任务并成功回传成绩后，冷却 **10 秒 (10s)** 再拉取下一个任务。
- **终态闭环保障 (Zero-Zombie SLA)**：
  计算层确保“凡被消费的任务，必定有终态回传”：
  - 触发安全风控熔断时：自动生成 0 分风控报告回传控制层；
  - 图节点偶发网络或模型异常时：携带当前上下文重试最多 3 次；
  - 发生不可恢复的致命异常时：兜底生成故障诊断报告并回传，杜绝任务死锁在 `in_progress`。

---

## 目录结构

```
CP/
├── client/                     # 控制层通信客户端 (HTTP 轮询与回传)
│   └── control_plane.py
├── core/                       # 核心数据模型、异常与监控
│   ├── exceptions.py
│   ├── fallback.py             # 兜底与 0 分风控报告生成器
│   ├── models.py               # Pydantic 核心数据模型
│   └── sidecar_monitor.py      # 旁路进程硬件采样监视器
├── env_manager/                # 环境管理与多语言工具链
│   ├── polyglot_toolchain.py   # C/C++, Rust 工具链
│   └── python_venv.py          # 基于 SHA256 的持久化虚拟环境
├── graph/                      # LangGraph 核心状态图
│   ├── nodes.py                # 节点定义 (Preflight, Audit, Exec, RFC)
│   ├── prompts.py              # RFC 2119 提示词模版
│   ├── state.py                # 状态图状态定义
│   ├── tools.py                # Agent 沙箱动态执行工具
│   └── workflow.py             # 图构建与路由边
├── sandbox/                    # 沙箱安全运行器
│   └── runner.py
├── security/                   # 安全预检与防注入隔离
│   ├── boundary.py             # 高熵 Nonce 边界隔离器
│   ├── cloner.py               # 受限浅克隆器
│   ├── polyglot_scanner.py     # 多语言 AST/特征扫描器
│   ├── preflight.py            # 远端文件树预检与大文件过滤
│   └── topic_matcher.py        # 宽松题目契约核验器
├── tests/                      # 单元与端到端集成测试集
│   ├── run_all_tests.py
│   ├── test_boundary.py
│   ├── test_e2e_graph.py
│   ├── test_polyglot_scanner.py
│   ├── test_preflight.py
│   ├── test_python_venv.py
│   ├── test_sidecar.py
│   └── test_topic_matcher.py
├── .env.example
├── config.py                   # 全局配置
├── Dockerfile                  # 生产级 Docker 构建文件
├── docker-compose.yml          # Docker Compose 编排文件
├── main.py                     # 衔尾蛇主入口进程
├── pyproject.toml
└── requirements.txt
```

---

## 快速上手与本地运行

### 1. 配置环境变量
复制 `.env.example` 为 `.env` 并填写相关密钥：
```bash
cp .env.example .env
openssl rand -hex 32
```
将生成的随机值填入 `COMPUTE_AUTH_TOKEN`，并确保与控制层配置一致；不要提交 `.env`。
配置示例：
```ini
# 控制层接口与鉴权密钥（请使用控制层配置的令牌；不要提交真实令牌）
CONTROL_PLANE_URL=https://cphomework.your-subdomain.workers.dev
COMPUTE_AUTH_TOKEN=在本机生成并与控制层保持一致的高熵令牌

# LLM 配置 (支持 OpenAI / DeepSeek / Gemini 等兼容 API)
OPENAI_API_KEY=your-api-key-here
OPENAI_API_BASE=https://api.openai.com/v1
OPENAI_MODEL=gpt-4o
```

### 2. 本地测试套件全量验证
系统自带覆盖边界隔离、AST扫描、虚拟环境缓存、Sidecar采样、RFC状态图及多轮迭代递增的完整测试集：
```bash
python tests/run_all_tests.py
```
> 测试套件达成 **16 / 16 PASS** 全绿通过。

### 3. 本地启动守护进程
```bash
python main.py
```

---

## Docker 容器化部署

### 1. 构建并启动容器
```bash
docker compose up -d --build
```

### 2. 检查运行日志
```bash
docker compose logs -f rfc-audit-agent

### 私有 Git 仓库（SSH）

每个任务报文携带本次仓库对应的 `task.deployKey`，计算节点只在该任务拉取阶段临时使用它：

- 私钥不保存在计算节点、不进入镜像、不写入持久卷；仅短暂写入 `/tmp` 的 `0600` 文件。
- Git 完成后立即删除临时私钥；任务日志和成绩回传不会包含私钥内容。
- 任务可提交 `git@github.com:组织/仓库.git`、`git@gitee.com:组织/仓库.git`，也兼容这两个站点的 HTTPS URL（计算侧会自动改用 SSH）。
- SSH 仓库若缺少 `task.deployKey` 会直接拒绝拉取，不回退到共享私钥。
- SSH host key 使用 `secrets/ssh/known_hosts` 严格校验，未知或变更的 host key 会拒绝拉取。

每个学生/仓库可以使用独立 Deploy Key，从而不受 GitHub 单个 Deploy Key 只能绑定一个仓库的限制。控制层应通过受保护的任务报文传入对应私钥，并限制其仓库权限为只读。

迁移部署时不要只导出 Docker image：任务私钥不在 image layer 中，部署包只需包含 `.env` 和 `known_hosts`。使用：

```bash
tools/package-deployment.sh /secure/path/cphomework-compute.tar
```

在目标机用：

```bash
tools/restore-deployment.sh /secure/path/cphomework-compute.tar /opt/cphomework-compute
cd /opt/cphomework-compute && docker compose up -d
```

这个 bundle 包含 `.env` 和 Git 私钥，必须通过受保护的私有通道传输；不要上传到 Git、镜像仓库或公开文件服务。
```

### 3. 挂载持久化卷说明
`docker-compose.yml` 中默认持久化配置：
- `/cache/venvs`：复用学生提交项目的依赖环境，避免重复下载包。
- `/workspace`：代码拉取与动态执行工作区。
