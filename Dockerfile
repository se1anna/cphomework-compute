# ==============================================================================
# RFC Audit Agent - 生产级安全加固 Dockerfile (非 Root、供应链可信、受限沙箱)
# ==============================================================================

FROM ubuntu:22.04

LABEL maintainer="RFC Audit Board <audit@example.com>"
LABEL description="LangGraph Multi-Language RFC Audit Agent with Restricted Non-Root User"

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# 1. 创建独立无特权用户与用户组 agentuser (UID 1000)
RUN groupadd -g 1000 agentuser && \
    useradd -u 1000 -g agentuser -m -s /bin/bash agentuser

# 2. 安装 Python 运行时、GCC/Clang/Make 编译工具链、Cargo/Rustc 与 Git (通过可信 APT 官方仓库)
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    build-essential \
    gcc \
    g++ \
    clang \
    make \
    cmake \
    git \
    openssh-client \
    cargo \
    rustc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 3. 创建应用工作目录与持久化缓存目录，并收紧权限 (仅属主读写执行，废弃 777)
WORKDIR /app
RUN mkdir -p /app/workspace /app/cache/venvs /app/cache/pip-cache /app/cache/cargo-cache && \
    chown -R agentuser:agentuser /app && \
    chmod 750 /app/workspace /app/cache

# 4. 复制依赖清单并以 root 完成系统级安装
COPY requirements.txt /app/
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# 5. 复制 Agent 业务代码并赋予专有用户所有权
COPY --chown=agentuser:agentuser . /app/

# 6. 配置持久化缓存环境变量
ENV PIP_CACHE_DIR=/app/cache/pip-cache
ENV CARGO_HOME=/app/cache/cargo-cache
ENV HOME=/home/agentuser

# 7. 切换至无特权用户运行，彻底消除容器 Root 逃逸风险
USER agentuser

# 8. 运行主守护进程
CMD ["python3", "main.py"]
