"""
RFC Audit Agent - 全局配置中心
"""

import os
import uuid
from pathlib import Path

# 根目录与工作区
BASE_DIR = Path(__file__).resolve().parent
WORKSPACE_DIR = BASE_DIR / "workspace"
CACHE_DIR = BASE_DIR / "cache"
VENV_CACHE_DIR = CACHE_DIR / "venvs"
PIP_CACHE_DIR = CACHE_DIR / "pip-cache"
CARGO_CACHE_DIR = CACHE_DIR / "cargo-cache"
MALICIOUS_DEPENDENCY_CACHE_FILE = Path(
    os.getenv("MALICIOUS_DEPENDENCY_CACHE_FILE", str(CACHE_DIR / "malicious-dependencies.json"))
)
AUDIT_LOG_FILE = Path(os.getenv("AUDIT_LOG_FILE", str(BASE_DIR / "logs" / "audit.jsonl")))

# 确保目录存在
for d in [WORKSPACE_DIR, CACHE_DIR, VENV_CACHE_DIR, PIP_CACHE_DIR, CARGO_CACHE_DIR, AUDIT_LOG_FILE.parent]:
    d.mkdir(parents=True, exist_ok=True)

# 控制层连接参数
CONTROL_PLANE_URL = os.getenv("CONTROL_PLANE_URL", "http://localhost:8787")
COMPUTE_AUTH_TOKEN = os.getenv("COMPUTE_AUTH_TOKEN", "")
if not COMPUTE_AUTH_TOKEN:
    if os.getenv("ENVIRONMENT") == "production":
        raise RuntimeError("安全致命错误：生产环境下必须显式配置 COMPUTE_AUTH_TOKEN 环境变量！")
    import warnings
    warnings.warn("[SECURITY NOTICE] 未配置 COMPUTE_AUTH_TOKEN，当前进程使用临时本地令牌；生产环境必须显式配置！")
    COMPUTE_AUTH_TOKEN = uuid.uuid4().hex

WORKER_ID = os.getenv("WORKER_ID", "rfc-audit-worker-01")

# 衔尾蛇 (Ouroboros) 轮询时钟 (秒)
POLL_INTERVAL_EMPTY = int(os.getenv("POLL_INTERVAL_EMPTY", "15"))   # 空队列休眠 15 秒
COOLDOWN_AFTER_TASK = int(os.getenv("COOLDOWN_AFTER_TASK", "10"))   # 任务完结后冷却 10 秒
POLL_TIMEOUT_SEC = int(os.getenv("POLL_TIMEOUT_SEC", "15"))         # HTTP 拉取超时时间

# 大语言模型配置 (OpenAI-compatible)
OPENAI_API_BASE = os.getenv("OPENAI_API_BASE", "")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o")
# User-requested generous reasoning/output budget. The upstream model may cap
# this according to its own context window.
LLM_MAX_OUTPUT_TOKENS = int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "20000"))
# LLM 请求的连接/读取超时。推理模型可能先花较长时间思考，不能用轮询层的
# 15 秒超时；读取超时默认 300 秒，并通过环境变量可调。
LLM_REQUEST_TIMEOUT_SEC = int(os.getenv("LLM_REQUEST_TIMEOUT_SEC", "500"))
MAX_NODE_RETRIES = int(os.getenv("MAX_NODE_RETRIES", "3"))
PRODUCTION_MODE = os.getenv("ENVIRONMENT", "development").lower() == "production"

# 安全审计阈值
MAX_FILE_COUNT = int(os.getenv("MAX_FILE_COUNT", "500"))
MAX_SINGLE_CODE_FILE_BYTES = int(os.getenv("MAX_SINGLE_CODE_FILE_BYTES", str(2 * 1024 * 1024))) # 2MB
MAX_TOTAL_REPO_BYTES = int(os.getenv("MAX_TOTAL_REPO_BYTES", str(100 * 1024 * 1024)))           # 100MB
SANDBOX_TIMEOUT_SEC = int(os.getenv("SANDBOX_TIMEOUT_SEC", "60"))                               # 沙箱硬超时 60s

# 过滤的大型非代码资产扩展名 (预检直接跳过，不下载)
FILTERED_EXTENSIONS = {
    # 深度学习模型与二进制权重
    ".pt", ".pth", ".bin", ".safetensors", ".weights", ".onnx", ".tflite", ".ckpt",
    # 大型数值与结构化数据集
    ".h5", ".hdf5", ".parquet", ".arrow", ".npy", ".npz", ".mat", ".fits",
    # 媒体与压缩包
    ".mp4", ".avi", ".mkv", ".mov", ".flv", ".mp3", ".wav",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".iso",
    # 高清图像 (视情况保留轻量图，其余大图过滤)
    ".png", ".jpg", ".jpeg", ".tiff", ".bmp", ".webp"
}

# 核心代码与文本扩展名
ALLOWED_CODE_EXTENSIONS = {
    ".py", ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hxx",
    ".rs", ".go", ".java", ".jl", ".f90", ".f95", ".f03",
    ".sh", ".bash", ".zsh", ".mk", ".cmake",
    ".json", ".yaml", ".yml", ".toml", ".txt", ".md", ".csv"
}
