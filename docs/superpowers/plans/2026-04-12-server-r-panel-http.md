# server-r-panel 提取计划（HTTP 优先）

## 分支

- 基于 `dev/master` 创建 `dev/extract-panel`
- 完成后合并回 `dev/master`

## 目标

从 `server-trojan-rs` 的 `business/` 模块提取面板通信逻辑为独立 crate `server-r-panel`，供 Trojan、TUIC 等代理服务器复用。

## 架构原则

- **协议无关**：crate 不绑定任何代理协议，消费者通过 newtype 桥接
- **HTTP 优先**：默认依赖 `server-client-rs`（HTTP REST），预留 `connectrpc` feature flag 扩展
- **无锁热路径**：ArcSwap 用户认证、DashMap+AtomicU64 流量统计
- **独立 runtime**：后台任务运行在 2-worker 专用 tokio runtime，避免代理 I/O 饥饿

## 模块结构

```
server-r-panel/
├── Cargo.toml
└── src/
    ├── lib.rs            # 公开导出 + password_to_hex()
    ├── types.rs          # User, UserTraffic, PanelConfig, TrafficStats
    ├── client.rs         # ApiManager — 包装 server_client_rs::ApiClient
    ├── user_manager.rs   # UserManager — ArcSwap 热更新 + UserDiff（无 kick）
    ├── stats.rs          # StatsCollector — 无锁流量统计
    └── tasks.rs          # BackgroundTasks — 周期任务编排 + on_user_diff 回调
```

## 依赖

```toml
[dependencies]
server-client-rs = { git = "https://github.com/xflash-panda/server-client-rs.git", tag = "v0.1.12" }
tokio = { version = "1.49", features = ["rt-multi-thread", "time", "sync"] }
anyhow = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1"
tracing = "0.1"
sha2 = "0.10"
hex = "0.4"
arc-swap = "1"
dashmap = "6.1"
scopeguard = "1.2.0"
hostname = "0.4"

[dev-dependencies]
tokio-test = "0.4"
```

## 执行步骤

### Task 1: crate 脚手架

在 `/Users/alex/code/rust/xflash-panda/server-r-panel/` 创建：
- `Cargo.toml`（上述依赖）
- `src/lib.rs`（空模块声明）
- `src/types.rs`, `src/stats.rs`, `src/user_manager.rs`, `src/client.rs`, `src/tasks.rs`（空文件）
- 确保 `cargo check` 通过

### Task 2: types.rs

公共类型，跨模块使用：

```rust
pub struct User { pub id: i64, pub uuid: String }
pub struct UserTraffic { pub user_id: i64, pub u: u64, pub d: u64, pub n: u64 }

pub struct PanelConfig {
    pub api: String,           // HTTP API 端点 URL
    pub token: String,         // API 认证 token
    pub node_id: i64,
    pub node_type: NodeType,   // 来自 server-client-rs
    pub data_dir: String,      // 状态文件目录
    pub api_timeout: u64,      // 超时秒数
    pub debug: bool,           // 调试模式
}
```

- `NodeType` 从 `server-client-rs` re-export
- `User` 自定义（不依赖消费者的 User 类型）

### Task 3: stats.rs

从 `business/stats.rs` 迁移 `ApiStatsCollector`：

- 重命名为 `StatsCollector`
- **不 impl 任何外部 trait**，消费者通过 newtype 桥接
- `UserId` 直接用 `i64`
- `UserStatsSnapshot`, `reset_all()`, `get_stats()` 等 API 保持不变
- 带上所有现有单元测试

### Task 4: user_manager.rs

从 `business/api/user_manager.rs` 迁移 `UserManager`：

- **移除 `ConnectionManager` 依赖和 kick 逻辑**
- `update()` 返回 `UserDiff` 替代 `(added, removed, uuid_changed, kicked)` 元组
- `User` 类型用 `crate::types::User`
- `password_to_hex()` 用 `crate::password_to_hex()`

```rust
pub struct UserDiff {
    pub added: usize,
    pub removed: usize,
    pub uuid_changed: usize,
    pub removed_ids: Vec<i64>,         // 被移除的用户 ID
    pub uuid_changed_ids: Vec<i64>,    // UUID 变更的用户 ID
}
```

- 测试改为验证 `UserDiff` 字段，移除 kick 相关断言

### Task 5: client.rs

从 `business/api/client.rs` 迁移 `ApiManager`：

- 构造函数接收 `PanelConfig` 替代 `CliArgs`
- `NodeType` 来自 `PanelConfig.node_type`（不硬编码 Trojan）
- `fetch_config()` 返回 `NodeConfigEnum`（消费者自己调 `.as_trojan()` / `.as_tuic()`）
- `fetch_users()` 返回 `Vec<crate::types::User>`（从 `server_client_rs::User` 转换）
- 日志用 `tracing` 宏替代 `crate::logger::log`
- `PersistentState`、状态文件管理原样迁移
- `state_file_path` 由 `PanelConfig.data_dir` + node_id 计算

### Task 6: tasks.rs

从 `business/api/tasks.rs` 迁移 `BackgroundTasks`：

- 引用更新为 crate 内部类型（`StatsCollector`, `ApiManager`, `UserManager`）
- `fetch_users_once` 调用 `user_manager.update()` 并记录 `UserDiff`
- **新增 `on_user_diff` 回调**：`BackgroundTasks::on_user_diff(self, f: Arc<dyn Fn(UserDiff) + Send + Sync>) -> Self`
- `report_traffic_once`：`stats.reset_all()` → 转换为 `server_client_rs::UserTraffic` → `api.submit_traffic()`
- `format_bytes` 辅助函数原样迁移
- `TaskConfig`, `BackgroundTasksHandle` 原样迁移

### Task 7: lib.rs

```rust
pub mod types;
mod client;
mod user_manager;
mod stats;
mod tasks;

pub use types::*;
pub use client::ApiManager;
pub use user_manager::{UserManager, UserDiff};
pub use stats::{StatsCollector, UserStatsSnapshot};
pub use tasks::{BackgroundTasks, BackgroundTasksHandle, TaskConfig};
pub use server_client_rs::NodeType;

/// SHA224 密码转 56 字节 hex
pub fn password_to_hex(password: &str) -> [u8; 56] { ... }
```

### Task 8: 编译测试 server-r-panel

- `cargo fmt`
- `cargo clippy`
- `cargo test`

### Task 9: 接入 server-trojan-rs

**Cargo.toml 变更：**
- 新增 `server-r-panel` path 依赖
- 移除 `hostname`、`scopeguard`（被 panel 内部消化）
- 保留 `server-client-rs`（仍需 `TrojanConfig` 等类型）

**business/ 模块精简为薄包装：**

```rust
// business/mod.rs
use server_r_panel as panel;

pub use panel::{ApiManager, BackgroundTasks, TaskConfig, UserManager};

// Newtype: 桥接 panel::StatsCollector → core::hooks::StatsCollector
pub struct TrojanStatsCollector(pub Arc<panel::StatsCollector>);
impl core::hooks::StatsCollector for TrojanStatsCollector { ... }

// Newtype: 桥接 ArcSwap user map → core::hooks::Authenticator
pub struct TrojanAuthenticator(pub Arc<ArcSwap<HashMap<[u8; 56], i64>>>);
impl core::hooks::Authenticator for TrojanAuthenticator { ... }
```

**main.rs 变更：**

```rust
let panel_config = panel::PanelConfig {
    api: cli.api.clone(),
    token: cli.token.clone(),
    node_id: cli.node,
    node_type: panel::NodeType::Trojan,
    data_dir: cli.data_dir.clone(),
    api_timeout: cli.api_timeout,
    debug: cli.log_mode == "debug",
};

let api_manager = Arc::new(panel::ApiManager::new(panel_config)?);
// fetch_config 返回 NodeConfigEnum，消费者提取 TrojanConfig
let node_config = api_manager.fetch_config().await?;
let trojan_config = node_config.as_trojan()?.clone();

// on_user_diff 回调处理 kick
let conn_mgr = conn_manager.clone();
let on_diff = Arc::new(move |diff: panel::UserDiff| {
    for uid in diff.removed_ids.iter().chain(diff.uuid_changed_ids.iter()) {
        conn_mgr.kick_user(*uid);
    }
});
let bg_handle = panel::BackgroundTasks::new(task_config, api_manager, user_manager, stats)
    .on_user_diff(on_diff)
    .start();
```

### Task 10: 全量测试

- `cargo fmt --check`
- `cargo clippy`
- `cargo test`（275 测试全部通过）

## server-trojan-rs 中保留不动的部分

- `core/` — 核心代理逻辑、hooks traits、连接管理
- `transport/` — TCP、WebSocket、gRPC 传输
- `handler.rs` — 连接处理
- `server_runner.rs` — 服务器启动
- `config.rs` — CLI 参数（CliArgs, ConnConfig, ServerConfig）
- `acl.rs`, `logger.rs`, `error.rs` — 不变

## 未来扩展：connectrpc feature

```toml
[features]
default = ["http"]
http = ["server-client-rs"]
connectrpc = ["server-agent-proto-rs", "tonic"]
```

client.rs 通过条件编译支持两种后端，API 接口保持一致。这部分在 `agent-master` 分支实现。
