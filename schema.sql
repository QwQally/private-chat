-- ============================================================
-- 私密聊天系统 v2 - 12人多分区版
-- D1 数据库 Schema
-- 执行方式: Cloudflare Dashboard → D1 → Console → 粘贴执行
-- ============================================================

-- 用户表 (最多12人)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'client',   -- 'admin'(服务端/你) 或 'client'
    display_name TEXT,
    created_at INTEGER NOT NULL
);

-- 会话表 (令牌管理)
-- admin: 有效期30天, 每次登录自动续期
-- client: 有效期24小时
CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- 群组表 (默认创建1个群)
CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- 群组成员
CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY (conversation_id, user_id)
);

-- 每个用户的公钥 (48个/用户, 独立分区)
CREATE TABLE IF NOT EXISTS public_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    key_index INTEGER NOT NULL,            -- 0-47
    jwk_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, key_index)
);

-- 群组密钥封装表
-- 群组AES密钥用每个用户的12层RSA独立封装, 每人一份
CREATE TABLE IF NOT EXISTS group_key_wraps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    conversation_id INTEGER NOT NULL DEFAULT 1,
    wrapped_key TEXT NOT NULL,             -- AES-GCM密文(base64), 内容是群组AES密钥
    wrap_iv TEXT NOT NULL,                 -- IV(base64)
    e_values TEXT NOT NULL,                -- 48个RSA封装值(JSON数组, 12真实+36诱饵)
    key_version INTEGER NOT NULL DEFAULT 1,-- 密钥轮换版本号
    created_at INTEGER NOT NULL,
    UNIQUE(user_id, conversation_id, key_version)
);

-- 消息表 (密文存储, 用群组AES密钥加密)
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL DEFAULT 1,
    sender_id INTEGER NOT NULL,
    ciphertext TEXT NOT NULL,              -- AES-GCM密文(base64)
    aes_iv TEXT NOT NULL,                  -- IV(base64), 每条消息随机
    message_type TEXT NOT NULL DEFAULT 'text', -- text / image / mixed / system
    timestamp INTEGER NOT NULL,
    shared_with TEXT,                      -- JSON数组, admin指定分享给哪些user_id
    FOREIGN KEY (sender_id) REFERENCES users(id)
);

-- 索引
CREATE INDEX IF NOT EXISTS idx_messages_conv_time ON messages(conversation_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_public_keys_user ON public_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_groupkey_user ON group_key_wraps(user_id, conversation_id);

-- 初始化默认群组
INSERT OR IGNORE INTO conversations (id, name, created_at) VALUES (1, '私密群聊', strftime('%s','now')*1000);
