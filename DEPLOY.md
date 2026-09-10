# 私密群聊 v2 — 手机端部署指南

> 12人加密群聊 / 每人独立密钥分区 / 12层嵌套加密 / 全程手机浏览器操作 / 全部免费

## 项目结构

```
chat-app/
├── index.html                  # 前端页面
├── style.css                   # 样式
├── crypto.js                   # 加密模块 (48密钥/12层嵌套/AES-256-GCM)
├── app.js                      # 前端逻辑
├── functions/
│   └── api/
│       └── [[path]].js         # 后端API (Pages Functions)
├── schema.sql                  # D1数据库建表语句
└── DEPLOY.md                   # 本文档
```

## 架构说明

- **1个管理员(admin)** + **最多11个成员(client)** = 12人
- 每个成员拥有独立的48对RSA-2048密钥(独立加密分区)
- 群组消息用群组AES密钥加密, 群组密钥由每个成员的12层嵌套RSA独立封装
- 12层嵌套: A→B→C洋葱式, 必须按顺序使用12个私钥逐层解封
- 管理员令牌30天有效期, 每次登录/操作自动续期
- 成员令牌24小时, 每次登录需重新输入账号密码验证码

---

## 部署步骤

### 第一步: 注册账号
1. 注册 Cloudflare: https://dash.cloudflare.com/sign-up (免费, 无需信用卡)
2. 注册 GitHub: https://github.com/signup (免费)

### 第二步: 创建GitHub仓库并上传代码
1. https://github.com/new → Repository name填 `private-chat` → 选Public → Create
2. Add file → Upload files → 上传 `index.html` `style.css` `crypto.js` `app.js` `schema.sql` `DEPLOY.md`
3. Add file → Create new file → 文件名填 `functions/api/[[path]].js` → 粘贴后端代码 → Commit

### 第三步: 创建D1数据库
1. Cloudflare Dashboard → D1 SQL Database → Create database
2. Name填 `chat-db` → 创建
3. 点击 Console → 粘贴 `schema.sql` 全部内容 → 回车执行
4. 记下 Database ID (Settings页面)

### 第四步: 创建R2存储桶
1. Cloudflare Dashboard → R2 → Create bucket
2. Bucket name填 `chat-files` → Create

### 第五步: 创建Pages项目
1. Cloudflare Dashboard → Workers & Pages → Create → Pages标签
2. Connect to Git → 授权GitHub → 选 `private-chat` 仓库
3. Framework preset选 None, Build command留空, Build output directory留空
4. Save and Deploy → 等待部署完成, 获得 `xxx.pages.dev` 域名

### 第六步: 配置绑定和环境变量
进入Pages项目 → Settings标签

**环境变量** (Production和Preview都加):
| 变量名 | 值 |
|--------|-----|
| `CAPTCHA_SECRET` | 任意随机字符串 |
| `ALLOW_REGISTRATION` | `true` (创建完账号后改为false) |

**D1绑定** (Settings → Functions → D1 database bindings):
- Variable name: `DB`
- Database: 选 `chat-db`

**R2绑定** (Settings → Functions → R2 bucket bindings):
- Variable name: `BUCKET`
- Bucket: 选 `chat-files`

**重新部署**: Deployments标签 → 最新部署右侧... → Retry deployment

---

## 初始化使用

### 1. 创建账号
1. 打开 `xxx.pages.dev`
2. 页面底部注册区域创建**管理员账号** (角色选"管理员")
3. 创建**成员账号** (角色选"普通成员"), 可创建最多11个
4. 回到Pages Settings → 环境变量 → `ALLOW_REGISTRATION`改为`false` → 重新部署 (关闭注册)

### 2. 管理员生成群组密钥
1. 用管理员账号登录
2. 系统自动生成群组AES密钥并保存在本地
3. 点击右上角 👥 打开成员管理

### 3. 为每个成员配置密钥
1. 在成员管理中点击某个成员
2. 点击"开始配置" → 等待生成48对RSA密钥(约10-30秒)
3. 系统自动: 上传公钥 → 12层嵌套封装群组密钥 → 上传封装 → 生成OTP+密钥包
4. 复制 **OTP** 和 **密钥包**, 通过Signal/Telegram密聊等可信平台发给该成员
5. OTP 4小时后自动失效, 可随时重新生成

### 4. 成员配置密钥
1. 成员用自己的账号登录
2. 进入密钥配置页 → 粘贴OTP和密钥包 → 解密并配置
3. 自动解密群组密钥封装 → 进入群聊

### 5. 日常使用
- 管理员: 打开即自动登录(30天续期), 可查看全部历史、分享历史、管理成员、轮换群组密钥
- 成员: 每次登录需账号+密码+验证码, 退出后历史消失, 管理员分享的消息可见
- 语音通话: 点击📞 → 选择通话对象

---

## 常见问题

**Q: 成员清除浏览器数据后怎么办?**
A: 管理员在成员管理中重新为该成员配置密钥, 生成新OTP和密钥包发给对方。

**Q: 如何轮换群组密钥?**
A: 管理员 → 👥成员管理 → 点击"🔄轮换群组密钥"。轮换后所有成员需重新配置密钥。

**Q: 12层嵌套加密如何工作?**
A: 群组AES密钥被12层AES+RSA嵌套封装。解密时必须按顺序使用12个RSA私钥, 每层解封后才能获得下一层的密钥和密文。48个密钥中只有12个是真实的, 其余36个是诱饵。

**Q: 免费额度够吗?**
A: 12人完全够用: Pages无限带宽, D1 5GB/10万读每天, R2 10GB, Functions 10万请求/天。

**Q: 管理员令牌30天怎么算?**
A: 从最后一次活动(任何API请求)开始算30天。只要30天内登录过一次就自动续期。连续30天不活动才会过期。
