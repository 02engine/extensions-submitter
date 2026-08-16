# 🐱 Scratch 扩展提交工具

一个网页工具，允许开发者通过表单提交 Scratch 扩展，自动上传文件并创建 GitHub Pull Request。

## 📁 项目结构

```
scratch-ext-submit/
├── public/
│   └── index.html          # 前端表单页面（纯静态，无任何外部依赖）
├── netlify/
│   └── functions/
│       └── submit.js       # Netlify Function（核心后端逻辑）
├── netlify.toml            # Netlify 配置文件
├── package.json            # 依赖声明（仅 dev 依赖 netlify-cli）
└── README.md
```

## 🔐 安全设计

| 安全措施 | 说明 |
|---------|------|
| **GitHub App 私钥** | 仅存储在 Netlify 环境变量中，永不暴露前端 |
| **短命令牌** | JWT 10分钟过期，安装令牌1小时过期 |
| **最小权限** | App 仅拥有 Contents + Pull Requests 写权限 |
| **分支隔离** | 每次提交创建独立分支，通过 PR 审查后合并 |
| **环境变量加密** | Netlify 自动加密存储所有环境变量 |

## 🚀 完整部署步骤

### 第一步：创建 GitHub App

1. 打开 **https://github.com/settings/apps**
2. 点击 **New GitHub App**
3. 填写表单：

| 字段 | 填什么 |
|------|--------|
| **GitHub App name** | `scratch-ext-submitter`（随意取，不重复就行） |
| **Homepage URL** | 先填 `https://example.com`，部署后再改 |
| **Webhook** | ❌ 取消勾选 "Active" |
| **Repository permissions → Contents** | Read & Write |
| **Repository permissions → Pull requests** | Read & Write |
| **Repository permissions → Metadata** | Read（自动勾选） |

4. 点击 **Create GitHub App**
5. 在跳转后的页面，记下 **App ID**（纯数字，如 `1234567`）
6. 滚动到页面底部 **Private keys** 区域
7. 点击 **Generate a private key**
8. 浏览器自动下载一个 `.pem` 文件（如 `scratch-ext-submitter-1234567-private-key.pem`）

### 第二步：安装 GitHub App 到目标仓库

1. 在 App 设置页面，左侧菜单点 **Install App**
2. 选择要安装到的账户/组织
3. 选择目标仓库（你的 Scratch 扩展仓库）
4. 点击 **Install**
5. 安装成功后，URL 会变成类似：
   ```
   https://github.com/settings/installations/55667788
   ```
6. 记下末尾数字 → 这就是 **Installation ID**

### 第三步：处理私钥（关键步骤）

你需要把 `.pem` 文件的内容转成一行字符串（换行用 `\n` 表示）：

**Mac / Linux 终端：**
```bash
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' scratch-ext-submitter-*.pem
```

**Windows PowerShell：**
```powershell
(Get-Content your-key.pem -Raw) -replace "`r`n","`n" -replace "`n","\n"
```

输出类似：
```
-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQEAxxxx...\n-----END RSA PRIVATE KEY-----\n
```

> ⚠️ 这就是你要填到 Netlify 环境变量里的 `GITHUB_PRIVATE_KEY` 的值

### 第四步：准备目标仓库

在你的 Scratch 扩展仓库中，确保存在以下文件结构（至少要有 `extensions.json`）：

```
your-repo/
├── extensions.json          # ← 必须存在，初始内容见下方
├── extension/             # ← 目录会自动创建
├── image/                 # ← 目录会自动创建
├── doc/                   # ← 目录会自动创建
└── samples/                # ← 目录会自动创建
```

如果仓库是全新的，先创建一个 `extensions.json`：

```json
{
    "extensions": []
}
```

提交到 `main` 分支。

### 第五步：部署到 Netlify

#### 方式 A：Git 集成部署（推荐）

1. 把整个 `scratch-ext-submit` 文件夹推送到一个 GitHub 仓库
   ```bash
   cd scratch-ext-submit
   git init
   git add .
   git commit -m "init: scratch extension submit tool"
   git remote add origin https://github.com/YOUR_USERNAME/scratch-ext-submit.git
   git push -u origin main
   ```

2. 打开 **https://app.netlify.com**
3. 点击 **Add new site** → **Import from Git**
4. 授权 GitHub，选择刚创建的仓库
5. 构建设置：
   - **Branch to deploy:** `main`
   - **Build command:** （留空）
   - **Publish directory:** `public`
6. 点击 **Deploy site**
7. 等待部署完成，记下你的站点 URL（如 `https://amazing-curie-123456.netlify.app`）

#### 方式 B：Netlify CLI 部署

```bash
# 安装 CLI
npm install -g netlify-cli

# 登录
netlify login

# 进入项目目录
cd scratch-ext-submit

# 初始化（首次）
netlify init

# 部署
netlify deploy --prod
```

### 第六步：设置环境变量

1. Netlify 后台 → 你的站点 → **Site settings** → **Environment variables**
2. 点击 **Add a variable**，逐个添加：

| 变量名 | 值示例 | 说明 |
|--------|--------|------|
| `GITHUB_APP_ID` | `1234567` | 第一步记下的 App ID |
| `GITHUB_PRIVATE_KEY` | `-----BEGIN...\n...END-----\n` | 第三步处理后的私钥 |
| `GITHUB_OWNER` | `FurryR` | 目标仓库的所有者名 |
| `GITHUB_REPO` | `scratch-extensions` | 目标仓库名 |
| `GITHUB_INSTALLATION_ID` | `55667788` | 第二步记下的安装 ID |

3. 添加完后，回到站点面板 → **Deploys** → **Trigger deploy** → **Deploy site**
   - 必须重新部署才能让环境变量生效！
> ⚠️ 两个必检项（最常见的"配置了却报未配置"的原因）：
> 1. **作用域（Scope）必须包含 Functions**：Netlify 后台添加变量时可选作用域，如果默认只勾了 **Builds**，服务器函数运行时就读不到，会一直报 `服务器环境变量未配置完整`。请把每个变量的作用域设为 **Functions**（或同时包含 Functions）。
> 2. **改完环境变量后必须重新部署**：函数的环境变量是在**构建/部署时注入**的（不是运行时实时读取）。改完请到 **Deploys → Trigger deploy → Deploy site**。
>
> 若仍报错，新版后端已会在报错里**明确指出缺少的变量名**（如 `缺少: GITHUB_INSTALLATION_ID`），照着补即可。

### 第七步：更新 GitHub App 的 Homepage URL

1. 回到 **https://github.com/settings/apps**
2. 点进你的 App → 修改 **Homepage URL** 为 Netlify 给你的站点地址
3. 点击 **Save changes**

## ✅ 使用方式

1. 打开你的 Netlify 站点 URL
2. 填写表单：
   - **Slug**：纯英文标识，如 `my-extension`
   - **扩展名称**：显示名称
   - **描述**：英文描述
   - **扩展 ID**：通常与 slug 相同
   - **作者**：至少填一个
3. 上传文件：
   - **JS 文件**：必须命名为 `{slug}.js`
   - **封面图**：任意比例都行，系统自动裁剪为 2:1
4. 可选：勾选上传文档 HTML / 实例 .sb3
5. 点击 **🚀 提交扩展并创建 PR**
6. 等待几秒 → 看到成功提示 → 点击 PR 链接去审查

## 📋 提交后仓库变化

```
your-repo/
├── extensions.json              # ← 自动新增/更新条目
├── extension/
│   └── {slug}.js               # ← 新增
├── image/
│   └── {slug}.png              # ← 新增（已裁剪为 2:1）
├── doc/
│   └── {slug}.html             # ← 可选新增
└── samples/
    └── {slug}.sb3              # ← 可选新增
```

PR 标题格式：`feat: 提交扩展 {名称} ({slug})`

## 🛠️ 本地开发

```bash
# 1. 安装依赖
npm install

# 2. 创建 .env 文件
cat > .env << 'EOF'
GITHUB_APP_ID=1234567
GITHUB_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIB...\n-----END RSA PRIVATE KEY-----\n"
GITHUB_OWNER=your-username
GITHUB_REPO=scratch-extensions
GITHUB_INSTALLATION_ID=55667788
EOF

# 3. 启动开发服务器（默认 http://localhost:8888）
netlify dev
```

## ❓ 常见问题
**Q: 一直提示 "服务器环境变量未配置完整，缺少: XXX"，但我明明配置了？**
- **作用域没选对**：把变量作用域从 `Builds` 改为/加上 `Functions`（函数运行时才能读到）。
- **没重新部署**：函数的环境变量在部署/build 时注入，改完后必须 **Trigger deploy → Deploy site**。
- **值是空串或纯空格**：后端会 trim 判空，请确认填的是真实值。
- 报错里会直接列出缺失的变量名，照提示补上缺失项即可。

**Q: 提交时报错 "获取安装令牌失败"**
- 检查 `GITHUB_APP_ID` 和 `GITHUB_PRIVATE_KEY` 是否正确
- 确认私钥的 `\n` 没有被二次转义（Netlify 环境变量里应该直接粘贴含 `\n` 的字符串）

**Q: 报错 "Not Found" 或 404**
- 检查 `GITHUB_OWNER` 和 `GITHUB_REPO` 拼写
- 确认 GitHub App 已安装到该仓库

**Q: JS 文件名为啥必须和 slug 一样？**
- 这是你现有仓库的约定（看你的 `extensions.json` 里都是 `{slug}.js`）
- 前端会强制校验，不一致直接报错

**Q: 封面图裁剪会失真吗？**
- 不会。始终从原图**居中裁剪**，只裁掉多余部分，不拉伸不变形
- 建议上传时尽量接近 2:1，裁剪损失最小

**Q: 能重复提交同一个 slug 吗？**
- 能。后端检测到同名 slug 会**替换**原有条目，文件也会覆盖更新
- 每次仍然创建新分支和新 PR

## 📄 License

MIT
