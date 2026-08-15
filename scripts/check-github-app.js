#!/usr/bin/env node
// scripts/check-github-app.js
// 本地诊断：用你当前的环境变量逐段验证 GitHub App 配置，精确定位 401/"对不上 hash" 出在哪一步。
//
// 用法：
//   1) 先创建并填写 .env（同 README），或直接 export 环境变量；
//   2) 运行：node scripts/check-github-app.js
//
// 它会依次测试：
//   1) GET /app                     —— 验证 GITHUB_APP_ID 与 GITHUB_PRIVATE_KEY 是否匹配
//   2) POST app/installations/{id}/access_tokens —— 验证 GITHUB_INSTALLATION_ID
//   3) GET /repos/{owner}/{repo}    —— 验证 GITHUB_OWNER/GITHUB_REPO 与安装权限
import { createSign } from 'crypto';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

function base64url(input) {
    const buf = typeof input === 'string' ? Buffer.from(input) : input;
    return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function buildJWT(appId, privateKey) {
    const header = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = { iat: now - 60, exp: now + 60 * 9, iss: String(appId) };
    const data = base64url(JSON.stringify(header)) + '.' + base64url(JSON.stringify(payload));
    const sign = createSign('RSA-SHA256');
    sign.update(data);
    return data + '.' + base64url(sign.sign(privateKey));
}

// 轻量 .env 读取（不覆盖已有真实环境变量）
function loadDotEnv() {
    const root = path.dirname(fileURLToPath(import.meta.url));
    for (const p of [path.join(process.cwd(), '.env'), path.join(root, '..', '.env')]) {
        if (!fs.existsSync(p)) continue;
        for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
            const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)(\s*#.*)?$/);
            if (!m || process.env[m[1]] !== undefined) continue;
            let v = m[2].trim().replace(/\s+$/, '');
            if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
            process.env[m[1]] = v;
        }
    }
}

function must(cond, msg) { if (cond) return; console.error('❌ ' + msg); process.exit(1); }

async function api(pathname, token, method = 'GET', body) {
    const res = await fetch('https://api.github.com' + pathname, {
        method,
        headers: {
            Authorization: 'Bearer ' + token,
            Accept: 'application/vnd.github+json',
            'X-GitHub-Api-Version': '2022-11-28',
            ...(body ? { 'Content-Type': 'application/json' } : {})
        },
        ...(body ? { body: JSON.stringify(body) } : {})
    });
    const text = await res.text();
    let json = null; try { json = text ? JSON.parse(text) : null; } catch (e) { /* ignore */ }
    return { ok: res.ok, status: res.status, json, text };
}
async function main() {
    loadDotEnv();
    const appId = process.env.GITHUB_APP_ID;
    const raw = process.env.GITHUB_PRIVATE_KEY;
    const owner = process.env.GITHUB_OWNER;
    const repo = process.env.GITHUB_REPO;
    const instId = process.env.GITHUB_INSTALLATION_ID;

    const missing = [];
    if (!appId) missing.push('GITHUB_APP_ID');
    if (!raw) missing.push('GITHUB_PRIVATE_KEY');
    if (!owner) missing.push('GITHUB_OWNER');
    if (!repo) missing.push('GITHUB_REPO');
    if (!instId) missing.push('GITHUB_INSTALLATION_ID');
    must(missing.length === 0, '缺失环境变量: ' + missing.join(', '));

    console.log('GITHUB_APP_ID          =', appId);
    console.log('GITHUB_OWNER/REPO      =', owner + '/' + repo);
    console.log('GITHUB_INSTALLATION_ID =', instId);
    console.log('私钥长度(字符)          =', raw.length);

    // ---- 1) 解码/归一化私钥 ----
    let privateKey = String(raw).trim();
    const looksBase64 = /^[A-Za-z0-9+/=\s]+$/.test(privateKey) && privateKey.startsWith('LS0t');
    if (looksBase64) { console.log('→ 检测到 Base64 编码，先解码'); privateKey = Buffer.from(privateKey, 'base64').toString('utf8'); }
    privateKey = privateKey.replace(/\\r\\n/g, '\n').replace(/\\r/g, '').replace(/\\n/g, '\n');
    console.log('→ 私钥头部(前30字符):', JSON.stringify(privateKey.slice(0, 30)));
    console.log('→ 含 -----BEGIN:', privateKey.includes('-----BEGIN'), '| 含 -----END:', privateKey.includes('-----END'));

    // ---- 2) 用私钥签 JWT ----
    let jwt;
    try { jwt = buildJWT(appId, privateKey); console.log('✅ 私钥可正常签名，JWT 生成成功'); }
    catch (e) { must(false, '私钥无法用于签名（格式/换行有误）：' + e.message); }

    // ---- 3) 测试第 1 段：App 的 JWT 是否有效 ----
    const a = await api('/app', jwt);
    console.log('\n── 1) GET /app（验证 App ID + 私钥是否匹配）──');
    if (a.ok) {
        console.log('   ✅ App:', a.json.name, '| id:', a.json.id, '| slug:', a.json.slug);
    } else {
        console.log('   ❌ HTTP', a.status, a.text.slice(0, 200));
        console.log('   ➜ 这是"对不上 hash/401"的根源：GITHUB_APP_ID 与 GITHUB_PRIVATE_KEY 不是同一个 App 的。');
        console.log('     请到 https://github.com/settings/apps 确认 App ID，并确认用的是该 App 『Generate a private key』下载的 .pem（建议用原始多行 PEM，勿转码）。');
        process.exit(1);
    }

    // ---- 4) 测试第 2 段：换安装令牌 ----
    console.log('\n── 4) POST /app/installations/' + instId + '/access_tokens（验证 Installation ID）──');
    const b = await api('/app/installations/' + instId + '/access_tokens', jwt, 'POST');
    if (!b.ok) {
        console.log('   ❌ HTTP', b.status, b.text.slice(0, 200));
        console.log('   ➜ JWT 有效但从该 Installation 换 token 失败：GITHUB_INSTALLATION_ID 填错，或该 App 未安装到此账号/组织。');
        console.log('     请到 https://github.com/settings/installations 复制真实的 Installation ID。');
        process.exit(1);
    }
    const token = b.json.token;
    console.log('   ✅ 安装令牌获取成功');
    const repoList = (b.json.repositories || []).map((r) => r.full_name);
    if (repoList.length) console.log('   → 该安装可访问的仓库:', repoList.join(', '));
    else console.log('   → 注意：该安装的仓库权限为「All repositories」或未授权任何仓库');

    // ---- 5) 测试第 3 段：目标仓库是否可访问 ----
    console.log('\n── 5) GET /repos/' + owner + '/' + repo + '（验证目标仓库权限）──');
    const c = await api('/repos/' + owner + '/' + repo, token);
    if (c.ok) {
        console.log('   ✅ 可访问。仓库:', c.json.full_name, '| 默认分支:', c.json.default_branch);
    } else {
        console.log('   ❌ HTTP', c.status, c.text.slice(0, 200));
        console.log('   ➜ GITHUB_OWNER/GITHUB_REPO 拼写，或该 App 未安装/未被授权访问此仓库。');
        process.exit(1);
    }

    console.log('\n✅ 三个步骤全部通过：配置完全可用。确保将本地改动提交并推送后再在 Netlify 触发部署。');
}

main().catch((e) => { console.error('脚本异常:', e.message); process.exit(1); });