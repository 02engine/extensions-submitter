import { KJUR, KEYUTIL } from 'jsrsasign';
import { createHash } from 'node:crypto';
import { getStore } from '@netlify/blobs';
const GH_API = 'https://api.github.com';

// ================= 超级日志工具 =================
// 统一输出格式：[时间] [+耗时] [级别] 消息 附加信息
const LOG_START = Date.now();
let __seq = 0;
function _pad(n) { return String(n).padStart(2, '0'); }
function _ts() {
    const d = new Date();
    return `${d.getFullYear()}-${_pad(d.getMonth() + 1)}-${_pad(d.getDate())} ${_pad(d.getHours())}:${_pad(d.getMinutes())}:${_pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}
const _ICON = { INFO: '🗒️', DEBUG: '🔵', WARN: '🟡', ERROR: '🔴', OK: '✅', STEP: '⚙️', GH: '🐙', CAP: '🛡️', BLOB: '📦', ENV: '🔑', JWT: '🎫', API: '☁️' };
function _log(level, tag, msg, extra) {
    const seq = ++__seq;
    const elapsed = Date.now() - LOG_START;
    const icon = _ICON[tag] || _ICON[level] || '•';
    const base = `[${_ts()}] [+${String(elapsed).padStart(6)}ms] #${String(seq).padStart(3)} [${level}] ${icon} ${msg}`;
    const payload = extra === undefined ? '' : (typeof extra === 'string' ? ` · ${extra}` : ` · ${JSON.stringify(extra)}`);
    if (level === 'ERROR') console.error(base + payload);
    else if (level === 'WARN') console.warn(base + payload);
    else console.log(base + payload);
}
const logInfo  = (m, e) => _log('INFO',  'INFO', m, e);
const logDebug = (m, e) => _log('INFO',  'DEBUG', m, e);
const logWarn  = (m, e) => _log('WARN',  'WARN', m, e);
const logError = (m, e) => _log('ERROR', 'ERROR', m, e);
const logOk    = (m, e) => _log('INFO',  'OK', m, e);
const logStep  = (m, e) => _log('INFO',  'STEP', m, e);
const logGh    = (m, e) => _log('INFO',  'GH', m, e);
const logCap   = (m, e) => _log('INFO',  'CAP', m, e);
const logBlob  = (m, e) => _log('INFO',  'BLOB', m, e);

// ---- Cap 人机验证 ----
// 与 netlify/edge-functions/cap.js 共用的 Blobs store（一次性 cap-token 存于此）
const CAP_STORE = 'cap';

// 校验前端经过 Cap 人机验证后签发的一次性 token。
// 只有带有效 token 的请求才允许继续调用后端，否则一律拒绝 —— 保证后端无法被单独使用。
async function verifyCapToken(capToken) {
    const t0 = Date.now();
    logCap('verifyCapToken 开始（校验前端一次性凭证）');

    // ---- 环境诊断：Netlify Blobs 连接上下文是否注入 ----
    const ctxGlobal = typeof globalThis.netlifyBlobsContext !== 'undefined' ? globalThis.netlifyBlobsContext : null;
    const ctxEnv = process.env.NETLIFY_BLOBS_CONTEXT || null;
    if (ctxGlobal || ctxEnv) {
        logBlob('Blobs 连接上下文已注入', { global: !!ctxGlobal, env: !!ctxEnv });
    } else {
        logWarn('Blobs 连接上下文缺失（global/env 均为空）→ getStore 将抛 MissingBlobsEnvironmentError', {
            global: false, env: false,
            提示: '生产=需重新部署让平台注入 NETLIFY_BLOBS_CONTEXT；本地=需 netlify login + link'
        });
    }
    if (ctxEnv) {
        try {
            const parsed = JSON.parse(Buffer.from(ctxEnv, 'base64').toString('utf-8'));
            logDebug('NETLIFY_BLOBS_CONTEXT 解码成功', { siteID: !!parsed.siteID, token: !!parsed.token, keys: Object.keys(parsed) });
        } catch (e) {
            logError('NETLIFY_BLOBS_CONTEXT base64 解码失败', e.message);
        }
    }

    if (!capToken || typeof capToken !== 'string') {
        logWarn('缺少 capToken → 拒绝');
        return { ok: false, error: '缺少人机验证凭证，请稍后重试' };
    }

    // token 格式为 "<id>:<verToken>"
    const idx = capToken.indexOf(':');
    if (idx <= 0) {
        logWarn('capToken 格式非法（无冒号分隔）', { len: capToken.length });
        return { ok: false, error: '人机验证凭证无效' };
    }
    const id = capToken.slice(0, idx);
    const verToken = capToken.slice(idx + 1);
    if (!id || !verToken) {
        logWarn('capToken 的 id/verToken 为空', { idLen: id.length, verTokenLen: verToken.length });
        return { ok: false, error: '人机验证凭证无效' };
    }

    // 重新推导 tokenKey，与边缘函数写入时一致
    const tokenKey = `${id}:${createHash('sha256').update(verToken).digest('hex')}`;
    logDebug('tokenKey 重算完成（不落完整值）', { idPrefix: id.substring(0, 6) });

    let store;
    let record;
    try {
        store = getStore(CAP_STORE);
        logDebug('getStore("cap") 创建成功');
        record = await store.get(`token:${tokenKey}`, { type: 'json' });
        logDebug('store.get 完成', { hit: !!record, ms: Date.now() - t0 });
    } catch (err) {
        logError('读取 Cap token 失败（getStore/store.get 抛错）', { name: err?.name, message: err?.message, ms: Date.now() - t0 });
        return { ok: false, error: '人机验证服务暂不可用，请稍后再试' };
    }

    if (!record || typeof record.expires !== 'number') {
        logWarn('token 不存在或缺少 expires', { found: !!record, type: typeof record?.expires });
        return { ok: false, error: '人机验证未通过，请重新提交' };
    }
    if (Number(record.expires) < Date.now()) {
        logWarn('token 已过期', { expires: record.expires, now: Date.now(), diffSec: Math.round((Date.now() - record.expires) / 1000) });
        return { ok: false, error: '人机验证已过期，请刷新页面后重试' };
    }
    logOk('token 校验通过（存在且未过期）');

    // 一次性消费，防止 token 被重放
    try {
        await store.delete(`token:${tokenKey}`);
        logOk('token 已消费（delete 完成）', { ms: Date.now() - t0 });
    } catch (err) {
        logError('消费 Cap token 失败', { name: err?.name, message: err?.message, ms: Date.now() - t0 });
        return { ok: false, error: '人机验证服务暂不可用，请稍后再试' };
    }

    logCap('verifyCapToken 通过，总耗时', `${Date.now() - t0}ms`);
    return { ok: true };
}

function signAppJwt(appId, privateKeyPem) {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = { iat: now - 60, exp: now + 8 * 60, iss: String(appId) };
    const prv = KEYUTIL.getKey(privateKeyPem);
    return KJUR.jws.JWS.sign('RS256', JSON.stringify(header), JSON.stringify(payload), prv);
}

async function ghRequest(path, options = {}) {
    const { token, method = 'GET', body, extraHeaders = {} } = options;
    const headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
        ...extraHeaders
    };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    if (body) headers['Content-Type'] = 'application/json';

    const t0 = Date.now();
    logGh(`→ GitHub ${method} ${path}`);
    const resp = await fetch(`${GH_API}${path}`, {
        method, headers,
        ...(body ? { body: JSON.stringify(body) } : {})
    });
    const ms = Date.now() - t0;

    if (resp.status === 404) { logGh(`← 404（视为不存在，继续）`, `${ms}ms`); return null; }
    if (!resp.ok) {
        const text = await resp.text();
        logError(`← GitHub ${method} ${path} 失败 ${resp.status}`, `${ms}ms · ${text.substring(0, 300)}`);
        throw new Error(`GitHub ${method} ${path} → ${resp.status}: ${text.substring(0, 300)}`);
    }
    if (resp.status === 204) { logGh(`← 204`, `${ms}ms`); return null; }

    const text = await resp.text();
    logGh(`← ${resp.status} ${path}`, `${ms}ms · ${text.length}B`);
    return text ? JSON.parse(text) : null;
}

async function getInstallationToken(jwt, installationId) {
    const data = await ghRequest(`/app/installations/${installationId}/access_tokens`, {
        method: 'POST', token: jwt
    });
    return data.token;
}

async function getFileSha(token, owner, repo, path, branch) {
    const data = await ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(branch)}`, { token });
    return data?.sha || undefined;
}

async function putFile(token, owner, repo, path, contentBase64, message, branch) {
    const sha = await getFileSha(token, owner, repo, path, branch);
    return ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
        method: 'PUT', token,
        body: { message, content: contentBase64, branch, ...(sha ? { sha } : {}) }
    });
}

async function getRef(token, owner, repo, ref) {
    const data = await ghRequest(`/repos/${owner}/${repo}/git/ref/${encodeURIComponent(ref)}`, { token });
    return { sha: data.object.sha };
}

async function createRef(token, owner, repo, ref, sha) {
    return ghRequest(`/repos/${owner}/${repo}/git/refs`, {
        method: 'POST', token,
        body: { ref: `refs/heads/${ref}`, sha }
    });
}

async function readTextFile(token, owner, repo, path, ref) {
    const data = await ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`, { token });
    if (!data || Array.isArray(data) || !data.content) return null;
    try { return decodeURIComponent(escape(atob(data.content))); }
    catch { return atob(data.content); }
}

export async function handler(event) {
    if (event.httpMethod === 'OPTIONS') {
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type'
            },
            body: ''
        };
    }
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }

    const cors = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

    try {
        const t_start = Date.now();
        logStep('handler 开始（收到提交请求）');

        const body = JSON.parse(event.body);
        const {
            slug, name, description, extId, authors, coverExt,
            jsContent, coverContent, docs, docsContent,
            hasSamples, sampleContent, translations,
            version, license, capToken
        } = body;

        // ---- 校验 ----
        if (!slug || !name || !description || !extId || !jsContent || !coverContent || !authors?.length) {
            logWarn('必填字段缺失 → 400', { slug: !!slug, name: !!name, desc: !!description, extId: !!extId, js: !!jsContent, cover: !!coverContent, authors: authors?.length });
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: '缺少必填字段' }) };
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(slug)) {
            logWarn('slug 含非法字符 → 400', { slug });
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'slug 只能包含字母、数字、下划线和连字符' }) };
        }
        logInfo('基础字段校验通过', { slug, name, descLen: description?.length, extId, authors: authors?.length, hasSamples, docs: !!docs });

        // ---- Cap 人机验证（必须通过才开始 GitHub 操作，后端无法被单独调用）----
        const capCheck = await verifyCapToken(capToken);
        if (!capCheck.ok) {
            logWarn('Cap 人机验证未通过 → 401', { error: capCheck.error });
            return { statusCode: 401, headers: cors, body: JSON.stringify({ error: capCheck.error }) };
        }
        logOk('Cap 人机验证通过');

        // ---- 环境变量 ----
        const appId = process.env.GITHUB_APP_ID;
        const privateKey = String(process.env.GITHUB_PRIVATE_KEY).replace(/^﻿/, '');
        const owner = process.env.GITHUB_OWNER;
        const repo = process.env.GITHUB_REPO;
        const installationId = process.env.GITHUB_INSTALLATION_ID;
        const envCheck = { GITHUB_APP_ID: !!appId, GITHUB_PRIVATE_KEY: !!privateKey, GITHUB_OWNER: !!owner, GITHUB_REPO: !!repo, GITHUB_INSTALLATION_ID: !!installationId };
        const missingEnv = Object.entries(envCheck).filter(([, v]) => !v).map(([k]) => k);
        logDebug('环境变量检查', envCheck);

        if (!appId || !privateKey || !owner || !repo || !installationId) {
            logError('环境变量未配置完整 → 500', { missing: missingEnv });
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: `环境变量未配置完整，缺少: ${missingEnv.join(', ')}` }) };
        }
        logOk('环境变量齐全', { owner, repo, appId, installationId });

        // ---- 1. 签 JWT → 换安装令牌 ----
        logStep('① 签发 JWT → 换取安装令牌', { appId, installationId });
        const jwt = signAppJwt(appId, privateKey);
        const token = await getInstallationToken(jwt, Number(installationId));
        logOk('安装令牌获取成功');

        // ---- 2. 获取默认分支 ----
        logStep('② 获取仓库默认分支');
        const repoData = await ghRequest(`/repos/${owner}/${repo}`, { token });
        const baseBranch = repoData.default_branch;
        const { sha: baseSha } = await getRef(token, owner, repo, `heads/${baseBranch}`);
        logOk('基础分支', `${baseBranch}@${baseSha.substring(0, 7)}`);

        // ---- 3. 创建分支 ----
        const branchName = `ext-submit/${slug}-${Date.now()}`;
        logStep('③ 创建独立分支', branchName);
        await createRef(token, owner, repo, branchName, baseSha);
        logOk('分支已创建', branchName);

        // ---- 4. 上传 JS ----
        logStep('④ 上传扩展 JS', `extension/${slug}.js`);
        await putFile(token, owner, repo, `extension/${slug}.js`, jsContent, `feat(${slug}): add extension JS`, branchName);
        logOk('JS 已上传', `extension/${slug}.js`);

        // ---- 5. 上传封面 ----
        const coverFileName = `${slug}.${coverExt}`;
        logStep('⑤ 上传封面', `image/${coverFileName}`);
        await putFile(token, owner, repo, `image/${coverFileName}`, coverContent, `feat(${slug}): add cover image`, branchName);
        logOk('封面已上传', `image/${coverFileName}`);

        // ---- 6. 可选文档 ----
        if (docs && docsContent) {
            logStep('⑥ 上传文档（可选）', `doc/${slug}.html`);
            await putFile(token, owner, repo, `doc/${slug}.html`, docsContent, `feat(${slug}): add documentation`, branchName);
            logOk('文档已上传');
        }

        // ---- 7. 可选实例 ----
        if (hasSamples && sampleContent) {
            logStep('⑦ 上传实例（可选）', `samples/${slug}.sb3`);
            await putFile(token, owner, repo, `samples/${slug}.sb3`, sampleContent, `feat(${slug}): add sample project`, branchName);
            logOk('实例已上传');
        }

        // ---- 8. 更新 extensions.json ----
        logStep('⑧ 更新 extensions.json');
        let extJson;
        let extSha = await getFileSha(token, owner, repo, 'extensions.json', branchName);
        if (extSha) {
            const existing = await readTextFile(token, owner, repo, 'extensions.json', branchName);
            extJson = existing ? JSON.parse(existing) : { extensions: [] };
            logDebug('读取线上 extensions.json', { existed: !!existing, extCount: extJson.extensions?.length });
        } else {
            extJson = { extensions: [] };
            logDebug('extensions.json 不存在，将新建');
        }

        const entry = {
            slug, id: extId, name, description,
            image: coverFileName, by: authors,
            docs: !!docs
        };
        if (hasSamples) entry.samples = [slug];
        if (version) entry.version = version;
        if (license) entry.license = license;
        if (translations?.nameTranslations) entry.nameTranslations = translations.nameTranslations;
        if (translations?.descriptionTranslations) entry.descriptionTranslations = translations.descriptionTranslations;

        const idx = extJson.extensions.findIndex(e => e.slug === slug);
        if (idx >= 0) {
            extJson.extensions[idx] = entry;
            logDebug('extensions.json 中已存在该 slug → 原地更新');
        } else {
            extJson.extensions.push(entry);
            logDebug('extensions.json 新增条目');
        }

        const jsonBase64 = Buffer.from(JSON.stringify(extJson, null, 2), 'utf-8').toString('base64');
        await putFile(token, owner, repo, 'extensions.json', jsonBase64, `feat(${slug}): register extension`, branchName);
        logOk('extensions.json 已更新', `共 ${extJson.extensions.length} 条`);

        // ---- 9. 创建 PR ----
        logStep('⑨ 创建 Pull Request');
        const prBody = [
            `## 📦 新扩展提交`,
            ``,
            `- **Slug:** \`${slug}\``,
            `- **名称:** ${name}`,
            `- **描述:** ${description}`,
            `- **作者:** ${authors.map(a => a.link ? `[@${a.name}](${a.link})` : a.name).join(', ')}`,
            `- **封面:** ${coverFileName}`,
            docs ? `- **文档:** 已选择` : ``,
            hasSamples ? `- **实例作品:** 已选择` : ``,
            ``,
            `---`,
            ``,
            `> 此 PR 由 02Engine ExtBot 自动创建`,
        ].filter(Boolean).join('\n');

        const pr = await ghRequest(`/repos/${owner}/${repo}/pulls`, {
            method: 'POST', token,
            body: {
                title: `feat: 自动提交扩展 ${name} (${slug})`,
                head: branchName,
                base: baseBranch,
                body: prBody
            }
        });

        logOk('PR 创建成功', `#${pr.number} · ${pr.html_url}`);
        logStep('handler 完成（全部成功）', `总耗时 ${Date.now() - t_start}ms`);

        return {
            statusCode: 200,
            headers: cors,
            body: JSON.stringify({
                success: true,
                pullRequestNumber: pr.number,
                pullRequestTitle: pr.title,
                pullRequestUrl: pr.html_url,
                branch: branchName
            })
        };

    } catch (err) {
        logError('handler 异常（→ 500）', { name: err?.name, message: err?.message, stackHead: (err?.stack || '').split('\n').slice(0, 4).join(' | ') });
        return {
            statusCode: 500,
            headers: cors,
            body: JSON.stringify({ error: err.message || '内部服务器错误' })
        };
    }
}
