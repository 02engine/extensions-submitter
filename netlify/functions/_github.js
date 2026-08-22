// ================= 共享工具模块 =================
// 从 submit.js 抽取的通用逻辑：超级日志、Cap 验证、GitHub App 认证与 Contents API 封装。
// 被 submit.js / query.js / update.js 共同引用。

import { KJUR, KEYUTIL } from 'jsrsasign';
import { createHmac, timingSafeEqual } from 'node:crypto';

export const GH_API = 'https://api.github.com';

// ================= 超级日志工具 =================
// 统一输出格式：[时间] [+耗时] [级别] 消息 附加信息
const LOG_START = Date.now();
let __seq = 0;
function _pad(n) { return String(n).padStart(2, '0'); }
function _ts() {
    const d = new Date();
    return `${d.getFullYear()}-${_pad(d.getMonth() + 1)}-${_pad(d.getDate())} ${_pad(d.getHours())}:${_pad(d.getMinutes())}:${_pad(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}
export const _ICON = { INFO: '🗒️', DEBUG: '🔵', WARN: '🟡', ERROR: '🔴', OK: '✅', STEP: '⚙️', GH: '🐙', CAP: '🛡️', BLOB: '📦', ENV: '🔑', JWT: '🎫', API: '☁️', TOKEN: '🔐' };
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
export const logInfo  = (m, e) => _log('INFO',  'INFO', m, e);
export const logDebug = (m, e) => _log('INFO',  'DEBUG', m, e);
export const logWarn  = (m, e) => _log('WARN',  'WARN', m, e);
export const logError = (m, e) => _log('ERROR', 'ERROR', m, e);
export const logOk    = (m, e) => _log('INFO',  'OK', m, e);
export const logStep  = (m, e) => _log('INFO',  'STEP', m, e);
export const logGh    = (m, e) => _log('INFO',  'GH', m, e);
export const logCap   = (m, e) => _log('INFO',  'CAP', m, e);
export const logToken = (m, e) => _log('INFO',  'TOKEN', m, e);

// ---- Cap 人机验证 ----
// 无状态签名凭证方案（不依赖 Netlify Blobs）：
// cap.js 验证真实 PoW 求解后，用共享 CAP_SECRET 对 payload 做 HMAC-SHA256 签名
// 生成自包含 token。各函数用同一把 CAP_SECRET 独立验证签名与过期时间。
export const CAP_SCOPE = 'submit';   // 与 cap.js 的 scope 必须一致

// 校验前端经过 Cap 人机验证后签发的一次性凭证 token。
// 只有带有效 token 的请求才允许继续调用后端，否则一律拒绝 —— 保证后端无法被单独使用。
// 依赖环境变量 CAP_SECRET（与 cap.js 保持一致）。
export async function verifyCapToken(capToken) {
    const t0 = Date.now();
    logCap('verifyCapToken 开始（校验前端一次性凭证）');

    const secret = process.env.CAP_SECRET;
    if (!secret) {
        logError('CAP_SECRET 未配置 → 拒绝所有人机验证');
        return { ok: false, error: '服务器环境变量未配置完整，缺少: CAP_SECRET' };
    }

    if (!capToken || typeof capToken !== 'string') {
        logWarn('缺少 capToken → 拒绝');
        return { ok: false, error: '缺少人机验证凭证，请稍后重试' };
    }

    // token 格式: "<payload>.<sig>"，payload = "cap:v1:<scope>:<expires>"
    // 通过重新计算 HMAC-SHA256(CAP_SECRET, payload) 与 token 中的 sig 比对来验证真实性。
    const parts = capToken.split('.');
    if (parts.length !== 2) {
        logWarn('capToken 格式非法（应为 payload.sig）', { segCnt: parts.length });
        return { ok: false, error: '人机验证凭证无效' };
    }
    const payload = parts[0];
    const sig = parts[1];
    const expectedSig = createHmac('sha256', secret).update(payload).digest('hex');
    const actualSig = Buffer.isBuffer(sig)
        ? sig
        : Buffer.from(String(sig), 'hex');
    const expected = Buffer.from(expectedSig, 'hex');
    if (actualSig.length !== expected.length || !timingSafeEqual(actualSig, expected)) {
        logWarn('capToken 签名不匹配 → 拒绝（凭证伪造或密钥不一致）');
        return { ok: false, error: '人机验证凭证无效' };
    }

    // 解析 payload：v:<1>:<scope>:<expires>
    const payloadParts = String(payload).split(':');
    if (
        payloadParts.length !== 4 ||
        payloadParts[0] !== 'cap' ||
        payloadParts[1] !== 'v1' ||
        payloadParts[2] !== CAP_SCOPE
    ) {
        logWarn('capToken payload 结构异常', { payloadParts });
        return { ok: false, error: '人机验证凭证无效' };
    }
    const expires = Number(payloadParts[3]);
    if (!Number.isFinite(expires) || expires < Date.now()) {
        logWarn('capToken 已过期', { expires, now: Date.now(), diffSec: Math.round((Date.now() - expires) / 1000) });
        return { ok: false, error: '人机验证已过期，请刷新页面后重试' };
    }

    logOk('capToken 签名有效且未过期', `剩余 ${Math.round((expires - Date.now()) / 1000)}s`);
    logCap('verifyCapToken 通过，总耗时', `${Date.now() - t0}ms`);
    return { ok: true };
}

export function signAppJwt(appId, privateKeyPem) {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: 'RS256', typ: 'JWT' };
    const payload = { iat: now - 60, exp: now + 8 * 60, iss: String(appId) };
    const prv = KEYUTIL.getKey(privateKeyPem);
    return KJUR.jws.JWS.sign('RS256', JSON.stringify(header), JSON.stringify(payload), prv);
}

export async function ghRequest(path, options = {}) {
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

export async function getInstallationToken(jwt, installationId) {
    const data = await ghRequest(`/app/installations/${installationId}/access_tokens`, {
        method: 'POST', token: jwt
    });
    return data.token;
}

// 获取文件内容（base64），不存在返回 null。用于二进制文件（如 SQLite 数据库、图片）。
export async function getFileBase64(token, owner, repo, path, ref) {
    const data = await ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`, { token });
    if (!data || Array.isArray(data) || !data.content) return null;
    return Buffer.from(data.content, 'base64');
}

export async function getFileSha(token, owner, repo, path, branch) {
    const data = await ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(branch)}`, { token });
    return data?.sha || undefined;
}

export async function putFile(token, owner, repo, path, contentBase64, message, branch) {
    const sha = await getFileSha(token, owner, repo, path, branch);
    return ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
        method: 'PUT', token,
        body: { message, content: contentBase64, branch, ...(sha ? { sha } : {}) }
    });
}



export async function deleteFile(token, owner, repo, path, message, branch) {
    const sha = await getFileSha(token, owner, repo, path, branch);
    if (!sha) { logDebug('deleteFile：文件不存在，跳过', path); return null; }
    return ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}`, {
        method: 'DELETE', token,
        body: { message, sha, branch }
    });
}

export async function getRef(token, owner, repo, ref) {
    const data = await ghRequest(`/repos/${owner}/${repo}/git/ref/${encodeURIComponent(ref)}`, { token });
    return { sha: data.object.sha };
}

export async function createRef(token, owner, repo, ref, sha) {
    return ghRequest(`/repos/${owner}/${repo}/git/refs`, {
        method: 'POST', token,
        body: { ref: `refs/heads/${ref}`, sha }
    });
}

export async function readTextFile(token, owner, repo, path, ref) {
    const data = await ghRequest(`/repos/${owner}/${repo}/contents/${encodeURIComponent(path)}?ref=${encodeURIComponent(ref)}`, { token });
    if (!data || Array.isArray(data) || !data.content) return null;
    try { return decodeURIComponent(escape(atob(data.content))); }
    catch { return atob(data.content); }
}

// ---- 公共环境变量读取与校验 ----
export function readGithubEnv() {
    const appId = process.env.GITHUB_APP_ID;
    const privateKey = String(process.env.GITHUB_PRIVATE_KEY || '').replace(/^﻿/, '');
    const owner = process.env.GITHUB_OWNER;
    const repo = process.env.GITHUB_REPO;
    const installationId = process.env.GITHUB_INSTALLATION_ID;
    const envCheck = { GITHUB_APP_ID: !!appId, GITHUB_PRIVATE_KEY: !!privateKey, GITHUB_OWNER: !!owner, GITHUB_REPO: !!repo, GITHUB_INSTALLATION_ID: !!installationId };
    const missingEnv = Object.entries(envCheck).filter(([, v]) => !v).map(([k]) => k);
    logDebug('环境变量检查', envCheck);
    return { appId, privateKey, owner, repo, installationId, missingEnv };
}

// 标准 OPTIONS / 方法校验
export function preflight(event) {
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
    return null;
}

// 统一 CORS 响应头与异常兜底响应
export const corsHeaders = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

export function errorResponse(err) {
    logError('handler 异常（→ 500）', { name: err?.name, message: err?.message, stackHead: (err?.stack || '').split('\n').slice(0, 4).join(' | ') });
    return {
        statusCode: 500,
        headers: corsHeaders,
        body: JSON.stringify({ error: err.message || '内部服务器错误' })
    };
}
