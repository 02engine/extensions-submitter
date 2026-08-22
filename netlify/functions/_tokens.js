// ================= 扩展更新凭证库（SQLite） =================
// 使用 sql.js（纯 WASM SQLite）在内存中操作数据库文件。
// 数据库文件 tokens.db 存放在独立仓库中（环境变量 TOKEN_REPO 指定，与 GITHUB_OWNER 同账号），
// 每次读写流程：GitHub Contents API 下载 → 内存 SQL 操作 → 整个文件 PUT 回仓库。
//
// 设计说明：
// - token 用 crypto.randomBytes(32) 生成 256 位随机值，仅签发时展示一次
// - 数据库以明文形式保存 token，便于管理员直接查阅/找回凭证

import { randomBytes } from 'node:crypto';
import { getFileBase64, putFile, logToken, logOk, logWarn, logError, logStep } from './_github.js';

const DB_PATH = 'tokens.db';

export const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS update_tokens (
    ext_id     TEXT PRIMARY KEY,
    token      TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER
);
`;

// ---- 加载 sql.js ----
let _SQL = null;
async function getSQL() {
    if (_SQL) return _SQL;
    const initSqlJs = (await import('sql.js')).default;
    // Netlify Functions 运行环境：全局 require 可用，直接 resolve WASM 路径
    const fs = await import('node:fs');
    let wasmBinary;
    try {
        const wasmPath = require.resolve('sql.js/dist/sql-wasm.wasm');
        wasmBinary = fs.readFileSync(wasmPath);
        logToken('sql-wasm.wasm 已加载', `${wasmBinary.length}B`);
    } catch (e) {
        logWarn('无法从 node_modules 读取 sql-wasm.wasm，回退到默认定位', e?.message);
    }
    _SQL = await initSqlJs(wasmBinary ? { wasmBinary } : {});
    return _SQL;
}

// ---- 数据库加载 / 保存（TOKEN_REPO 仓库）----
async function loadDb(githubToken, owner, repo) {
    const SQL = await getSQL();
    const buf = await getFileBase64(githubToken, owner, repo, DB_PATH, 'HEAD');
    if (!buf || buf.length === 0) {
        logToken('tokens.db 不存在 → 新建空库');
        const db = new SQL.Database();
        db.run(SCHEMA_SQL);
        return db;
    }
    logToken('已下载 tokens.db', `${buf.length}B`);
    const db = new SQL.Database(buf);
    db.run(SCHEMA_SQL); // 兼容旧库缺表/缺列的情况
    return db;
}

async function saveDb(githubToken, owner, repo, db) {
    const data = Buffer.from(db.export());
    db.close();
    await putFile(
        githubToken, owner, repo, DB_PATH,
        data.toString('base64'),
        `chore(tokens): update credentials database (${new Date().toISOString()})`,
        'HEAD'
    );
    logOk('tokens.db 已写回凭证仓库', `${data.length}B`);
}

// ---- 对外接口：为扩展 id 签发新更新凭证 ----
// 成功返回 { ok: true, token }；失败返回 { ok: false, error }
export async function issueTokenFor(githubToken, owner, repo, extId) {
    try {
        logStep(`为扩展 ${extId} 签发更新凭证`);
        const db = await loadDb(githubToken, owner, repo);

        const raw = randomBytes(32).toString('base64url'); // 256-bit 高强度随机 token
        const now = Date.now();

        const stmt = db.prepare(
            `INSERT INTO update_tokens (ext_id, token, created_at, updated_at)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(ext_id) DO UPDATE SET token = excluded.token, updated_at = excluded.updated_at`
        );
        stmt.run([extId, raw, now, now]);
        stmt.free();

        await saveDb(githubToken, owner, repo, db);
        logOk('更新凭证已签发并入库', `extId=${extId}`);
        return { ok: true, token: raw };
    } catch (err) {
        logError('签发更新凭证失败', err?.message);
        return { ok: false, error: err.message || '签发更新凭证失败' };
    }
}

// ---- 对外接口：校验扩展 id 对应的更新凭证 ----
// 成功返回 { ok: true }；失败返回 { ok: false, error }
export async function verifyTokenFor(githubToken, owner, repo, extId, inputToken) {
    try {
        if (!inputToken || typeof inputToken !== 'string') {
            return { ok: false, error: '缺少更新凭证（token），请输入提交扩展时获得的凭证' };
        }
        logStep(`校验扩展 ${extId} 的更新凭证`);
        const db = await loadDb(githubToken, owner, repo);
        const stmt = db.prepare('SELECT token FROM update_tokens WHERE ext_id = ?');
        stmt.bind([extId]);
        let row = null;
        if (stmt.step()) row = stmt.getAsObject();
        stmt.free();
        db.close();

        if (!row || !row.token) {
            logWarn('该扩展没有登记的更新凭证 → 拒绝', `extId=${extId}`);
            return { ok: false, error: '该扩展没有登记的更新凭证，请先通过提交页面重新提交' };
        }

        if (String(row.token) !== String(inputToken)) {
            logWarn('更新凭证不匹配 → 拒绝', `extId=${extId}`);
            return { ok: false, error: '更新凭证错误，请核对后重试' };
        }
        logOk('更新凭证校验通过', `extId=${extId}`);
        return { ok: true };
    } catch (err) {
        logError('校验更新凭证失败', err?.message);
        return { ok: false, error: err.message || '校验更新凭证失败' };
    }
}
