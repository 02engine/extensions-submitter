// ================= 扩展信息查询函数 =================
// 输入扩展 ID，从目标仓库的 extensions.json 中查询该扩展的当前信息。
// 受 Cap 人机验证门控，防止被滥用枚举仓库内容。

import {
    logStep, logWarn, logOk, verifyCapToken, signAppJwt, getInstallationToken,
    readTextFile, readGithubEnv, corsHeaders, preflight, errorResponse, logInfo
} from './_github.js';

export async function handler(event) {
    const pf = preflight(event);
    if (pf) return pf;
    const cors = corsHeaders;

    try {
        const t_start = Date.now();
        logStep('query handler 开始（收到查询请求）');

        const body = JSON.parse(event.body);
        const { extId, capToken } = body;

        if (!extId || typeof extId !== 'string') {
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: '缺少扩展 ID' }) };
        }
        logInfo('查询目标', { extId });

        // ---- Cap 人机验证 ----
        const capCheck = await verifyCapToken(capToken);
        if (!capCheck.ok) {
            return { statusCode: 401, headers: cors, body: JSON.stringify({ error: capCheck.error }) };
        }
        logOk('Cap 人机验证通过');

        // ---- 环境变量 ----
        const { appId, privateKey, owner, repo, installationId, missingEnv } = readGithubEnv();
        if (!appId || !privateKey || !owner || !repo || !installationId) {
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: `环境变量未配置完整，缺少: ${missingEnv.join(', ')}` }) };
        }

        // ---- 换取安装令牌 ----
        const jwt = signAppJwt(appId, privateKey);
        const token = await getInstallationToken(jwt, Number(installationId));

        // ---- 读取 extensions.json ----
        logStep('读取线上 extensions.json');
        const raw = await readTextFile(token, owner, repo, 'extensions.json', 'HEAD');
        if (!raw) {
            return { statusCode: 404, headers: cors, body: JSON.stringify({ error: '目标仓库中不存在 extensions.json' }) };
        }
        const extJson = JSON.parse(raw);
        const entry = extJson.extensions?.find(e => e.id === extId || e.slug === extId);
        if (!entry) {
            logWarn('未找到对应扩展 → 404', { extId });
            return { statusCode: 404, headers: cors, body: JSON.stringify({ error: `未找到扩展 ID 为 "${extId}" 的条目` }) };
        }

        logOk('查询成功', `slug=${entry.slug}`, `总耗时 ${Date.now() - t_start}ms`);
        return {
            statusCode: 200,
            headers: cors,
            body: JSON.stringify({ success: true, extension: entry })
        };

    } catch (err) {
        return errorResponse(err);
    }
}
