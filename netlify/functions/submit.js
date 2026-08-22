// ================= 扩展提交函数 =================
import {
    logInfo, logDebug, logWarn, logError, logOk, logStep, logGh,
    verifyCapToken, signAppJwt, ghRequest, getInstallationToken,
    getFileSha, putFile, getRef, createRef, readTextFile,
    readGithubEnv, corsHeaders, errorResponse
} from './_github.js';
import { issueTokenFor } from './_tokens.js';

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

    const cors = corsHeaders;

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
        const { appId, privateKey, owner, repo, installationId, missingEnv } = readGithubEnv();
        logDebug('环境变量检查', { owner, repo, appId });

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

        // ---- 10. 签发扩展更新凭证（SQLite，存于 TOKEN_REPO 仓库）----
        // 凭证签发失败不阻断提交结果，仅在响应中附带 warning 提示。
        let updateToken = null;
        let updateTokenWarning = null;
        const tokenRepo = process.env.TOKEN_REPO;
        if (!tokenRepo) {
            logWarn('TOKEN_REPO 未配置 → 跳过更新凭证签发（该扩展将无法使用在线更新功能）');
            updateTokenWarning = '服务器未配置 TOKEN_REPO，本次提交未生成更新凭证';
        } else {
            logStep('⑩ 签发扩展更新凭证', `extId=${extId}`);
            const issued = await issueTokenFor(token, owner, tokenRepo, extId);
            if (issued.ok) {
                updateToken = issued.token;
                logOk('更新凭证已签发');
            } else {
                updateTokenWarning = `更新凭证签发失败：${issued.error}`;
                logWarn('更新凭证签发失败（不影响 PR）', issued.error);
            }
        }

        logStep('handler 完成（全部成功）', `总耗时 ${Date.now() - t_start}ms`);

        return {
            statusCode: 200,
            headers: cors,
            body: JSON.stringify({
                success: true,
                pullRequestNumber: pr.number,
                pullRequestTitle: pr.title,
                pullRequestUrl: pr.html_url,
                branch: branchName,
                updateToken,
                ...(updateTokenWarning ? { warning: updateTokenWarning } : {})
            })
        };

    } catch (err) {
        return errorResponse(err);
    }
}

