// ================= 扩展更新函数 =================
// 凭证校验通过后，按正常提交逻辑（建分支 → 上传文件 → 更新 extensions.json → 发 PR）更新已有扩展。
// 未重新上传的文件保留线上旧文件；封面更换格式时自动删除旧封面。

import {
    logStep, logWarn, logOk, logInfo, logError,
    verifyCapToken, signAppJwt, getInstallationToken, ghRequest,
    putFile, deleteFile, getRef, createRef, readTextFile,
    readGithubEnv, corsHeaders, preflight, errorResponse
} from './_github.js';
import { verifyTokenFor } from './_tokens.js';

export async function handler(event) {
    const pf = preflight(event);
    if (pf) return pf;
    const cors = corsHeaders;

    try {
        const t_start = Date.now();
        logStep('update handler 开始（收到更新请求）');

        const body = JSON.parse(event.body);
        const {
            extId, name, description, authors,
            version, license, translations,
            coverExt, coverContent, jsContent, docsContent, sampleContent,
            removeDocs, removeSamples,
            updateToken, capToken
        } = body;

        // ---- 校验 ----
        if (!extId || !name || !description || !authors?.length) {
            logWarn('必填字段缺失 → 400', { extId: !!extId, name: !!name, desc: !!description, authors: authors?.length });
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: '缺少必填字段' }) };
        }
        if (coverContent && !coverExt) {
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: '上传了封面但缺少封面格式（coverExt）' }) };
        }
        logInfo('基础字段校验通过', { extId, name, descLen: description?.length, hasJs: !!jsContent, hasCover: !!coverContent });

        // ---- Cap 人机验证 ----
        const capCheck = await verifyCapToken(capToken);
        if (!capCheck.ok) {
            return { statusCode: 401, headers: cors, body: JSON.stringify({ error: capCheck.error }) };
        }
        logOk('Cap 人机验证通过');

        // ---- 环境变量 ----
        const { appId, privateKey, owner, repo, installationId, missingEnv } = readGithubEnv();
        const tokenRepo = process.env.TOKEN_REPO;
        const allMissing = missingEnv.concat(tokenRepo ? [] : ['TOKEN_REPO']);
        if (allMissing.length) {
            logError('环境变量未配置完整 → 500', { missing: allMissing });
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: `环境变量未配置完整，缺少: ${allMissing.join(', ')}` }) };
        }
        logOk('环境变量齐全', { owner, repo, tokenRepo });

        // ---- 1. 签 JWT → 换安装令牌 ----
        logStep('① 签发 JWT → 换取安装令牌');
        const jwt = signAppJwt(appId, privateKey);
        const token = await getInstallationToken(jwt, Number(installationId));
        logOk('安装令牌获取成功');

        // ---- 2. 校验更新凭证（SQLite 凭证库）----
        logStep('② 校验扩展更新凭证');
        const v = await verifyTokenFor(token, owner, tokenRepo, extId, updateToken);
        if (!v.ok) {
            return { statusCode: 401, headers: cors, body: JSON.stringify({ error: v.error }) };
        }

        // ---- 3. 读取原条目，确定 slug ----
        logStep('③ 查询原条目');
        const raw = await readTextFile(token, owner, repo, 'extensions.json', 'HEAD');
        if (!raw) {
            return { statusCode: 404, headers: cors, body: JSON.stringify({ error: '目标仓库中不存在 extensions.json，无法更新' }) };
        }
        const extJson = JSON.parse(raw);
        const idx = extJson.extensions?.findIndex(e => e.id === extId || e.slug === extId);
        if (idx === undefined || idx < 0) {
            logWarn('未找到对应扩展 → 404', { extId });
            return { statusCode: 404, headers: cors, body: JSON.stringify({ error: `未找到扩展 ID 为 "${extId}" 的条目` }) };
        }

        const oldEntry = extJson.extensions[idx];
        const slug = oldEntry.slug;
        logOk('已定位原条目', `slug=${slug}`);

        // ---- 4. 默认分支 + 创建独立分支 ----
        const repoData = await ghRequest(`/repos/${owner}/${repo}`, { token });
        const baseBranch = repoData.default_branch;
        const { sha: baseSha } = await getRef(token, owner, repo, `heads/${baseBranch}`);
        const branchName = `ext-update/${slug}-${Date.now()}`;
        logStep('④ 创建独立分支', `${branchName} ← ${baseBranch}@${baseSha.substring(0, 7)}`);
        await createRef(token, owner, repo, branchName, baseSha);

        // ---- 5. 上传文件（未提供则保留旧文件）----
        if (jsContent) {
            logStep('⑤.a 更新扩展 JS', `extension/${slug}.js`);
            await putFile(token, owner, repo, `extension/${slug}.js`, jsContent, `feat(${slug}): update extension JS`, branchName);
            logOk('JS 已更新');
        } else {
            logInfo('未提供新 JS → 保留旧文件');
        }

        if (coverContent) {
            const newCoverName = `${slug}.${coverExt}`;
            const newCoverPath = `image/${newCoverName}`;
            const oldCoverPath = oldEntry.image ? `image/${oldEntry.image}` : null;
            logStep('⑤.b 更新封面', newCoverPath);
            await putFile(token, owner, repo, newCoverPath, coverContent, `feat(${slug}): update cover image`, branchName);
            logOk('封面已更新');
            if (oldCoverPath && oldCoverPath !== newCoverPath) {
                await deleteFile(token, owner, repo, oldCoverPath, `feat(${slug}): remove old cover image`, branchName);
                logOk('旧封面已删除', oldCoverPath);
            }
        } else {
            logInfo('未提供新封面 → 保留旧图片');
        }

        if (docsContent) {
            logStep('⑤.c 更新文档', `doc/${slug}.html`);
            await putFile(token, owner, repo, `doc/${slug}.html`, docsContent, `feat(${slug}): update documentation`, branchName);
            logOk('文档已更新');
        } else if (removeDocs) {
            await deleteFile(token, owner, repo, `doc/${slug}.html`, `feat(${slug}): remove documentation`, branchName);
            logOk('文档已删除');
        }

        if (sampleContent) {
            logStep('⑤.d 更新实例', `samples/${slug}.sb3`);
            await putFile(token, owner, repo, `samples/${slug}.sb3`, sampleContent, `feat(${slug}): update sample project`, branchName);
            logOk('实例已更新');
        } else if (removeSamples) {
            await deleteFile(token, owner, repo, `samples/${slug}.sb3`, `feat(${slug}): remove sample project`, branchName);
            logOk('实例已删除');
        }

        // ---- 6. 更新 extensions.json ----
        logStep('⑥ 更新 extensions.json');
        const entry = {
            ...oldEntry,
            id: extId, name, description,
            by: authors,
            image: coverContent ? `${slug}.${coverExt}` : (oldEntry.image || `${slug}.png`),
            docs: removeDocs ? false : (docsContent ? true : !!oldEntry.docs)
        };
        if ((sampleContent || oldEntry.samples) && !removeSamples) entry.samples = oldEntry.samples || [slug];
        else delete entry.samples;
        if (version) entry.version = version; else delete entry.version;
        if (license) entry.license = license; else delete entry.license;
        if (translations?.nameTranslations) entry.nameTranslations = translations.nameTranslations;
        if (translations?.descriptionTranslations) entry.descriptionTranslations = translations.descriptionTranslations;

        extJson.extensions[idx] = entry;
        const jsonBase64 = Buffer.from(JSON.stringify(extJson, null, 2), 'utf-8').toString('base64');
        await putFile(token, owner, repo, 'extensions.json', jsonBase64, `feat(${slug}): update extension registration`, branchName);
        logOk('extensions.json 已更新');

        // ---- 7. 创建 PR ----
        logStep('⑦ 创建 Pull Request');
        const prBody = [
            `## 🔄 扩展更新`,
            ``,
            `- **Slug:** \`${slug}\``,
            `- **名称:** ${name}`,
            `- **描述:** ${description}`,
            `- **作者:** ${authors.map(a => a.link ? `[@${a.name}](${a.link})` : a.name).join(', ')}`,
            `- **JS:** ${jsContent ? '已更新' : '未变更'}`,
            `- **封面:** ${coverContent ? '已更新' : '未变更'}`,
            removeDocs ? `- **文档:** 已移除` : (docsContent ? `- **文档:** 已更新` : ``),
            removeSamples ? `- **实例:** 已移除` : (sampleContent ? `- **实例:** 已更新` : ``),
            ``,
            `---`,
            ``,
            `> 此 PR 由 02Engine ExtBot 自动创建（更新请求已通过更新凭证验证）`,
        ].filter(Boolean).join('\n');

        const pr = await ghRequest(`/repos/${owner}/${repo}/pulls`, {
            method: 'POST', token,
            body: {
                title: `feat: 更新扩展 ${name} (${slug})`,
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
        return errorResponse(err);
    }
}
