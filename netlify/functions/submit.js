import { KJUR, KEYUTIL } from 'jsrsasign';
const GH_API = 'https://api.github.com';

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

    const resp = await fetch(`${GH_API}${path}`, {
        method, headers,
        ...(body ? { body: JSON.stringify(body) } : {})
    });

    if (resp.status === 404) return null;
    if (!resp.ok) {
        const text = await resp.text();
        throw new Error(`GitHub ${method} ${path} → ${resp.status}: ${text.substring(0, 300)}`);
    }
    if (resp.status === 204) return null;

    const text = await resp.text();
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
        const body = JSON.parse(event.body);
        const {
            slug, name, description, extId, authors, coverExt,
            jsContent, coverContent, docs, docsContent,
            hasSamples, sampleContent, translations,
            version, license
        } = body;

        // ---- 校验 ----
        if (!slug || !name || !description || !extId || !jsContent || !coverContent || !authors?.length) {
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: '缺少必填字段' }) };
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(slug)) {
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: 'slug 只能包含字母、数字、下划线和连字符' }) };
        }

        // ---- 环境变量 ----
        const appId = process.env.GITHUB_APP_ID;
        const privateKey = String(process.env.GITHUB_PRIVATE_KEY).replace(/^﻿/, '');
        const owner = process.env.GITHUB_OWNER;
        const repo = process.env.GITHUB_REPO;
        const installationId = process.env.GITHUB_INSTALLATION_ID;

        if (!appId || !privateKey || !owner || !repo || !installationId) {
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: '环境变量未配置完整' }) };
        }

        // ---- 1. 签 JWT → 换安装令牌 ----
        console.log(`[submit] 签发 JWT, App ID=${appId}`);
        const jwt = signAppJwt(appId, privateKey);
        const token = await getInstallationToken(jwt, Number(installationId));
        console.log(`[submit] 安装令牌获取成功`);

        // ---- 2. 获取默认分支 ----
        const repoData = await ghRequest(`/repos/${owner}/${repo}`, { token });
        const baseBranch = repoData.default_branch;
        const { sha: baseSha } = await getRef(token, owner, repo, `heads/${baseBranch}`);
        console.log(`[submit] 基础分支: ${baseBranch}@${baseSha.substring(0, 7)}`);

        // ---- 3. 创建分支 ----
        const branchName = `ext-submit/${slug}-${Date.now()}`;
        await createRef(token, owner, repo, branchName, baseSha);
        console.log(`[submit] 分支已创建: ${branchName}`);

        // ---- 4. 上传 JS ----
        await putFile(token, owner, repo, `extension/${slug}.js`, jsContent, `feat(${slug}): add extension JS`, branchName);
        console.log(`[submit] JS 已上传`);

        // ---- 5. 上传封面 ----
        const coverFileName = `${slug}.${coverExt}`;
        await putFile(token, owner, repo, `image/${coverFileName}`, coverContent, `feat(${slug}): add cover image`, branchName);
        console.log(`[submit] 封面已上传: ${coverFileName}`);

        // ---- 6. 可选文档 ----
        if (docs && docsContent) {
            await putFile(token, owner, repo, `doc/${slug}.html`, docsContent, `feat(${slug}): add documentation`, branchName);
            console.log(`[submit] 文档已上传`);
        }

        // ---- 7. 可选实例 ----
        if (hasSamples && sampleContent) {
            await putFile(token, owner, repo, `samples/${slug}.sb3`, sampleContent, `feat(${slug}): add sample project`, branchName);
            console.log(`[submit] 实例已上传`);
        }

        // ---- 8. 更新 extensions.json ----
        let extJson;
        let extSha = await getFileSha(token, owner, repo, 'extensions.json', branchName);
        if (extSha) {
            const existing = await readTextFile(token, owner, repo, 'extensions.json', branchName);
            extJson = existing ? JSON.parse(existing) : { extensions: [] };
        } else {
            extJson = { extensions: [] };
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
            // 如果已存在该扩展，在原位置更新，不影响其他元素顺序
            extJson.extensions[idx] = entry;
        } else {
            // 否则，将其追加到末尾
            extJson.extensions.push(entry);
        }

        const jsonBase64 = Buffer.from(JSON.stringify(extJson, null, 2), 'utf-8').toString('base64');
        await putFile(token, owner, repo, 'extensions.json', jsonBase64, `feat(${slug}): register extension`, branchName);
        console.log(`[submit] extensions.json 已更新`);

        // ---- 9. 创建 PR ----
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

        console.log(`[submit] PR 创建成功: #${pr.number}`);

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
        console.error('[submit] 错误:', err.message);
        console.error(err.stack);
        return {
            statusCode: 500,
            headers: cors,
            body: JSON.stringify({ error: err.message || '内部服务器错误' })
        };
    }
}
