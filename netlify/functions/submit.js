// Netlify Function: 接收前端提交，生成文件，通过 GitHub App 创建 PR
// 使用 JWT + REST API 方式，避免 @octokit/app 在 Netlify 的兼容性问题

import { createSign, createVerify } from 'crypto';

// ---- 环境变量（在 Netlify 后台设置）----
// GITHUB_APP_ID          - GitHub App 的 App ID
// GITHUB_PRIVATE_KEY     - GitHub App 的私钥（PEM 格式，\n 转义）
// GITHUB_OWNER           - 仓库所有者
// GITHUB_REPO            - 仓库名称
// GITHUB_INSTALLATION_ID - App 安装 ID

// ---- JWT 相关 ----
function base64url(input) {
    let str;
    if (typeof input === 'string') {
        str = input;
    } else {
        str = input.toString('base64');
    }
    return str.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function createJWT(appId, privateKey) {
    const header = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iat: now - 60,           // 提前60秒，防止时钟偏差
        exp: now + 60 * 10,      // 10分钟过期
        iss: String(appId)
    };

    const headerB64 = base64url(JSON.stringify(header));
    const payloadB64 = base64url(JSON.stringify(payload));
    const data = headerB64 + '.' + payloadB64;

    const sign = createSign('RSA-SHA256');
    sign.update(data);
    const signature = base64url(sign.sign(privateKey));

    return data + '.' + signature;
}

// ---- 获取安装访问令牌 ----
async function getInstallationToken(jwt, installationId) {
    const resp = await fetch(
        `https://api.github.com/app/installations/${installationId}/access_tokens`,
        {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${jwt}`,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28'
            }
        }
    );

    if (!resp.ok) {
        const errText = await resp.text();
        throw new Error('获取安装令牌失败: ' + resp.status + ' ' + errText);
    }

    const data = await resp.json();
    return data.token;
}

// ---- GitHub API 请求封装 ----
async function githubRequest(token, method, path, body) {
    const url = `https://api.github.com${path}`;
    const headers = {
        'Authorization': `Bearer ${token}`,
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28'
    };

    const opts = { method, headers };
    if (body !== undefined) {
        headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
    }

    const resp = await fetch(url, opts);

    if (resp.status === 204) return null; // No Content

    const text = await resp.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch(e) {}

    if (!resp.ok) {
        throw new Error(`GitHub API ${method} ${path} → ${resp.status}: ${text.substring(0, 300)}`);
    }

    return data;
}

// ---- 主处理函数 ----
export async function handler(event, context) {
    // CORS 预检
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

    // 仅允许 POST
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: JSON.stringify({ error: 'Method Not Allowed' }) };
    }

    // 添加 CORS 头到所有响应
    const corsHeaders = {
        'Access-Control-Allow-Origin': '*',
        'Content-Type': 'application/json'
    };

    try {
        const body = JSON.parse(event.body);
        const {
            slug, name, description, extId,
            version, license, authors,
            coverExt, jsContent, coverContent,
            docs, docsContent, hasSamples, sampleContent,
            translations
        } = body;

        // ---- 基本校验 ----
        if (!slug || !name || !description || !extId) {
            return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: '缺少必填字段（slug/name/description/extId）' }) };
        }
        if (!jsContent || !coverContent) {
            return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: '缺少 JS 或封面文件内容' }) };
        }
        if (!authors || authors.length === 0) {
            return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: '至少需要一位作者' }) };
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(slug)) {
            return { statusCode: 400, headers: corsHeaders, body: JSON.stringify({ error: 'Slug 只能包含字母、数字、下划线和连字符' }) };
        }

        // ---- 初始化 GitHub 认证 ----
        const appId = process.env.GITHUB_APP_ID;
        const privateKeyRaw = process.env.GITHUB_PRIVATE_KEY;
        const owner = process.env.GITHUB_OWNER;
        const repo = process.env.GITHUB_REPO;
        const installationId = process.env.GITHUB_INSTALLATION_ID;

        // 逐个检查环境变量（空字符串/纯空白同样视为未配置），并准确报出缺失项。
        // 若在 Netlify 上已配置却仍报"未配置"，请检查：
        //  1) 环境变量作用域是否包含 Functions（不要只选 Builds）；
        //  2) 改完环境变量后是否重新触发部署（函数的环境变量在部署时注入）；
        //  3) 是否填的是空格或空字符串，读入后会被 trim 判空。
        const envCheck = {
            'GITHUB_APP_ID': process.env.GITHUB_APP_ID,
            'GITHUB_PRIVATE_KEY': privateKeyRaw,
            'GITHUB_OWNER': owner,
            'GITHUB_REPO': repo,
            'GITHUB_INSTALLATION_ID': installationId
        };
        const missingEnv = Object.keys(envCheck).filter((k) => !String(envCheck[k] || '').trim());

        if (missingEnv.length > 0) {
            console.error('[submit] 服务器环境变量未配置: ' + missingEnv.join(', '));
            return {
                statusCode: 500,
                headers: corsHeaders,
                body: JSON.stringify({
                    error: '服务器环境变量未配置完整，缺少: ' + missingEnv.join(', '),
                    missing: missingEnv
                })
            };
        }

        // 兼容多种私钥换行转义形式：
        // 真实换行、字面 \r\n / \r / \\n（双反斜杠+n）/ \n（单反斜杠+n）
        const privateKey = String(privateKeyRaw)
            .replace(/\r\n/g, '\n')
            .replace(/\r/g, '')
            .replace(/\\n/g, '\n')
            .replace(/\n/g, '\n');

        console.log(`[submit] 开始处理: slug=${slug}, name=${name}`);

        // 创建 JWT → 换安装令牌
        const jwt = createJWT(appId, privateKey);
        const token = await getInstallationToken(jwt, installationId);
        console.log('[submit] 安装令牌获取成功');

        // ---- 获取默认分支信息 ----
        const repoData = await githubRequest(token, 'GET', `/repos/${owner}/${repo}`);
        const defaultBranch = repoData.default_branch;
        console.log(`[submit] 默认分支: ${defaultBranch}`);

        const refData = await githubRequest(token, 'GET', `/repos/${owner}/${repo}/git/refs/heads/${defaultBranch}`);
        const baseSha = refData.object.sha;
        console.log(`[submit] 基础 SHA: ${baseSha.substring(0, 7)}`);

        // ---- 创建新分支 ----
        const timestamp = Date.now();
        const branchName = `ext-submit/${slug}-${timestamp}`;
        await githubRequest(token, 'POST', `/repos/${owner}/${repo}/git/refs`, {
            ref: `refs/heads/${branchName}`,
            sha: baseSha
        });
        console.log(`[submit] 分支已创建: ${branchName}`);

        // ---- 上传扩展 JS ----
        await uploadFile(token, owner, repo, `extensions/${slug}.js`, jsContent, branchName, `feat(${slug}): add extension JS`);
        console.log(`[submit] JS 文件已上传`);

        // ---- 上传封面图 ----
        const coverFileName = `${slug}.${coverExt}`;
        await uploadFile(token, owner, repo, `images/${coverFileName}`, coverContent, branchName, `feat(${slug}): add cover image`);
        console.log(`[submit] 封面图已上传: ${coverFileName}`);

        // ---- 可选：上传文档 HTML ----
        if (docs && docsContent) {
            await uploadFile(token, owner, repo, `docs/${slug}.html`, docsContent, branchName, `feat(${slug}): add documentation`);
            console.log(`[submit] 文档已上传`);
        }

        // ---- 可选：上传实例作品 .sb3 ----
        if (hasSamples && sampleContent) {
            await uploadFile(token, owner, repo, `samples/${slug}.sb3`, sampleContent, branchName, `feat(${slug}): add sample project`);
            console.log(`[submit] 实例作品已上传`);
        }

        // ---- 读取并更新 extensions.json ----
        let extJson, extSha;
        try {
            const jsonData = await githubRequest(token, 'GET', `/repos/${owner}/${repo}/contents/extensions.json?ref=${branchName}`);
            extJson = JSON.parse(Buffer.from(jsonData.content, 'base64').toString('utf-8'));
            extSha = jsonData.sha;
        } catch (e) {
            console.log('[submit] extensions.json 不存在，创建新文件');
            extJson = { extensions: [] };
            extSha = undefined;
        }

        // 构建新扩展条目
        const newEntry = {
            slug: slug,
            id: extId,
            name: name,
            description: description,
            image: coverFileName,
            by: authors
        };

        // 翻译
        if (translations) {
            if (translations.nameTranslations) {
                newEntry.nameTranslations = translations.nameTranslations;
            }
            if (translations.descriptionTranslations) {
                newEntry.descriptionTranslations = translations.descriptionTranslations;
            }
        }

        // 文档
        newEntry.docs = !!docs;

        // 实例
        if (hasSamples) {
            newEntry.samples = [slug];
        }

        // 版本
        if (version) newEntry.version = version;

        // 许可证
        if (license) newEntry.license = license;

        // 检查是否已存在同名 slug，存在则替换
        const existingIdx = extJson.extensions.findIndex(e => e.slug === slug);
        if (existingIdx >= 0) {
            console.log(`[submit] 替换已有扩展: ${slug}`);
            extJson.extensions[existingIdx] = newEntry;
        } else {
            extJson.extensions.push(newEntry);
        }

        // 按 slug 排序
        extJson.extensions.sort((a, b) => a.slug.localeCompare(b.slug));

        // 上传更新后的 extensions.json
        const jsonContent = Buffer.from(JSON.stringify(extJson, null, 2), 'utf-8').toString('base64');
        await githubRequest(token, 'PUT', `/repos/${owner}/${repo}/contents/extensions.json`, {
            message: `feat(${slug}): register extension in extensions.json`,
            content: jsonContent,
            branch: branchName,
            sha: extSha
        });
        console.log(`[submit] extensions.json 已更新`);

        // ---- 创建 Pull Request ----
        const prTitle = `feat: 提交扩展 ${name} (${slug})`;
        let prBody = `## 📦 新扩展提交\n\n`;
        prBody += `- **Slug:** \`${slug}\`\n`;
        prBody += `- **名称:** ${name}\n`;
        prBody += `- **描述:** ${description}\n`;
        prBody += `- **作者:** ${authors.map(a => a.link ? `[@${a.name}](${a.link})` : a.name).join(', ')}\n`;
        prBody += `- **封面:** ${coverFileName} (已自动裁剪为 2:1)\n`;
        if (docs) prBody += `- **文档:** ✅ 已附上\n`;
        if (hasSamples) prBody += `- **实例作品:** ✅ 已附上\n`;
        prBody += `\n---\n\n> 此 PR 由 Scratch 扩展提交工具自动创建 🤖\n\n`;
        prBody += `请审查以下内容：\n`;
        prBody += `1. 扩展 JS 文件是否正常运行\n`;
        prBody += `2. 封面图片显示是否正确\n`;
        prBody += `3. 描述信息是否准确\n`;
        prBody += `4. 作者信息是否完整\n`;

        const pr = await githubRequest(token, 'POST', `/repos/${owner}/${repo}/pulls`, {
            title: prTitle,
            head: branchName,
            base: defaultBranch,
            body: prBody
        });

        console.log(`[submit] PR 创建成功: #${pr.number}`);

        return {
            statusCode: 200,
            headers: corsHeaders,
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
            headers: corsHeaders,
            body: JSON.stringify({
                error: err.message || '内部服务器错误'
            })
        };
    }
}

// ---- 上传/更新文件 ----
async function uploadFile(token, owner, repo, path, contentBase64, branch, message) {
    // 检查文件是否已存在
    let fileSha = undefined;
    try {
        const data = await githubRequest(token, 'GET', `/repos/${owner}/${repo}/contents/${path}?ref=${branch}`);
        if (data && data.sha) fileSha = data.sha;
    } catch (e) {
        // 文件不存在，正常
    }

    const body = {
        message: message,
        content: contentBase64,
        branch: branch
    };
    if (fileSha) body.sha = fileSha;

    await githubRequest(token, 'PUT', `/repos/${owner}/${repo}/contents/${path}`, body);
}
