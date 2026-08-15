import { App } from "@octokit/app";

// ---- 环境变量 ----
// GITHUB_APP_ID / GITHUB_PRIVATE_KEY(PKCS#8明文) / GITHUB_OWNER / GITHUB_REPO / GITHUB_INSTALLATION_ID

async function getInstallOctokit(appId, privateKey, installationId) {
    const app = new App({ appId: Number(appId), privateKey });
    return await app.getInstallationOctokit(Number(installationId));
}

// ---- GitHub 内容上传封装（用 octokit 实例）----
async function uploadFile(octokit, owner, repo, path, contentBase64, branch, message) {
    let sha;
    try {
        const { data } = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", {
            owner, repo, path, ref: branch
        });
        sha = data.sha;
    } catch (_) { /* 新文件 */ }

    await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
        owner, repo, path,
        message, content: contentBase64, branch,
        ...(sha ? { sha } : {})
    });
}

export async function handler(event) {
    if (event.httpMethod === "OPTIONS") {
        return { statusCode: 200, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" }, body: "" };
    }
    if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method Not Allowed" };

    const cors = { "Access-Control-Allow-Origin": "*", "Content-Type": "application/json" };

    try {
        const body = JSON.parse(event.body);
        const { slug, name, description, extId, authors, coverExt, jsContent, coverContent,
                docs, docsContent, hasSamples, sampleContent, translations,
                version, license } = body;

        if (!slug || !name || !description || !extId || !jsContent || !coverContent || !authors?.length)
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "缺少必填字段" }) };
        if (!/^[a-zA-Z0-9_-]+$/.test(slug))
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "slug 非法" }) };

        const appId = process.env.GITHUB_APP_ID;
        const privateKey = String(process.env.GITHUB_PRIVATE_KEY)
            .replace(/^﻿/, "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").trim() + "\n";
        const owner = process.env.GITHUB_OWNER;
        const repo = process.env.GITHUB_REPO;
        const installationId = process.env.GITHUB_INSTALLATION_ID;

        if (!appId || !privateKey || !owner || !repo || !installationId)
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: "环境变量不全" }) };

        if (!privateKey.includes("-----BEGIN PRIVATE KEY-----"))
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: "私钥必须是 PKCS#8（BEGIN PRIVATE KEY），请先 openssl pkcs8 转换" }) };

        // 拿安装级 octokit（自动管 JWT + 安装令牌）
        const octokit = await getInstallOctokit(appId, privateKey, installationId);

        // 默认分支 + base sha
        const { data: repoData } = await octokit.request("GET /repos/{owner}/{repo}", { owner, repo });
        const base = repoData.default_branch;
        const { data: refData } = await octokit.request("GET /repos/{owner}/{repo}/git/refs/heads/{branch}", { owner, repo, branch: base });
        const baseSha = refData.object.sha;

        const branchName = `ext-submit/${slug}-${Date.now()}`;
        await octokit.request("POST /repos/{owner}/{repo}/git/refs", {
            owner, repo, ref: `refs/heads/${branchName}`, sha: baseSha
        });

        await uploadFile(octokit, owner, repo, `extensions/${slug}.js`, jsContent, branchName, `feat(${slug}): add extension JS`);
        const coverFileName = `${slug}.${coverExt}`;
        await uploadFile(octokit, owner, repo, `images/${coverFileName}`, coverContent, branchName, `feat(${slug}): add cover image`);
        if (docs && docsContent) await uploadFile(octokit, owner, repo, `docs/${slug}.html`, docsContent, branchName, `feat(${slug}): add docs`);
        if (hasSamples && sampleContent) await uploadFile(octokit, owner, repo, `samples/${slug}.sb3`, sampleContent, branchName, `feat(${slug}): add sample`);

        // extensions.json
        let extJson, extSha;
        try {
            const { data } = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}?ref={branch}", {
                owner, repo, path: "extensions.json", branch: branchName
            });
            extJson = JSON.parse(Buffer.from(data.content, "base64").toString("utf8"));
            extSha = data.sha;
        } catch (_) { extJson = { extensions: [] }; }

        const entry = { slug, id: extId, name, description, image: coverFileName, by: authors, docs: !!docs };
        if (hasSamples) entry.samples = [slug];
        if (version) entry.version = version;
        if (license) entry.license = license;
        if (translations?.nameTranslations) entry.nameTranslations = translations.nameTranslations;
        if (translations?.descriptionTranslations) entry.descriptionTranslations = translations.descriptionTranslations;

        const idx = extJson.extensions.findIndex(e => e.slug === slug);
        if (idx >= 0) extJson.extensions[idx] = entry; else extJson.extensions.push(entry);
        extJson.extensions.sort((a, b) => a.slug.localeCompare(b.slug));

        await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
            owner, repo, path: "extensions.json",
            message: `feat(${slug}): register extension`,
            content: Buffer.from(JSON.stringify(extJson, null, 2)).toString("base64"),
            branch: branchName, ...(extSha ? { sha: extSha } : {})
        });

        const { data: pr } = await octokit.request("POST /repos/{owner}/{repo}/pulls", {
            owner, repo,
            title: `feat: 提交扩展 ${name} (${slug})`,
            head: branchName, base,
            body: `## 新扩展提交\n- Slug: \`${slug}\`\n- 作者: ${authors.map(a => a.name).join(", ")}`
        });

        return { statusCode: 200, headers: cors, body: JSON.stringify({ success: true, pullRequestNumber: pr.number, pullRequestUrl: pr.html_url, branch: branchName }) };
    } catch (err) {
        console.error("[submit] 错误:", err.message);
        return { statusCode: 500, headers: cors, body: JSON.stringify({ error: err.message }) };
    }
}