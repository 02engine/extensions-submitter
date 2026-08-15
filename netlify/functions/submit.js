import { App } from "@octokit/app";

// ---- 环境变量 ----
// GITHUB_APP_ID / GITHUB_PRIVATE_KEY / GITHUB_OWNER / GITHUB_REPO / GITHUB_INSTALLATION_ID

async function getInstallOctokit(appId, privateKey, installationId) {
    const app = new App({ appId: Number(appId), privateKey });
    return await app.getInstallationOctokit(Number(installationId));
}

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
        return {
            statusCode: 200,
            headers: {
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "POST, OPTIONS",
                "Access-Control-Allow-Headers": "Content-Type"
            },
            body: ""
        };
    }

    if (event.httpMethod !== "POST") {
        return { statusCode: 405, body: "Method Not Allowed" };
    }

    const cors = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json"
    };

    try {
        const body = JSON.parse(event.body);
        const {
            slug, name, description, extId, authors, coverExt,
            jsContent, coverContent, docs, docsContent,
            hasSamples, sampleContent, translations,
            version, license
        } = body;

        // ---- 基本校验 ----
        if (!slug || !name || !description || !extId || !jsContent || !coverContent || !authors?.length) {
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "缺少必填字段" }) };
        }
        if (!/^[a-zA-Z0-9_-]+$/.test(slug)) {
            return { statusCode: 400, headers: cors, body: JSON.stringify({ error: "slug 只能包含字母、数字、下划线和连字符" }) };
        }

        // ---- 环境变量 ----
        const appId = process.env.GITHUB_APP_ID;
        const privateKey = String(process.env.GITHUB_PRIVATE_KEY)
            .replace(/^﻿/, "")
            .replace(/\r\n/g, "\n")
            .replace(/\r/g, "\n")
            .trim() + "\n";
        const owner = process.env.GITHUB_OWNER;
        const repo = process.env.GITHUB_REPO;
        const installationId = process.env.GITHUB_INSTALLATION_ID;

        if (!appId || !privateKey || !owner || !repo || !installationId) {
            return { statusCode: 500, headers: cors, body: JSON.stringify({ error: "环境变量未配置完整" }) };
        }

        // ---- 初始化 octokit ----
        const octokit = await getInstallOctokit(appId, privateKey, installationId);

        // ---- 获取默认分支 ----
        const { data: repoData } = await octokit.request("GET /repos/{owner}/{repo}", { owner, repo });
        const base = repoData.default_branch;

        const { data: refData } = await octokit.request("GET /repos/{owner}/{repo}/git/refs/heads/{branch}", {
            owner, repo, branch: base
        });
        const baseSha = refData.object.sha;

        // ---- 创建分支 ----
        const branchName = `ext-submit/${slug}-${Date.now()}`;
        await octokit.request("POST /repos/{owner}/{repo}/git/refs", {
            owner, repo,
            ref: `refs/heads/${branchName}`,
            sha: baseSha
        });

        // ---- 上传文件 ----
        await uploadFile(octokit, owner, repo, `extensions/${slug}.js`, jsContent, branchName, `feat(${slug}): add extension JS`);

        const coverFileName = `${slug}.${coverExt}`;
        await uploadFile(octokit, owner, repo, `images/${coverFileName}`, coverContent, branchName, `feat(${slug}): add cover image`);

        if (docs && docsContent) {
            await uploadFile(octokit, owner, repo, `docs/${slug}.html`, docsContent, branchName, `feat(${slug}): add documentation`);
        }
        if (hasSamples && sampleContent) {
            await uploadFile(octokit, owner, repo, `samples/${slug}.sb3`, sampleContent, branchName, `feat(${slug}): add sample project`);
        }

        // ---- 读取并更新 extensions.json ----
        let extJson, extSha;
        try {
            const { data } = await octokit.request("GET /repos/{owner}/{repo}/contents/{path}", {
                owner, repo, path: "extensions.json", ref: branchName
            });
            extJson = JSON.parse(Buffer.from(data.content, "base64").toString("utf8"));
            extSha = data.sha;
        } catch (_) {
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
        if (idx >= 0) extJson.extensions[idx] = entry;
        else extJson.extensions.push(entry);

        extJson.extensions.sort((a, b) => a.slug.localeCompare(b.slug));

        await octokit.request("PUT /repos/{owner}/{repo}/contents/{path}", {
            owner, repo, path: "extensions.json",
            message: `feat(${slug}): register extension`,
            content: Buffer.from(JSON.stringify(extJson, null, 2)).toString("base64"),
            branch: branchName,
            ...(extSha ? { sha: extSha } : {})
        });

        // ---- 创建 PR ----
        const prBody = [
            `## 📦 新扩展提交`,
            ``,
            `- **Slug:** \`${slug}\``,
            `- **名称:** ${name}`,
            `- **描述:** ${description}`,
            `- **作者:** ${authors.map(a => a.link ? `[@${a.name}](${a.link})` : a.name).join(", ")}`,
            `- **封面:** ${coverFileName}`,
            docs ? `- **文档:** ✅ 已附上` : ``,
            hasSamples ? `- **实例作品:** ✅ 已附上` : ``,
            ``,
            `---`,
            ``,
            `> 此 PR 由 Scratch 扩展提交工具自动创建 🤖`,
        ].filter(Boolean).join("\n");

        const { data: pr } = await octokit.request("POST /repos/{owner}/{repo}/pulls", {
            owner, repo,
            title: `feat: 提交扩展 ${name} (${slug})`,
            head: branchName,
            base,
            body: prBody
        });

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
        console.error("[submit] 错误:", err.message);
        console.error(err.stack);
        return {
            statusCode: 500,
            headers: cors,
            body: JSON.stringify({ error: err.message || "内部服务器错误" })
        };
    }
}