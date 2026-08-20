// Cap CAPTCHA 边缘函数（Netlify Edge Function，基于 Deno）
// 提供无状态的 challenge 生成与 redemption 验证。
// 使用 capjs-core（已确认可在 Deno 运行）+ Netlify Blobs 做原子 nonce 防重放。
import { getStore } from "@netlify/blobs";
import { generateChallenge, validateChallenge } from "capjs-core";

// 与 submit.js 共享的 scope，校验两端必须一致
const SCOPE = "submit";

function json(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type",
        },
    });
}

export default async (request, context) => {
    const url = new URL(request.url);

    // 预检请求
    if (request.method === "OPTIONS") {
        return new Response("", { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" } });
    }

    // CAP_SECRET 只存在于服务端，绝不暴露给前端
    const secret = Deno.env.get("CAP_SECRET");
    if (!secret) {
        console.error("[cap] CAP_SECRET 未配置");
        return json({ error: "服务器未配置人机验证密钥" }, 500);
    }

    const store = getStore("cap");

    // ---- POST /cap/challenge：生成一个挑战（widget 会先调用这里）----
    if (url.pathname === "/cap/challenge" && request.method === "POST") {
        try {
            const ch = await generateChallenge(secret, {
                scope: SCOPE,
                // 开启浏览器 instrumentation（无感，后台运行），提高反自动化能力
                instrumentation: true,
            });
            return json(ch);
        } catch (err) {
            console.error("[cap] generateChallenge 失败:", err);
            return json({ error: "生成挑战失败" }, 500);
        }
    }

    // ---- POST /cap/redeem：验证 widget 求解结果，签发一次性 cap-token ----
    if (url.pathname === "/cap/redeem" && request.method === "POST") {
        let body;
        try {
            body = await request.json();
        } catch {
            return json({ success: false, error: "请求体不是合法 JSON" }, 400);
        }

        const result = await validateChallenge(secret, body, {
            scope: SCOPE,
            // 原子防重放：同一 challenge 只能被兑换一次（onlyIfNew 保证并发安全）
            consumeNonce: async (sigHex, ttlMs) => {
                const res = await store.set(`nonce:${sigHex}`, "1", { onlyIfNew: true });
                return res.modified === true;
            },
        });

        if (!result.success) {
            console.warn("[cap] redeem 失败:", result.reason);
            return json({ success: false, error: result.reason || "验证未通过" }, 400);
        }

        // 把一次性 cap-token 写入 Blobs，供 submit 函数做二次验证（get+delete）
        try {
            await store.setJSON(`token:${result.tokenKey}`, { expires: result.expires });
        } catch (err) {
            console.error("[cap] 写入 cap-token 失败:", err);
            return json({ success: false, error: "服务端存储失败" }, 500);
        }

        // 只把 token / expires 返回给 widget（tokenKey 绝不外泄）
        return json({ success: true, token: result.token, expires: result.expires });
    }

    return json({ error: "Not Found" }, 404);
};
