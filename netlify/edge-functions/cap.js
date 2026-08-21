// Cap CAPTCHA 边缘函数（Netlify Edge Function，基于 Deno）
// 提供无状态的 challenge 生成与 redemption 验证。
// 使用 capjs-core（已确认可在 Deno 运行）。不再依赖 Netlify Blobs：
// PoW 求解验证通过后，直接用共享 CAP_SECRET 签发一个 HMAC-SHA256 自签名凭证，
// submit.js 用同一把 CAP_SECRET 独立验证，两端均无需任何外部存储。
import { generateChallenge, validateChallenge } from "capjs-core";
import { createHmac } from "node:crypto";

// 与 submit.js 共享的 scope，校验两端必须一致
const SCOPE = "submit";
const CAP_TTL_MS = 10 * 60 * 1000; // 凭证有效期 10 分钟

// ================= 超级日志工具（Edge 版） =================
let __capSeq = 0;
function _cTs() {
    const d = new Date();
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, "0")}`;
}
function _cLog(level, tag, msg, extra) {
    const seq = ++__capSeq;
    const icon = { INFO: "🗒️", WARN: "🟡", ERROR: "🔴", OK: "✅", CAP: "🛡️", BLOB: "📦" }[tag] || "•";
    const base = `[${_cTs()}] #${String(seq).padStart(3)} [${level}] ${icon} [cap] ${msg}`;
    const payload = extra === undefined ? "" : ` · ${typeof extra === "string" ? extra : JSON.stringify(extra)}`;
    if (level === "ERROR") console.error(base + payload);
    else if (level === "WARN") console.warn(base + payload);
    else console.log(base + payload);
}
const cInfo  = (m, e) => _cLog("INFO", "INFO", m, e);
const cWarn  = (m, e) => _cLog("WARN", "WARN", m, e);
const cError = (m, e) => _cLog("ERROR", "ERROR", m, e);
const cOk    = (m, e) => _cLog("INFO", "OK", m, e);
const cCap   = (m, e) => _cLog("INFO", "CAP", m, e);
const cBlob  = (m, e) => _cLog("INFO", "BLOB", m, e);

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
    cInfo(`收到请求`, `${request.method} ${url.pathname}`);

    // 预检请求
    if (request.method === "OPTIONS") {
        return new Response("", { status: 204, headers: { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Methods": "POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type" } });
    }

    // CAP_SECRET 只存在于服务端，绝不暴露给前端
    const secret = Deno.env.get("CAP_SECRET");
    if (!secret) {
        cError("CAP_SECRET 未配置 → 500");
        return json({ error: "服务器未配置人机验证密钥" }, 500);
    }
    cOk("CAP_SECRET 已配置");


    // ---- POST /cap/challenge：生成一个挑战（widget 会先调用这里）----
    if (url.pathname === "/cap/challenge" && request.method === "POST") {
        const t0 = Date.now();
        try {
            cCap("生成 challenge 开始");
            const ch = await generateChallenge(secret, {
                scope: SCOPE,
                // 开启浏览器 instrumentation（无感，后台运行），提高反自动化能力
                instrumentation: true,
            });
            cOk("generateChallenge 成功", `${Date.now() - t0}ms`);
            return json(ch);
        } catch (err) {
            cError("generateChallenge 失败", { name: err?.name, message: err?.message, ms: Date.now() - t0 });
            return json({ error: "生成挑战失败" }, 500);
        }
    }

    // ---- POST /cap/redeem：验证 widget 求解结果，签发一次性 cap-token ----
    if (url.pathname === "/cap/redeem" && request.method === "POST") {
        const t0 = Date.now();
        cCap("redeem 开始（验证求解结果）");
        let body;
        try {
            body = await request.json();
        } catch {
            cWarn("请求体不是合法 JSON → 400");
            return json({ success: false, error: "请求体不是合法 JSON" }, 400);
        }

        const result = await validateChallenge(secret, body, {
            scope: SCOPE,
            // 无状态：不设 consumeNonce（过去依赖 Blobs 做 nonce 防重放），
            // 改为在 PoW 验证通过后，用 CAP_SECRET 签发一个 HMAC 自签名凭证，
            // 由 submit.js 用同一把密钥独立校验真实性与过期时间。
        });

        if (!result.success) {
            cWarn("redeem 验证失败", result.reason);
            return json({ success: false, error: result.reason || "验证未通过" }, 400);
        }
        cOk("redeem 验证通过");

        // 签发自签名凭证: payload = "cap:v1:<scope>:<expires>", sig = HMAC-SHA256(CAP_SECRET, payload)
        const payload = `cap:v1:${SCOPE}:${Date.now() + CAP_TTL_MS}`;
        const sig = createHmac("sha256", secret).update(payload).digest("hex");
        const capToken = `${payload}.${sig}`;
        const expires = Date.now() + CAP_TTL_MS;
        cOk("cap-token 已签发（无状态自签名），无需任何存储", { scope: SCOPE, expires, ms: Date.now() - t0 });

        // 只把凭证 token / expires 返回给 widget（payload 语义对前端不透明）
        return json({ success: true, token: capToken, expires });
    }

    cWarn("未匹配任何路由 → 404", url.pathname);
    return json({ error: "Not Found" }, 404);
};
