//! KukuAI 的「业务会话令牌」换发：BDUSS + PTOKEN → genflowpro 作用域的 STOKEN。
//!
//! ── 为什么需要换发 ──────────────────────────────────────────
//! KukuAI 的业务接口（`userreport` / `sendmsg` / `getchatcontent`）认的是
//! **按产品签发**的 STOKEN，而网页登录 Cookie 里那份是**通行证级**的 ——
//! 无论带多少 Cookie 都过不了校验（`errno=-6`）。症状很有欺骗性：余额接口
//! 只看 BDUSS，所以「余额正常、模型拉不下」。
//!
//! 换发材料是 `PTOKEN`（`credentials::ptoken_of`），端点：
//! `POST https://passport.baidu.com/v3/login/api/auth`
//!
//! ── 与网关那份的差别（迁移时改的）───────────────────────────
//! 网关版先 `LoadLibraryW` 加载官方客户端的 `genflowengine.dll`、调它导出的
//! `genflow_engine_get_login_auth_param` 构造签名参数体。插件这边：
//!
//!   · `windows` crate 只开了 `Win32_Security_Cryptography`（那是 DPAPI 用的），
//!     加载 DLL 要 `Win32_System_LibraryLoader` + `Win32_System_Registry`；
//!   · 更根本的是**插件不该去翻用户的注册表、不该把 14MB 的原生引擎映射进
//!     宿主进程** —— 那两件事都是「进程级副作用」，与插件「一次请求一个
//!     spawn 的沙箱」相反。
//!
//! 换发参数使用 KukuAI 客户端引擎的纯算法签名：签名字段是
//! `appid / bduss / ptoken / return_type / tpl / tpl_list`，追加内置
//! `sign_key` 后做 MD5。这样插件不需要加载 `genflowengine.dll`。
//!
//! ── 硬约束 ──────────────────────────────────────────────────
//! release 是 `panic=abort`：本文件零 unwrap/expect/panic。

use md5::{Digest as _, Md5};
use serde_json::Value;

use crate::errors::GatewayError;
use crate::http::{control_client, describe_chain};

/// 换发端点（passport 的 v3 登录 API）
const PASSPORT_AUTH_URL: &str = "https://passport.baidu.com/v3/login/api/auth";

/// KukuAI 官方客户端引擎内置签名密钥
const ENGINE_SIGN_KEY: &str = "34868b316de55815273b2616954b0286";

/// passport 换发接口对客户端引擎 UA 敏感，浏览器 UA 不可靠。
const ENGINE_UA: &str = "genflow;1.6.5;PC;PC-Windows;10.0.26200;GenFlowPro";

/// 构造 passport 换发用的签名参数体。
fn build_auth_param(bduss: &str, ptoken: &str) -> String {
    let signed = format!(
        "appid=1&bduss={bduss}&ptoken={ptoken}&return_type=1&tpl=genflowpro&\
         tpl_list=genflowpro|netdisk&sign_key={ENGINE_SIGN_KEY}"
    );
    let mut hasher = Md5::new();
    hasher.update(signed.as_bytes());
    let signature = format!("{:x}", hasher.finalize());
    format!(
        "appid=1&bduss={bduss}&ptoken={ptoken}&return_type=1&tpl=genflowpro&\
         tpl_list=genflowpro|netdisk&sig={signature}"
    )
}

/// 用 BDUSS + PTOKEN 换发「genflowpro 作用域」的 STOKEN。
///
/// 成功返回新 STOKEN；失败（缺材料 / 没有引擎 / 被拒）返回带可读原因的错误，
/// 由调用方决定回退方式（本项目的口径是「只记日志，用原凭证继续」）。
pub async fn exchange_genflowpro_stoken(bduss: &str, ptoken: &str) -> Result<String, GatewayError> {
    if bduss.trim().is_empty() || ptoken.trim().is_empty() {
        return Err(GatewayError::with_status(
            400,
            "换发 KukuAI 会话令牌需要 BDUSS 与 PTOKEN（登录 Cookie 里缺 PTOKEN）",
        ));
    }
    let body = build_auth_param(bduss, ptoken);
    // ── 为什么不用 `http::send_raw` ──────────────────────────────
    // 那个函数的 body 是 `Option<&Value>`，会按 JSON 发；passport 只认
    // `application/x-www-form-urlencoded`（发错编码的表现是 400
    // `invalid_request`，与「凭证不对」难以区分）。这里直发一次。
    let response = control_client(None, "direct")
        .post(PASSPORT_AUTH_URL)
        .header(
            "Content-Type",
            "application/x-www-form-urlencoded;charset=UTF-8",
        )
        .header("Referer", format!("{}/genflowpro", super::BASE_URL))
        .header("Origin", super::BASE_URL)
        .header("User-Agent", ENGINE_UA)
        .body(body)
        .timeout(std::time::Duration::from_secs(20))
        .send()
        .await
        .map_err(|error| {
            GatewayError::with_status(
                502,
                format!("换发 KukuAI 会话令牌失败：{}", describe_chain(&error)),
            )
        })?;
    let status = response.status().as_u16();
    let value: Value = response.json().await.map_err(|error| {
        GatewayError::with_status(502, format!("换发 KukuAI 会话令牌响应异常：{error}"))
    })?;
    if !(200..300).contains(&status) {
        return Err(GatewayError::with_status(
            502,
            format!("换发 KukuAI 会话令牌失败（HTTP {status}）"),
        ));
    }
    let errno = value.get("errno").and_then(Value::as_i64).unwrap_or(-1);
    if errno != 0 {
        let message = value
            .get("errmsg")
            .or_else(|| value.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("未知错误");
        return Err(GatewayError::with_status(
            502,
            format!("换发 KukuAI 会话令牌被拒（errno={errno}：{message}）"),
        ));
    }
    let stoken = value
        .pointer("/stoken_list/genflowpro")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    if stoken.is_empty() {
        return Err(GatewayError::with_status(
            502,
            "换发 KukuAI 会话令牌成功但响应缺少 genflowpro 令牌",
        ));
    }
    Ok(stoken)
}

#[cfg(test)]
mod tests {
    use super::build_auth_param;

    #[test]
    fn auth_param_matches_dll_signature_vectors() {
        let bduss = "A".repeat(192);
        let ptoken = "P".repeat(64);
        let body = build_auth_param(&bduss, &ptoken);
        assert_eq!(
            body,
            format!(
                "appid=1&bduss={bduss}&ptoken={ptoken}&return_type=1&tpl=genflowpro&\
                 tpl_list=genflowpro|netdisk&sig=9cf3a33e3b6f19324853970abf2d00a2"
            )
        );
        assert!(build_auth_param(&"X".repeat(192), &"Y".repeat(64))
            .ends_with("&sig=a3d861ea0946b617a7235b6b36c65add"));
    }
}
