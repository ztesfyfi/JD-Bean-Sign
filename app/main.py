from __future__ import annotations

import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, date
from pathlib import Path
from typing import Any
from urllib.parse import unquote

import httpx
from apscheduler.schedulers.background import BackgroundScheduler
from cryptography.fernet import Fernet, InvalidToken
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field

DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "jd-bean-sign.db"
KEY_PATH = DATA_DIR / "secret.key"
SIGN_TIME = os.getenv("SIGN_TIME", "08:05")


def get_cipher() -> Fernet:
    if not KEY_PATH.exists():
        KEY_PATH.write_bytes(Fernet.generate_key())
        try:
            KEY_PATH.chmod(0o600)
        except OSError:
            pass
    return Fernet(KEY_PATH.read_bytes())


cipher = get_cipher()


@contextmanager
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL,
            pin TEXT NOT NULL,
            cookie_enc TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER,
            label TEXT NOT NULL,
            status TEXT NOT NULL,
            beans INTEGER NOT NULL DEFAULT 0,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        """)


def now_text() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def extract_pin(cookie: str) -> str:
    match = re.search(r"(?:^|;\s*)pt_pin=([^;]+)", cookie)
    if not match or not re.search(r"(?:^|;\s*)pt_key=([^;]+)", cookie):
        raise ValueError("Cookie 必须同时包含 pt_pin 和 pt_key")
    return unquote(match.group(1))


def decrypt_cookie(value: str) -> str:
    try:
        return cipher.decrypt(value.encode()).decode()
    except (InvalidToken, ValueError):
        raise RuntimeError("Cookie 解密失败，请重新保存账号 Cookie")


class AccountInput(BaseModel):
    label: str = Field(min_length=1, max_length=60)
    cookie: str = Field(min_length=20)


class SignResult:
    def __init__(self, status: str, beans: int = 0, message: str = ""):
        self.status, self.beans, self.message = status, beans, message


async def check_cookie(cookie: str) -> tuple[bool, str]:
    """校验京东登录态，不触发签到。"""
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            response = await client.get(
                "https://me-api.jd.com/user_new/info/GetJDUserInfoUnion",
                headers={
                    "Cookie": cookie,
                    "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36",
                    "Referer": "https://m.jd.com/",
                },
            )
        data = response.json()
        return (isinstance(data, dict) and str(data.get("retcode")) in ("0", "200"),
                "Cookie 有效" if isinstance(data, dict) and str(data.get("retcode")) in ("0", "200")
                else "京东登录态校验失败，请更新 Cookie")
    except httpx.TimeoutException:
        return False, "Cookie 检测超时"
    except Exception as exc:
        return False, f"Cookie 检测接口异常：{type(exc).__name__}"


def _jd_client_action(client: httpx.AsyncClient, cookie: str, function_id: str) -> str:
    params = {
        "functionId": function_id, "appid": "ld", "client": "android",
        "clientVersion": "10.6.8", "networkType": "wifi",
        "osVersion": "13", "uuid": "jd-bean-sign",
    }
    body = {
        "fp": "-1", "shshshfp": "-1", "shshshfpa": "-1",
        "referUrl": "-1", "userAgent": "-1", "jda": "-1", "rnVersion": "3.9",
    }
    response = client.post(
        "https://api.m.jd.com/client.action",
        params=params,
        data={"body": json.dumps(body, separators=(",", ":"))},
        headers={
            "Cookie": cookie,
            "User-Agent": "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/126.0.0.0 Mobile Safari/537.36",
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": "https://m.jd.com/",
        },
    )
    response.raise_for_status()
    return response.text


def _parse_jd_claim(raw: str) -> dict[str, Any]:
    result = {"status": "unknown", "beans": 0, "message": ""}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        result["message"] = (raw or "")[:200]
        return result
    if not isinstance(data, dict):
        result["message"] = "京东接口返回格式无法识别"
        return result
    code = str(data.get("code", ""))
    message = str(data.get("message") or data.get("msg") or data.get("errMsg") or "").strip()
    payload = data.get("data") if isinstance(data.get("data"), dict) else {}
    result["message"] = message or json.dumps(data, ensure_ascii=False)[:200]
    if code in ("0", "200"):
        if "已签" in message or any(payload.get(k) in (True, 1, "1", "true")
                                     for k in ("isSign", "signed", "todaySigned")):
            result["status"] = "already"
            return result
        for key in ("beanCount", "beans", "reward"):
            value = payload.get(key)
            if value is not None and str(value).isdigit():
                result["beans"] = int(value)
                break
        award = payload.get("dailyAward") or payload.get("beanAward")
        if isinstance(award, dict):
            value = award.get("beanAward") or award.get("beanCount")
            if value is not None and str(value).isdigit():
                result["beans"] = int(value)
        result["status"] = "success"
        return result
    if any(word in message for word in ("人数较多", "稍晚", "繁忙", "系统繁忙", "稍后再试")):
        result["status"] = "busy"
    elif any(word.lower() in message.lower() for word in ("登录", "未登录", "cookie", "失效", "过期", "鉴权", "token")):
        result["status"] = "cookie_invalid"
    else:
        result["status"] = "rejected"
    return result


async def perform_sign(cookie: str) -> SignResult:
    """先查今日签到状态，再领取京豆；只按京东业务响应判断结果。"""
    try:
        async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
            index = _parse_jd_claim(_jd_client_action(client, cookie, "signBeanIndex"))
            if index["status"] == "already":
                return SignResult("already", message="今日已签到")
            if index["status"] == "cookie_invalid":
                return SignResult("cookie_invalid", message="签到状态查询被拒绝，请更新 Cookie")
            last = None
            for attempt in range(1, 4):
                try:
                    parsed = _parse_jd_claim(_jd_client_action(client, cookie, "signBean"))
                except httpx.TimeoutException:
                    last = SignResult("error", message=f"领取京豆超时（第 {attempt}/3 次）")
                    if attempt < 3:
                        await __import__("asyncio").sleep(2)
                        continue
                    return last
                status = parsed["status"]
                if status == "success":
                    return SignResult("success", int(parsed["beans"] or 0),
                                      parsed["message"] or "京东返回领取成功")
                if status == "already":
                    return SignResult("already", message="今日已签到")
                if status == "busy":
                    return SignResult("error", message=f"京东服务繁忙：{parsed['message']}")
                if status in ("cookie_invalid", "rejected"):
                    return SignResult("cookie_invalid" if status == "cookie_invalid" else "error",
                                      message=parsed["message"] or "京东拒绝本次签到")
                last = SignResult("error", message=f"京东响应无法识别：{parsed['message'][:160]}")
                if attempt < 3:
                    await __import__("asyncio").sleep(2)
            return last or SignResult("error", message="签到失败")
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code in (401, 403):
            return SignResult("cookie_invalid", message="京东拒绝请求，Cookie 可能已失效")
        return SignResult("error", message=f"京东接口 HTTP {exc.response.status_code}")
    except httpx.TimeoutException:
        return SignResult("error", message="京东签到接口请求超时")
    except Exception as exc:
        return SignResult("error", message=f"京东签到接口异常：{type(exc).__name__}")



def save_record(account_id: int, label: str, result: SignResult) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO records(account_id,label,status,beans,message,created_at) VALUES(?,?,?,?,?,?)",
            (account_id, label, result.status, result.beans, result.message, now_text()),
        )


async def sign_account(account_id: int) -> None:
    with db() as conn:
        row = conn.execute("SELECT * FROM accounts WHERE id=? AND enabled=1", (account_id,)).fetchone()
    if not row:
        return
    try:
        cookie = decrypt_cookie(row["cookie_enc"])
        valid, message = await check_cookie(cookie)
        result = SignResult("cookie_invalid", message=message) if not valid else await perform_sign(cookie)
    except Exception as exc:
        result = SignResult("error", message=str(exc))
    save_record(account_id, row["label"], result)


async def sign_all() -> None:
    with db() as conn:
        ids = [r["id"] for r in conn.execute("SELECT id FROM accounts WHERE enabled=1").fetchall()]
    for account_id in ids:
        await sign_account(account_id)


def scheduled_sign() -> None:
    import asyncio
    asyncio.run(sign_all())


init_db()
scheduler = BackgroundScheduler(timezone=os.getenv("TZ", "Asia/Shanghai"))
try:
    hour, minute = [int(x) for x in SIGN_TIME.split(":", 1)]
    if 0 <= hour <= 23 and 0 <= minute <= 59:
        scheduler.add_job(scheduled_sign, "cron", hour=hour, minute=minute, id="daily-sign", replace_existing=True)
except ValueError:
    pass
scheduler.start()

app = FastAPI(title="JD Bean Sign", version="0.1.0")
templates = Jinja2Templates(directory="web")


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    with db() as conn:
        accounts = conn.execute("SELECT id,label,pin,enabled,created_at FROM accounts ORDER BY id DESC").fetchall()
        records = conn.execute("SELECT * FROM records ORDER BY id DESC LIMIT 30").fetchall()
        today = date.today().isoformat()
        totals = conn.execute(
            "SELECT COUNT(*) AS count, COALESCE(SUM(beans),0) AS beans FROM records WHERE substr(created_at,1,10)=? AND status='success'",
            (today,),
        ).fetchone()
        all_beans = conn.execute("SELECT COALESCE(SUM(beans),0) AS n FROM records WHERE status='success'").fetchone()["n"]
    return templates.TemplateResponse("index.html", {
        "request": request, "accounts": accounts, "records": records,
        "today_count": totals["count"], "today_beans": totals["beans"], "all_beans": all_beans,
        "sign_time": SIGN_TIME,
    })



def _qr_cleanup() -> None:
    cutoff = time.time() - QR_TTL_SECONDS
    for key, value in list(QR_SESSIONS.items()):
        if value.get("created", 0) < cutoff or value.get("status") in ("success", "expired", "cancelled", "error"):
            client = value.get("client")
            if client is not None:
                # close is scheduled by the route that completes/cancels; stale sessions are dropped here
                pass
            QR_SESSIONS.pop(key, None)


@app.post("/api/accounts/qr-login/init")
async def qr_login_init():
    _qr_cleanup()
    client = httpx.AsyncClient(timeout=15, follow_redirects=True)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
        "Referer": "https://passport.jd.com/new/login.aspx",
    }
    try:
        await client.get("https://passport.jd.com/new/login.aspx", headers=headers)
        response = await client.get(
            "https://qr.m.jd.com/show",
            params={"appid": "133", "size": "300", "t": str(int(time.time() * 1000))},
            headers=headers,
        )
        response.raise_for_status()
        if not response.headers.get("content-type", "").startswith("image/"):
            raise RuntimeError("京东没有返回二维码图片")
        token = client.cookies.get("wlfstk_smdl")
        if not token:
            raise RuntimeError("未能取得二维码校验令牌，请稍后重试")
        session_id = secrets.token_urlsafe(24)
        QR_SESSIONS[session_id] = {
            "client": client, "token": token, "created": time.time(),
            "status": "waiting", "headers": headers, "last_message": "等待京东 App 扫码",
        }
        return {
            "session_id": session_id,
            "qr_image": "data:image/png;base64," + base64.b64encode(response.content).decode(),
            "expires_in": QR_TTL_SECONDS,
        }
    except Exception as exc:
        await client.aclose()
        raise HTTPException(502, f"获取京东二维码失败：{type(exc).__name__}：{str(exc)[:120]}")


@app.get("/api/accounts/qr-login/status")
async def qr_login_status(session_id: str):
    session = QR_SESSIONS.get(session_id)
    if not session:
        raise HTTPException(404, "二维码登录会话不存在或已过期，请重新获取")
    if time.time() - session["created"] > QR_TTL_SECONDS:
        await session["client"].aclose()
        QR_SESSIONS.pop(session_id, None)
        return {"status": "expired", "message": "二维码已过期，请刷新"}
    if session["status"] != "waiting":
        return {"status": session["status"], "message": session.get("last_message", "")}

    client: httpx.AsyncClient = session["client"]
    headers = session["headers"]
    try:
        response = await client.get(
            "https://qr.m.jd.com/check",
            params={
                "appid": "133",
                "callback": "jQuery" + str(secrets.randbelow(9000000) + 1000000),
                "token": session["token"],
                "_": str(int(time.time() * 1000)),
            },
            headers=headers,
        )
        match = re.search(r"\((.*)\)\s*;?\s*$", response.text, re.S)
        payload = json.loads(match.group(1) if match else response.text)
        code = payload.get("code")
        if code == 201:
            return {"status": "waiting", "message": "等待扫码"}
        if code == 202:
            session["last_message"] = "已扫码，请在京东 App 确认登录"
            return {"status": "scanned", "message": session["last_message"]}
        if code == 203:
            session["status"] = "expired"
            session["last_message"] = "二维码已失效，请刷新"
            await client.aclose()
            return {"status": "expired", "message": session["last_message"]}
        if code != 200:
            return {"status": "waiting", "message": payload.get("msg", "等待扫码")}

        ticket = payload.get("ticket")
        if not ticket:
            raise RuntimeError("京东扫码确认响应缺少 ticket")
        validation = await client.get(
            "https://passport.jd.com/uc/qrCodeTicketValidation",
            params={"t": ticket},
            headers={**headers, "Referer": "https://passport.jd.com/uc/login?ltype=logout"},
        )
        validation.raise_for_status()
        try:
            validation_data = validation.json()
        except ValueError:
            validation_data = json.loads(validation.text)
        if validation_data.get("returnCode") != 0:
            session["last_message"] = "扫码票据校验未通过，请重新扫码"
            session["status"] = "error"
            await client.aclose()
            return {"status": "error", "message": session["last_message"]}

        # Collect cookies after ticket validation; do not trust the QR scan state alone.
        cookie_pairs = {}
        for cookie in client.cookies.jar:
            if cookie.name in ("pt_key", "pt_pin"):
                cookie_pairs[cookie.name] = cookie.value
        if not cookie_pairs.get("pt_key") or not cookie_pairs.get("pt_pin"):
            session["status"] = "error"
            session["last_message"] = "京东已确认扫码，但未取得完整 pt_key/pt_pin。请重试或使用手动 Cookie 导入"
            await client.aclose()
            return {"status": "error", "message": session["last_message"]}

        cookie_text = f"pt_key={cookie_pairs['pt_key']}; pt_pin={cookie_pairs['pt_pin']};"
        pin = unquote(cookie_pairs["pt_pin"])
        valid, message = await check_cookie(cookie_text)
        if not valid:
            session["status"] = "error"
            session["last_message"] = "登录态校验失败：" + message
            await client.aclose()
            return {"status": "error", "message": session["last_message"]}

        with db() as conn:
            existing = conn.execute("SELECT id FROM accounts WHERE pin=?", (pin,)).fetchone()
            if existing:
                conn.execute(
                    "UPDATE accounts SET cookie_enc=?, enabled=1 WHERE id=?",
                    (cipher.encrypt(cookie_text.encode()).decode(), existing["id"]),
                )
                account_id = existing["id"]
                action = "已更新现有账号 Cookie"
            else:
                cur = conn.execute(
                    "INSERT INTO accounts(label,pin,cookie_enc,enabled,created_at) VALUES(?,?,?,?,?)",
                    (pin, pin, cipher.encrypt(cookie_text.encode()).decode(), 1, now_text()),
                )
                account_id = cur.lastrowid
                action = "已添加新账号"
        session["status"] = "success"
        session["last_message"] = action
        await client.aclose()
        return {"status": "success", "message": action, "account_id": account_id, "pin_masked": pin[:2] + "***"}
    except Exception as exc:
        session["status"] = "error"
        session["last_message"] = f"扫码登录异常：{type(exc).__name__}"
        await client.aclose()
        return {"status": "error", "message": session["last_message"]}


@app.post("/api/accounts/qr-login/cancel")
async def qr_login_cancel(payload: dict):
    session_id = payload.get("session_id", "")
    session = QR_SESSIONS.pop(session_id, None)
    if session:
        session["status"] = "cancelled"
        await session["client"].aclose()
    return {"ok": True}


@app.post("/api/accounts")
async def add_account(data: AccountInput):
    try:
        pin = extract_pin(data.cookie)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    with db() as conn:
        cur = conn.execute(
            "INSERT INTO accounts(label,pin,cookie_enc,enabled,created_at) VALUES(?,?,?,?,?)",
            (data.label.strip(), pin, cipher.encrypt(data.cookie.strip().encode()).decode(), 1, now_text()),
        )
    return {"ok": True, "id": cur.lastrowid}


@app.post("/api/accounts/{account_id}/toggle")
async def toggle_account(account_id: int):
    with db() as conn:
        row = conn.execute("SELECT enabled FROM accounts WHERE id=?", (account_id,)).fetchone()
        if not row:
            raise HTTPException(404, "账号不存在")
        conn.execute("UPDATE accounts SET enabled=? WHERE id=?", (0 if row["enabled"] else 1, account_id))
    return {"ok": True}


@app.delete("/api/accounts/{account_id}")
async def delete_account(account_id: int):
    with db() as conn:
        conn.execute("DELETE FROM accounts WHERE id=?", (account_id,))
    return {"ok": True}


@app.post("/api/accounts/{account_id}/check")
async def account_check(account_id: int):
    with db() as conn:
        row = conn.execute("SELECT cookie_enc FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not row:
        raise HTTPException(404, "账号不存在")
    valid, message = await check_cookie(decrypt_cookie(row["cookie_enc"]))
    return {"valid": valid, "message": message}


@app.post("/api/accounts/{account_id}/sign")
async def account_sign(account_id: int):
    with db() as conn:
        exists = conn.execute("SELECT id FROM accounts WHERE id=?", (account_id,)).fetchone()
    if not exists:
        raise HTTPException(404, "账号不存在")
    await sign_account(account_id)
    with db() as conn:
        row = conn.execute("SELECT * FROM records WHERE account_id=? ORDER BY id DESC LIMIT 1", (account_id,)).fetchone()
    return dict(row) if row else {"ok": True}


@app.post("/api/sign-all")
async def sign_everyone():
    await sign_all()
    return {"ok": True}


@app.get("/health")
async def health():
    return {"status": "ok", "app": "JD Bean Sign", "version": "0.1.0"}
