import os
import time
import uuid
from typing import Optional

import redis
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# --------------------------------------------------------
# Slack App 초기화
# --------------------------------------------------------
app = App(token=os.environ["SLACK_BOT_TOKEN"])
ALERT_PREFIX = "❗"

# --------------------------------------------------------
# Redis 초기화
# --------------------------------------------------------
REDIS_URL = os.environ.get("REDIS_URL")
if not REDIS_URL:
    raise RuntimeError("REDIS_URL env var is required. (Railway Redis plugin needed)")
r = redis.Redis.from_url(REDIS_URL, decode_responses=True)

# --------------------------------------------------------
# 기존 채널/멘션/설정값 (네 코드 그대로 유지)
# --------------------------------------------------------
SVC_WATCHTOWER_CH = "C04M1UCMCFQ"
SVC_TMAP_DIV_CH = "C09BY22G12Q"
SVC_BTV_DIV_CH = "C077QK6NB4K"
RTZR_STT_SKT_ALERT_CH = "C091J89DQF7"
EXT_GIP_REPAIRING_CH = "C06L4C7HUCF"
LINER_ADOT_CH = "C08DRU0U7CK"
ERROR_AX_CH = "C0A2ZM3EMBN"
TEST_ALERT_CH = "C092DJVHVPY"
OPEN_MONITORING_CH = "C09BLHZAPSS"

MENTION_HEO = "<@U04MGC3BFCY>"
MENTION_KDW = "<@U03H53S4B2B>"
MENTION_NJK = "<@U03L9HG1Q49>"
MENTION_JJY = "<@U03J9DUADJ4>"
MENTION_KJH = "<@U04M5AFPQHF>"
MENTION_KHR = "<@U04LSM49TR8>"
MENTION_KYH = "<@U063M2LKNA1>"
MENTION_GJH = "<@U063M2QM89K>"
MENTION_YYJ = "<@U04LSHPDC03>"
MENTION_PJY = "<@U05319QDEET>"
MENTION_KAI = "<@U06NSJVR0GH>"
MENTION_BSR = "<@U08DS680G7L>"
MENTION_KSW = "<@U04MGC174HE>"
MENTION_LYS = "<@U04LV5K4PA8>"
MENTION_GMS = "<@U04M5A7194H>"
MENTION_JUR = "<@U05BK5TSBRV>"
MENTION_SYC = "<@U04LSHQMADR>"
MENTION_KHJ = "<@U04LC55FDN3>"
MENTION_PJH = "<@U04LL3F11C6>"

WINDOW_SECONDS = 180
ALERT_COOLDOWN_SECONDS = 240

# --------------------------------------------------------
# Redis key prefix (서비스별로 유니크하게)
# --------------------------------------------------------
PFX = "watchbot:adot"
KEY_MUTE = f"{PFX}:muted"

BOT_USER_ID: Optional[str] = None

# --------------------------------------------------------
# RULES (✅ 너의 기존 RULES 리스트를 그대로 붙여넣어)
# --------------------------------------------------------
RULES = [
    # TODO: 여기에 네가 올린 RULES 블록을 그대로 붙여넣기
]

# --------------------------------------------------------
# Redis helper
# --------------------------------------------------------
def k_events(channel: str, rule_name: str) -> str:
    return f"{PFX}:events:{channel}:{rule_name}"

def k_cooldown(channel: str, rule_name: str) -> str:
    return f"{PFX}:cooldown:{channel}:{rule_name}"

def get_muted() -> bool:
    return r.get(KEY_MUTE) == "1"

def set_muted(value: bool):
    if value:
        r.set(KEY_MUTE, "1")
    else:
        r.delete(KEY_MUTE)

def reset_state():
    # 프리픽스만 삭제 (이 봇 전용이면 안전)
    for k in r.scan_iter(f"{PFX}:*"):
        r.delete(k)

def can_send_alert(channel: str, rule_name: str) -> bool:
    if get_muted():
        return False
    return not r.exists(k_cooldown(channel, rule_name))

def mark_cooldown(channel: str, rule_name: str):
    r.set(k_cooldown(channel, rule_name), "1", ex=ALERT_COOLDOWN_SECONDS)

def record_and_count(channel: str, rule_name: str, now_ts: float) -> int:
    """
    WINDOW_SECONDS 내 발생 건수를 ZSET로 관리 (재시작/멀티 인스턴스에서도 유지)
    """
    k = k_events(channel, rule_name)
    cutoff = now_ts - WINDOW_SECONDS

    member = str(uuid.uuid4())
    pipe = r.pipeline()
    pipe.zadd(k, {member: now_ts})
    pipe.zremrangebyscore(k, 0, cutoff)
    pipe.zcard(k)
    pipe.expire(k, WINDOW_SECONDS + 60)
    _, _, cnt, _ = pipe.execute()
    return int(cnt)

def clear_events(channel: str, rule_name: str):
    r.delete(k_events(channel, rule_name))

# --------------------------------------------------------
# Alert send
# --------------------------------------------------------
def send_alert_for_rule(rule, event):
    channel = event.get("channel")
    rule_name = rule["name"]

    if not can_send_alert(channel, rule_name):
        return

    original_text = event.get("text", "") or ""

    for action in rule["notify"]:
        text = action["text"]
        if action.get("include_log"):
            text += f"\n\n```{original_text}```"
        app.client.chat_postMessage(channel=action["channel"], text=text)

    mark_cooldown(channel, rule_name)

# --------------------------------------------------------
# Message processing
# --------------------------------------------------------
def process_message(event):
    channel = event.get("channel")
    text = (event.get("text") or "")
    now_ts = time.time()

    # 1) 일반 RULES 기반 감지
    for rule in RULES:
        if channel != rule["channel"]:
            continue
        if rule["keyword"].lower() not in text.lower():
            continue

        cnt = record_and_count(channel, rule["name"], now_ts)
        if cnt >= rule["threshold"]:
            send_alert_for_rule(rule, event)
            clear_events(channel, rule["name"])

    # 2) API 미포함 카운팅 (TMAP 채널 전용)
    if channel == SVC_TMAP_DIV_CH and "api" not in text.lower():
        rule_name = "TMAP_API_MISSING"
        cnt = record_and_count(channel, rule_name, now_ts)
        if cnt >= 5:
            pseudo_rule = {
                "name": rule_name,
                "notify": [
                    {
                        "channel": SVC_TMAP_DIV_CH,
                        "text": (
                            f"{ALERT_PREFIX} 에러가 감지되어 확인 문의드립니다. "
                            f"{MENTION_KHJ}님, {MENTION_PJH}님 (cc. {MENTION_GMS}님, {MENTION_JUR}님, {MENTION_HEO}님)"
                        ),
                        "include_log": False,
                    }
                ],
            }
            send_alert_for_rule(pseudo_rule, event)
            clear_events(channel, rule_name)

def init_bot_user_id():
    global BOT_USER_ID
    BOT_USER_ID = app.client.auth_test()["user_id"]

# --------------------------------------------------------
# Slack message event
# --------------------------------------------------------
@app.event("message")
def handle_message(body, say):
    event = body.get("event", {}) or {}

    # ✅ (1) subtype 무시 (message_changed 등)
    if event.get("subtype") is not None:
        return

    # ✅ (1) bot 메시지 무시
    if event.get("bot_id") is not None:
        return

    # ✅ (1) 자기 자신 메시지 무시
    if BOT_USER_ID and event.get("user") == BOT_USER_ID:
        return

    text = (event.get("text") or "")
    cmd = text.strip().lower()

    # ✅ (3) !mute/!unmute 파싱 완화
    if cmd.startswith("!mute"):
        set_muted(True)
        say("🔇 Bot mute 상태입니다. (Redis 저장)")
        return

    if cmd.startswith("!unmute"):
        set_muted(False)
        reset_state()
        say("🔔 Bot unmute 되었습니다. (카운트/쿨다운 초기화)")
        return

    process_message(event)

# --------------------------------------------------------
# Slash commands (등록돼 있어야 호출됨)
# --------------------------------------------------------
@app.command("/mute")
def slash_mute(ack, respond):
    ack()
    set_muted(True)
    respond("🔇 Bot mute 설정 완료 (Redis 저장)")

@app.command("/unmute")
def slash_unmute(ack, respond):
    ack()
    set_muted(False)
    reset_state()
    respond("🔔 Bot unmute 완료 (카운트/쿨다운 초기화)")

# --------------------------------------------------------
# main
# --------------------------------------------------------
if __name__ == "__main__":
    init_bot_user_id()
    SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"]).start()
