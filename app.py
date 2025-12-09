import os
import time
from collections import defaultdict, deque

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# --------------------------------------------------------
#  Slack App 초기화 (Railway 환경변수 사용)
# --------------------------------------------------------
app = App(token=os.environ["SLACK_BOT_TOKEN"])

ALERT_PREFIX = "❗"   # 메시지 앞 아이콘

# --------------------------------------------------------
# 채널 ID 정의
# --------------------------------------------------------
SVC_WATCHTOWER_CH = "C04M1UCMCFQ"
SVC_TMAP_DIV_CH = "C09BY22G12Q"
SVC_BTV_DIV_CH = "C077QK6NB4K"
RTZR_STT_SKT_ALERT_CH = "C091J89DQF7"
EXT_GIP_REPAIRING_CH = "C06L4C7HUCF"
LINER_ADOT_CH = "C08DRU0U7CK"
ERROR_AX_CH = "C09SQLEU8N8"
TEST_ALERT_CH = "C092DJVHVPY"

# --------------------------------------------------------
# 멘션 ID 정의
# --------------------------------------------------------
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
MENTION_KTH = "<@U04LPNR61BP>"
MENTION_JUR = "<@U05BK5TSBRV>"

MENTION_SYC = "<@U04LSHQMADR>"

# --------------------------------------------------------
# 공통 설정
# --------------------------------------------------------
WINDOW_SECONDS = 180  # 3분
ALERT_COOLDOWN_SECONDS = 600  # 10분

message_window = defaultdict(deque)
last_message_by_rule = {}

last_alert_sent_at = 0
is_muted = False


# --------------------------------------------------------
# 규칙 정의
# --------------------------------------------------------
RULES = [

    # RTZR_API
    {
        "name": "RTZR_API",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "RTZR_API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} 노트 에러(RTZR_API)가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": RTZR_STT_SKT_ALERT_CH,
                "text": f"{ALERT_PREFIX} RTZR_API 5회 이상 감지중! {MENTION_KDW}, {MENTION_NJK}, {MENTION_JJY} 확인 부탁드립니다. (cc. {MENTION_HEO})",
                "include_log": False,
            },
        ],
    },

    # PET_API
    {
        "name": "PET_API",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "PET_API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} 노트 에러(PET_API) 감지됨! {MENTION_KJH}, {MENTION_KHR} 확인 바랍니다. (cc. {MENTION_HEO})",
                "include_log": False,
            },
        ],
    },

    # builtin.one
    {
        "name": "BUILTIN_ONE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "builtin.one",
        "threshold": 7,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} One Agent 에러 발생. (cc. {MENTION_HEO})",
                "include_log": False,
            },
        ],
    },

    # Perplexity
    {
        "name": "PERPLEXITY",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Perplexity",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Perplexity 에러 감지됨. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": f"{ALERT_PREFIX} Perplexity 에러 발생! {MENTION_KYH}, {MENTION_GJH} (cc. {MENTION_YYJ}, {MENTION_PJY}, {MENTION_HEO})",
                "include_log": True,
            },
        ],
    },

    # Claude
    {
        "name": "CLAUDE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Claude",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Claude 에러 감지됨. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": f"{ALERT_PREFIX} Claude 에러 발생! {MENTION_KYH}, {MENTION_GJH} (cc. {MENTION_YYJ}, {MENTION_PJY}, {MENTION_HEO})",
                "include_log": True,
            },
        ],
    },

    # GPT
    {
        "name": "GPT",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "MODEL_LABEL: GPT",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} GPT 에러 감지됨. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": f"{ALERT_PREFIX} GPT 에러 발생! {MENTION_KYH}, {MENTION_GJH} (cc. {MENTION_YYJ}, {MENTION_PJY}, {MENTION_HEO})",
                "include_log": True,
            },
        ],
    },

    # Gemini
    {
        "name": "GEMINI",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Gemini",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Gemini 에러 감지됨. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": f"{ALERT_PREFIX} Gemini 에러 발생! {MENTION_KYH}, {MENTION_GJH} (cc. {MENTION_YYJ}, {MENTION_PJY}, {MENTION_HEO})",
                "include_log": True,
            },
        ],
    },

    # Liner
    {
        "name": "LINER",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Liner",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Liner 에러 감지됨. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": LINER_ADOT_CH,
                "text": f"{ALERT_PREFIX} Liner 에러 발생! {MENTION_KAI}, {MENTION_BSR} (cc. {MENTION_HEO})",
                "include_log": True,
            },
        ],
    },

    # A.X
    {
        "name": "AX",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "A.X",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} A.X 에러 감지됨. (cc. {MENTION_HEO})",
                "include_log": False,
            },
            {
                "channel": ERROR_AX_CH,
                "text": f"{ALERT_PREFIX} A.X 에러 발생! {MENTION_KSW}, {MENTION_LYS} (cc. {MENTION_HEO})",
                "include_log": True,
            },
        ],
    },

    # agent.tmap
    {
        "name": "AGENT_TMAP",
        "channel": SVC_TMAP_DIV_CH,
        "keyword": "agent.tmap",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_TMAP_DIV_CH,
                "text": f"{ALERT_PREFIX} agent.tmap 에러 감지됨! {MENTION_GMS}, {MENTION_KTH} (cc. {MENTION_JUR}, {MENTION_HEO})",
                "include_log": False,
            },
        ],
    },

    # REQUEST_ID
    {
        "name": "REQUEST_ID",
        "channel": SVC_BTV_DIV_CH,
        "keyword": "REQUEST_ID",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_BTV_DIV_CH,
                "text": f"{ALERT_PREFIX} REQUEST_ID 에러 감지됨! {MENTION_SYC}, {MENTION_GMS} (cc. {MENTION_HEO})",
                "include_log": False,
            },
        ],
    },

    # test 채널 테스트용
    {
        "name": "TEST",
        "channel": TEST_ALERT_CH,
        "keyword": "test",
        "threshold": 3,
        "notify": [
            {
                "channel": TEST_ALERT_CH,
                "text": f"{ALERT_PREFIX} 테스트 알림: test 감지됨.",
                "include_log": False,
            },
        ],
    }
]


# --------------------------------------------------------
# 헬퍼 함수
# --------------------------------------------------------
def prune_old_events(key, now_ts):
    dq = message_window[key]
    while dq and now_ts - dq[0] > WINDOW_SECONDS:
        dq.popleft()


def can_send_alert(now_ts):
    global is_muted, last_alert_sent_at
    if is_muted:
        return False
    if now_ts - last_alert_sent_at < ALERT_COOLDOWN_SECONDS:
        return False
    return True


def send_alert_for_rule(rule, event):
    global last_alert_sent_at

    now_ts = time.time()
    if not can_send_alert(now_ts):
        return

    original_text = event.get("text", "")

    for action in rule["notify"]:
        text = action["text"]

        if action.get("include_log"):
            text += f"\n\n```{original_text}```"

        app.client.chat_postMessage(
            channel=action["channel"],
            text=text,
        )

    last_alert_sent_at = now_ts


def process_message(event):
    channel = event.get("channel")
    text = (event.get("text") or "")

    now_ts = time.time()

    for rule in RULES:

        if channel != rule["channel"]:
            continue

        # *** 대소문자 무시하여 감지 ***
        if rule["keyword"].lower() not in text.lower():
            continue

        key = (channel, rule["name"])

        prune_old_events(key, now_ts)

        message_window[key].append(now_ts)
        last_message_by_rule[key] = event

        if len(message_window[key]) >= rule["threshold"]:
            send_alert_for_rule(rule, event)
            message_window[key].clear()


# --------------------------------------------------------
# Slack 메시지 이벤트
# --------------------------------------------------------
@app.event("message")
def handle_message(body, say):
    event = body.get("event", {})

    # 🔥 변경: bot 메시지도 포함하여 전부 감지 → 삭제함
    # if event.get("subtype") == "bot_message": return
    # if event.get("bot_id"): return

    text = (event.get("text") or "").strip()

    global is_muted, last_alert_sent_at, message_window

    if text == "!mute":
        is_muted = True
        say("🔇 Bot mute 상태입니다.")
        return

    if text == "!unmute":
        is_muted = False
        last_alert_sent_at = 0
        message_window.clear()
        say("🔔 Bot unmute 되었습니다.")
        return

    process_message(event)


# --------------------------------------------------------
# Slash Commands
# --------------------------------------------------------
@app.command("/mute")
def slash_mute(ack, respond):
    global is_muted
    ack()
    is_muted = True
    respond("🔇 Bot mute 설정 완료")


@app.command("/unmute")
def slash_unmute(ack, respond):
    global is_muted, last_alert_sent_at, message_window
    ack()
    is_muted = False
    last_alert_sent_at = 0
    message_window.clear()
    respond("🔔 Bot unmute 완료 (카운트 초기화)")


# --------------------------------------------------------
# 실행
# --------------------------------------------------------
if __name__ == "__main__":
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
