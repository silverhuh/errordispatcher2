import os
import time
from collections import defaultdict, deque

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# --------------------------------------------------------
# Slack App 초기화
# --------------------------------------------------------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")
if not SLACK_BOT_TOKEN or not SLACK_APP_TOKEN:
    raise RuntimeError("Missing SLACK_BOT_TOKEN or SLACK_APP_TOKEN in environment variables.")

app = App(token=SLACK_BOT_TOKEN)

ALERT_PREFIX = "❗"

# --------------------------------------------------------
# 채널 ID 정의
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
MENTION_JUR = "<@U05BK5TSBRV>"

MENTION_SYC = "<@U04LSHQMADR>"

MENTION_KHJ = "<@U04LC55FDN3>"
MENTION_PJH = "<@U04LL3F11C6>"

# --------------------------------------------------------
# 공통 설정
# --------------------------------------------------------
WINDOW_SECONDS = 240  # threshold 카운팅 윈도우(기존 유지)

# ✅ 전역 발언 제한: 5분 동안 2회
GLOBAL_RATE_WINDOW_SECONDS = 300
GLOBAL_RATE_LIMIT_COUNT = 1
global_alert_sent_times = deque()  # bot chat_postMessage 성공 timestamps

message_window = defaultdict(deque)  # (channel, rule) -> deque[timestamps]
is_muted = False

# 내 봇 식별용
BOT_USER_ID = None
BOT_ID = None  # event.get("bot_id") 비교용(있으면 더 안전)

# --------------------------------------------------------
# RULES
# --------------------------------------------------------
RULES = [
    {
        "name": "RTZR_API",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "RTZR_API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": (
                    f"{ALERT_PREFIX} Test 메시지 : 노트 에러(RTZR_API)가 감지되어 담당자 전달하였습니다. "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
            {
                "channel": RTZR_STT_SKT_ALERT_CH,
                "text": (
                    f"{ALERT_PREFIX} Test 메시지 입니다. "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
        ],
    },
    {
        "name": "PET_API",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "PET_API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": (
                    f"{ALERT_PREFIX} 노트 에러(PET_API) 5회 이상 감지중! "
                    f"{MENTION_KJH}님, {MENTION_KHR}님 확인 문의드립니다. "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
        ],
    },
    {
        "name": "BUILTIN_ONE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "builtin.one",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": (
                    f"{ALERT_PREFIX} One Agent 에러가 감지되었습니다."
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
        ],
    },
    {
        "name": "PERPLEXITY",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Perplexity",
        "threshold": 20,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Perplexity 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX} Perplexity 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KYH}님, {MENTION_GJH}님 "
                    f"(cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)"
                ),
                "include_log": True,
            },
        ],
    },
    {
        "name": "CLAUDE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Claude",
        "threshold": 20,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Claude 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX} Claude 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KYH}님, {MENTION_GJH}님 "
                    f"(cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)"
                ),
                "include_log": True,
            },
        ],
    },
    {
        "name": "GPT",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "MODEL_LABEL: GPT",
        "threshold": 20,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} GPT 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX} GPT 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KYH}님, {MENTION_GJH}님 "
                    f"(cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)"
                ),
                "include_log": True,
            },
        ],
    },
    {
        "name": "GEMINI",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Gemini",
        "threshold": 20,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Gemini 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX} Gemini 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KYH}님, {MENTION_GJH}님 "
                    f"(cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)"
                ),
                "include_log": True,
            },
        ],
    },
    {
        "name": "LINER",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Liner",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} Liner 모델 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": LINER_ADOT_CH,
                "text": (
                    f"{ALERT_PREFIX} Liner 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KAI}님, {MENTION_BSR}님 "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": True,
            },
        ],
    },
    {
        "name": "AX",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "A.X",
        "threshold": 10,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX} A.X 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": ERROR_AX_CH,
                "text": (
                    f"{ALERT_PREFIX} A.X 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KSW}님, {MENTION_LYS}님 "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": True,
            },
        ],
    },
    {
        "name": "REQUEST_ID",
        "channel": SVC_BTV_DIV_CH,
        "keyword": "REQUEST_ID",
        "threshold": 10,
        "notify": [
            {
                "channel": SVC_BTV_DIV_CH,
                "text": (
                    f"{ALERT_PREFIX} 에러가 감지되어 확인 문의드립니다. "
                    f"{MENTION_SYC}님, {MENTION_GMS}님 "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
        ],
    },
    # 테스트
    {
        "name": "TEST",
        "channel": TEST_ALERT_CH,
        "keyword": "builtin.one",
        "threshold": 5,
        "notify": [
            {
                "channel": TEST_ALERT_CH,
                "text": f"{ALERT_PREFIX} 테스트 알림: test 감지됨.",
                "include_log": False,
            },
        ],
    },
    # TMAP API
    {
        "name": "API",
        "channel": SVC_TMAP_DIV_CH,
        "keyword": "API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_TMAP_DIV_CH,
                "text": (
                    f"{ALERT_PREFIX} TMAP API 에러가 감지되어 티모비 채널에 전파하였습니다. "
                    f"(cc. {MENTION_GMS}님, {MENTION_JUR}님, {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
            {
                "channel": OPEN_MONITORING_CH,
                "text": (
                    f"{ALERT_PREFIX} TMAP API 에러가 지속 감지되어 확인 문의드립니다. "
                    f"<!here>\n"
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
        ],
    },
]

# --------------------------------------------------------
# helpers
# --------------------------------------------------------
def init_bot_identity():
    """
    BOT_USER_ID: 내 봇 '유저' ID (U로 시작)
    BOT_ID: 내 봇 'bot_id' (B로 시작) - 이벤트에서 bot_id로 들어올 때 비교용
    """
    global BOT_USER_ID, BOT_ID
    try:
        resp = app.client.auth_test()
        BOT_USER_ID = resp.get("user_id")
        BOT_ID = resp.get("bot_id")
        print(f"[BOOT] BOT_USER_ID={BOT_USER_ID}, BOT_ID={BOT_ID}")
    except Exception as e:
        BOT_USER_ID, BOT_ID = None, None
        print(f"[BOOT] auth_test failed: {repr(e)}")


def prune_old_events(key, now_ts):
    dq = message_window[key]
    while dq and now_ts - dq[0] > WINDOW_SECONDS:
        dq.popleft()


# ✅ 전역 발언 제한(레이트리밋) 관련 helpers
def prune_global_alerts(now_ts: float):
    while global_alert_sent_times and (now_ts - global_alert_sent_times[0] > GLOBAL_RATE_WINDOW_SECONDS):
        global_alert_sent_times.popleft()


def global_can_speak(now_ts: float) -> bool:
    if is_muted:
        return False
    prune_global_alerts(now_ts)
    return len(global_alert_sent_times) < GLOBAL_RATE_LIMIT_COUNT


def global_mark_spoke(now_ts: float):
    prune_global_alerts(now_ts)
    global_alert_sent_times.append(now_ts)


def keyword_hits_in_text(keyword: str, text: str) -> int:
    """
    한 메시지 안에서 keyword가 여러 번 나오면 그 횟수만큼 카운트
    - 대소문자 무시
    - 단순 substring count
    """
    if not keyword or not text:
        return 0
    return text.lower().count(keyword.lower())


def send_alert_for_rule(rule, event):
    """
    ✅ 전파 중 일부 채널 실패해도 프로세스가 죽지 않도록 방어
    ✅ 전역 발언 제한: 5분 동안 2회까지만 전송
    - "발언 1회"는 chat_postMessage 성공 1회를 의미함
      (notify가 2채널이면 2회로 카운트)
    """
    now_ts = time.time()
    original_text = event.get("text", "") or ""
    rule_name = rule.get("name")

    sent_any = False
    errors = []

    for action in rule.get("notify", []):
        # 전역 발언 제한 체크 (발언 직전)
        if not global_can_speak(now_ts):
            break

        try:
            text = action["text"]
            if action.get("include_log"):
                text += f"\n\n```{original_text}```"

            app.client.chat_postMessage(channel=action["channel"], text=text)

            sent_any = True
            global_mark_spoke(now_ts)

        except Exception as e:
            errors.append(f"{action.get('channel')} -> {repr(e)}")

    if (not sent_any) and errors:
        src_channel = event.get("channel")
        print(f"[ALERT_FAIL] rule={rule_name} src_channel={src_channel} errors={errors}")


def process_message(event):
    channel = event.get("channel")
    text = (event.get("text") or "")
    now_ts = time.time()

    # 1) RULES 기반 감지
    for rule in RULES:
        if channel != rule["channel"]:
            continue

        hits = keyword_hits_in_text(rule["keyword"], text)
        if hits <= 0:
            continue

        key = (channel, rule["name"])
        prune_old_events(key, now_ts)

        # 한 메시지에서 여러 번 등장하면 그 횟수만큼 timestamp 추가
        for _ in range(hits):
            message_window[key].append(now_ts)

        if len(message_window[key]) >= rule["threshold"]:
            send_alert_for_rule(rule, event)
            message_window[key].clear()

    # 2) TMAP 채널 전용: "API" 미포함 메시지 5회
    if channel == SVC_TMAP_DIV_CH and "api" not in text.lower():
        key = (channel, "TMAP_API_MISSING")
        prune_old_events(key, now_ts)
        message_window[key].append(now_ts)

        if len(message_window[key]) >= 5:
            pseudo_rule = {
                "name": "TMAP_API_MISSING",
                "notify": [
                    {
                        "channel": SVC_TMAP_DIV_CH,
                        "text": (
                            f"{ALERT_PREFIX} 내부 원인으로 추정되는 에러가 감지되어 확인 문의드립니다. "
                            f"{MENTION_KHJ}님, {MENTION_PJH}님 "
                            f"(cc. {MENTION_GMS}님, {MENTION_JUR}님, {MENTION_HEO}님)"
                        ),
                        "include_log": False,
                    }
                ],
            }
            send_alert_for_rule(pseudo_rule, event)
            message_window[key].clear()


# --------------------------------------------------------
# Slack message event
# --------------------------------------------------------
@app.event("message")
def handle_message(body, say):
    event = body.get("event", {}) or {}

    # (1) 메시지 수정/삭제 등 '메시지 본문이 아닌 이벤트'는 제외
    if event.get("subtype") is not None:
        return

    # 다른 봇 메시지도 감지한다.
    # 단, "내 봇이 보낸 메시지"만 무시하여 무한루프를 방지한다.
    if BOT_USER_ID and event.get("user") == BOT_USER_ID:
        return
    if BOT_ID and event.get("bot_id") == BOT_ID:
        return

    channel = event.get("channel")
    text = (event.get("text") or "")
    cmd = text.strip().lower()

    global is_muted

    # !mute / !unmute
    if cmd.startswith("!mute"):
        is_muted = True
        try:
            app.client.chat_postMessage(channel=channel, text="🔇 Bot mute 상태입니다.")
        except Exception as e:
            print(f"[MUTE_REPLY_FAIL] {repr(e)}")
        return

    if cmd.startswith("!unmute"):
        is_muted = False
        message_window.clear()
        global_alert_sent_times.clear()  # 전역 발언 제한 카운터 초기화
        try:
            app.client.chat_postMessage(channel=channel, text="🔔 Bot unmute 되었습니다. (카운트 초기화)")
        except Exception as e:
            print(f"[UNMUTE_REPLY_FAIL] {repr(e)}")
        return

    process_message(event)


# --------------------------------------------------------
# Slash commands (등록돼 있어야 작동)
# --------------------------------------------------------
@app.command("/mute")
def slash_mute(ack, respond):
    global is_muted
    ack()
    is_muted = True
    respond("🔇 Bot mute 설정 완료")


@app.command("/unmute")
def slash_unmute(ack, respond):
    global is_muted
    ack()
    is_muted = False
    message_window.clear()
    global_alert_sent_times.clear()  # 전역 발언 제한 카운터 초기화
    respond("🔔 Bot unmute 완료 (카운트 초기화)")


# --------------------------------------------------------
# main
# --------------------------------------------------------
if __name__ == "__main__":
    init_bot_identity()
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
