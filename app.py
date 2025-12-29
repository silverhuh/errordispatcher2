import os
import time
from collections import defaultdict, deque

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# --------------------------------------------------------
# Slack App 초기화 (Railway 환경변수 사용)
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
ERROR_AX_CH = "C0A2ZM3EMBN"
TEST_ALERT_CH = "C092DJVHVPY"

# TODO: #에이닷_오픈_모니터링 채널 ID로 교체
OPEN_MONITORING_CH = "C09BLHZAPSS"   # #에이닷_오픈_모니터링

# --------------------------------------------------------
# 멘션 ID 정의
# --------------------------------------------------------
MENTION_HEO = "<@U04MGC3BFCY>"   # 허은석님

MENTION_KDW = "<@U03H53S4B2B>"   # 김동우님
MENTION_NJK = "<@U03L9HG1Q49>"   # 노정규님
MENTION_JJY = "<@U03J9DUADJ4>"   # 정주영님

MENTION_KJH = "<@U04M5AFPQHF>"   # 김지환님
MENTION_KHR = "<@U04LSM49TR8>"   # 김학래님

MENTION_KYH = "<@U063M2LKNA1>"   # 김용현님
MENTION_GJH = "<@U063M2QM89K>"   # 구진현님
MENTION_YYJ = "<@U04LSHPDC03>"   # 양영준님
MENTION_PJY = "<@U05319QDEET>"   # 박지윤님

MENTION_KAI = "<@U06NSJVR0GH>"   # Kai님
MENTION_BSR = "<@U08DS680G7L>"   # 백승렬님

MENTION_KSW = "<@U04MGC174HE>"   # 김성완님
MENTION_LYS = "<@U04LV5K4PA8>"   # 이영순님

MENTION_GMS = "<@U04M5A7194H>"   # 고민석님
MENTION_KTH = "<@U04LPNR61BP>"   # 강태희님
MENTION_JUR = "<@U05BK5TSBRV>"   # 조욱래님

MENTION_SYC = "<@U04LSHQMADR>"   # 신윤철님

MENTION_PYH = "<@U09AS8FCQD9>"   # 박윤호님
MENTION_NSH = "<@U01RWQ5QLER>"   # 남소희님
MENTION_LJH = "<@UF7ELUSJV>"     # 이재한님

MENTION_KHJ = "<@U04LC55FDN3>"   # 김현준님
MENTION_PJH = "<@U04LL3F11C6>"   # 박지형님

# --------------------------------------------------------
# 공통 설정
# --------------------------------------------------------
WINDOW_SECONDS = 180          # 3분
ALERT_COOLDOWN_SECONDS = 240  # 4분 (룰/채널별 쿨다운으로 적용)

# (channel, rule_name) -> deque[timestamp]
message_window = defaultdict(deque)

# ✅ (channel, rule_name) -> last alert timestamp
last_alert_sent_at = defaultdict(float)

# ✅ mute flag
is_muted = False

# ✅ bot user id
BOT_USER_ID = None

# --------------------------------------------------------
# 규칙 정의 (네가 올린 RULES 그대로)
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
                "text": (
                    f"{ALERT_PREFIX} 노트 에러(RTZR_API)가 감지되어 담당자 전달하였습니다. "
                    f"(cc. {MENTION_HEO}님)"
                ),
                "include_log": False,
            },
            {
                "channel": RTZR_STT_SKT_ALERT_CH,
                "text": (
                    f"{ALERT_PREFIX} RTZR_API 5회 이상 감지중! "
                    f"{MENTION_KDW}님, {MENTION_NJK}님, {MENTION_JJY}님 확인 문의드립니다. "
                    f"(cc. {MENTION_HEO}님)"
                ),
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
                "text": (
                    f"{ALERT_PREFIX} 노트 에러(PET_API) 5회 이상 감지중! "
                    f"{MENTION_KJH}님, {MENTION_KHR}님 확인 문의드립니다. "
                    f"(cc. {MENTION_HEO}님)"
                ),
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
                "text": f"{ALERT_PREFIX} One Agent 에러가 감지되었습니다. (cc. {MENTION_HEO}님)",
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

    # Claude
    {
        "name": "CLAUDE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Claude",
        "threshold": 5,
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

    # GPT
    {
        "name": "GPT",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "MODEL_LABEL: GPT",
        "threshold": 5,
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

    # Gemini
    {
        "name": "GEMINI",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Gemini",
        "threshold": 5,
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

    # Liner
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

    # A.X
    {
        "name": "AX",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "A.X",
        "threshold": 5,
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

    # REQUEST_ID
    {
        "name": "REQUEST_ID",
        "channel": SVC_BTV_DIV_CH,
        "keyword": "REQUEST_ID",
        "threshold": 5,
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

    # test 채널 테스트용
    {
        "name": "TEST",
        "channel": TEST_ALERT_CH,
        "keyword": "builtin.one",
        "threshold": 3,
        "notify": [
            {
                "channel": TEST_ALERT_CH,
                "text": f"{ALERT_PREFIX} 테스트 알림: test 감지됨.",
                "include_log": False,
            },
        ],
    },

    # API (키워드 포함 시)
    {
        "name": "API",
        "channel": SVC_TMAP_DIV_CH,
        "keyword": "API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_TMAP_DIV_CH,
                "text": (
                    f"{ALERT_PREFIX} TMAP API 에러가 감지되어 티모비 담당자에게 전파하였습니다. "
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
# 헬퍼 함수
# --------------------------------------------------------
def init_bot_user_id():
    global BOT_USER_ID
    try:
        BOT_USER_ID = app.client.auth_test()["user_id"]
    except Exception:
        BOT_USER_ID = None


def prune_old_events(key, now_ts):
    dq = message_window[key]
    while dq and now_ts - dq[0] > WINDOW_SECONDS:
        dq.popleft()


def can_send_alert(key, now_ts):
    # key = (channel, rule_name)
    if is_muted:
        return False
    last = last_alert_sent_at.get(key, 0)
    return (now_ts - last) >= ALERT_COOLDOWN_SECONDS


def send_alert_for_rule(rule, event):
    channel = event.get("channel")
    rule_name = rule["name"]
    key = (channel, rule_name)

    now_ts = time.time()
    if not can_send_alert(key, now_ts):
        return

    original_text = event.get("text", "") or ""

    for action in rule["notify"]:
        text = action["text"]
        if action.get("include_log"):
            text += f"\n\n```{original_text}```"
        app.client.chat_postMessage(channel=action["channel"], text=text)

    last_alert_sent_at[key] = now_ts


def process_message(event):
    channel = event.get("channel")
    text = (event.get("text") or "")
    now_ts = time.time()

    # 1) RULES 기반 감지 (대소문자 무시)
    for rule in RULES:
        if channel != rule["channel"]:
            continue
        if rule["keyword"].lower() not in text.lower():
            continue

        key = (channel, rule["name"])
        prune_old_events(key, now_ts)

        message_window[key].append(now_ts)

        if len(message_window[key]) >= rule["threshold"]:
            send_alert_for_rule(rule, event)
            message_window[key].clear()

    # 2) API 미포함 카운팅 (SVC_TMAP_DIV_CH 전용)
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
                            f"{ALERT_PREFIX} 에러가 감지되어 확인 문의드립니다. "
                            f"{MENTION_KHJ}님, {MENTION_PJH}님 (cc. {MENTION_GMS}님, {MENTION_JUR}님, {MENTION_HEO}님)"
                        ),
                        "include_log": False,
                    }
                ],
            }
            send_alert_for_rule(pseudo_rule, event)
            message_window[key].clear()


# --------------------------------------------------------
# Slack 메시지 이벤트
# --------------------------------------------------------
@app.event("message")
def handle_message(body, say):
    event = body.get("event", {}) or {}

    # ✅ 봇/수정 메시지 등 subtype 무시
    if event.get("subtype") is not None:
        return

    # ✅ bot 메시지 무시
    if event.get("bot_id") is not None:
        return

    # ✅ 자기 자신 메시지 무시
    if BOT_USER_ID and event.get("user") == BOT_USER_ID:
        return

    text = (event.get("text") or "")
    cmd = text.strip().lower()

    global is_muted

    # ✅ !mute/!unmute 파싱 완화
    if cmd.startswith("!mute"):
        is_muted = True
        say("🔇 Bot mute 상태입니다.")
        return

    if cmd.startswith("!unmute"):
        is_muted = False
        message_window.clear()
        last_alert_sent_at.clear()
        say("🔔 Bot unmute 되었습니다. (카운트/쿨다운 초기화)")
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
    global is_muted
    ack()
    is_muted = False
    message_window.clear()
    last_alert_sent_at.clear()
    respond("🔔 Bot unmute 완료 (카운트/쿨다운 초기화)")


# --------------------------------------------------------
# 실행
# --------------------------------------------------------
if __name__ == "__main__":
    init_bot_user_id()
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
