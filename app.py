import os
import time
import threading
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

# ✅ 전역 "트리거" 제한: 5분 동안 1회
GLOBAL_RATE_WINDOW_SECONDS = 300
GLOBAL_RATE_LIMIT_COUNT = 1
global_alert_sent_times = deque()  # "트리거 성공" timestamps (notify 개수와 무관)

message_window = defaultdict(deque)  # (channel, rule) -> deque[timestamps]
is_muted = False

# 내 봇 식별용
BOT_USER_ID = None
BOT_ID = None  # event.get("bot_id") 비교용(있으면 더 안전)

# --------------------------------------------------------
# 🔧 동시성/레이스 방지용 락
# --------------------------------------------------------
rate_lock = threading.Lock()

# --------------------------------------------------------
# 🔧 Slack 중복 이벤트(재시도/중복전달) 방지용 dedupe
# --------------------------------------------------------
EVENT_DEDUPE_TTL_SECONDS = 600  # 10분
recent_event_ids = deque()      # (ts, event_id)
recent_event_id_set = set()

def dedupe_event(event_id: str, now_ts: float) -> bool:
    """
    True  -> 이미 처리한 이벤트(중복)라서 skip
    False -> 처음 보는 이벤트라서 처리 계속
    """
    if not event_id:
        return False

    while recent_event_ids and (now_ts - recent_event_ids[0][0] > EVENT_DEDUPE_TTL_SECONDS):
        old_ts, old_id = recent_event_ids.popleft()
        recent_event_id_set.discard(old_id)

    if event_id in recent_event_id_set:
        return True

    recent_event_ids.append((now_ts, event_id))
    recent_event_id_set.add(event_id)
    return False


# --------------------------------------------------------
# RULES (✅ 사용자가 준 내용 그대로 유지)
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
                    f"{ALERT_PREFIX} RTZR_API 5회 이상 감지중! "
                    f"{MENTION_KDW}님, {MENTION_NJK}님, {MENTION_JJY}님 확인 문의드립니다. "
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
        "threshold": 2,
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


def prune_global_triggers(now_ts: float):
    while global_alert_sent_times and (now_ts - global_alert_sent_times[0] > GLOBAL_RATE_WINDOW_SECONDS):
        global_alert_sent_times.popleft()


def try_reserve_global_trigger(now_ts: float):
    """
    🔥 핵심:
    - 전역 5분 1회 제한은 "트리거 단위"로 카운트
    - notify가 여러 채널이어도 트리거 1개로만 카운트
    - 동시성 레이스 방지를 위해 '선점'을 원자적으로 수행
    """
    global is_muted
    with rate_lock:
        if is_muted:
            return None
        prune_global_triggers(now_ts)
        if len(global_alert_sent_times) >= GLOBAL_RATE_LIMIT_COUNT:
            return None
        global_alert_sent_times.append(now_ts)  # 선점(예약)
        return now_ts  # token


def rollback_reserved_trigger(token_ts: float):
    """
    전송이 '단 1건도 성공하지 않은 경우'에만 롤백(선택적).
    """
    if token_ts is None:
        return
    with rate_lock:
        # 가장 끝이 토큰이면 pop (정상 케이스)
        if global_alert_sent_times and global_alert_sent_times[-1] == token_ts:
            global_alert_sent_times.pop()
            return
        # 혹시 다른 순서로 섞였으면 1회 제거(보수적)
        try:
            global_alert_sent_times.remove(token_ts)
        except ValueError:
            pass


def keyword_hits_in_text(keyword: str, text: str) -> int:
    if not keyword or not text:
        return 0
    return text.lower().count(keyword.lower())


def send_alert_for_rule(rule, event):
    """
    ✅ 전역 제한(5분 1회)은 '트리거' 기준
    ✅ 트리거가 허용되면 rule.notify는 "전부" 전송한다 (여러 채널 OK)
    ✅ notify 개수와 관계없이 전역 카운트는 1회로만 처리한다
    """
    now_ts = time.time()
    original_text = event.get("text", "") or ""
    rule_name = rule.get("name")

    token = try_reserve_global_trigger(now_ts)
    if token is None:
        return  # 5분 내 이미 트리거가 발생했거나 mute

    sent_any = False
    errors = []

    for action in rule.get("notify", []):
        target_channel = action.get("channel")
        try:
            text = action["text"]
            if action.get("include_log"):
                text += f"\n\n```{original_text}```"

            app.client.chat_postMessage(channel=target_channel, text=text)
            sent_any = True

        except Exception as e:
            errors.append(f"{target_channel} -> {repr(e)}")

    # 전송이 "단 1건도" 성공 못했으면, 트리거 선점 롤백(선택적이지만 보통 유용)
    if not sent_any:
        rollback_reserved_trigger(token)

    if errors:
        src_channel = event.get("channel")
        print(f"[ALERT_PARTIAL_FAIL] rule={rule_name} src_channel={src_channel} errors={errors}")


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

        for _ in range(hits):
            message_window[key].append(now_ts)

        if len(message_window[key]) >= rule["threshold"]:
            send_alert_for_rule(rule, event)
            message_window[key].clear()

    # 2) TMAP 채널 전용: "API" 미포함 메시지 5회 (✅ 기존 기능 유지)
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
    now_ts = time.time()

    # 🔧 중복 이벤트 방지
    event_id = body.get("event_id") or event.get("event_id") or event.get("client_msg_id")
    with rate_lock:
        if dedupe_event(str(event_id) if event_id else "", now_ts):
            return

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
        with rate_lock:
            is_muted = True
            global_alert_sent_times.clear()
        try:
            app.client.chat_postMessage(channel=channel, text="🔇 Bot mute 상태입니다.")
        except Exception as e:
            print(f"[MUTE_REPLY_FAIL] {repr(e)}")
        return

    if cmd.startswith("!unmute"):
        with rate_lock:
            is_muted = False
            message_window.clear()
            global_alert_sent_times.clear()
        try:
            app.client.chat_postMessage(channel=channel, text="🔔 Bot unmute 되었습니다.")
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
    with rate_lock:
        is_muted = True
        global_alert_sent_times.clear()
    respond("🔇 Bot mute 설정 완료")


@app.command("/unmute")
def slash_unmute(ack, respond):
    global is_muted
    ack()
    with rate_lock:
        is_muted = False
        message_window.clear()
        global_alert_sent_times.clear()
    respond("🔔 Bot unmute 완료 (카운트 초기화)")


# --------------------------------------------------------
# main
# --------------------------------------------------------
if __name__ == "__main__":
    init_bot_identity()
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
