# --------------------------------------------------------
# BOOT 로그 (인스턴스/재기동 확인용)
# --------------------------------------------------------
import os, socket, time as _time
print(
    f"[BOOT] pid={os.getpid()} "
    f"host={socket.gethostname()} "
    f"time={_time.time()}"
)

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
WINDOW_SECONDS = 240
GLOBAL_RATE_WINDOW_SECONDS = 300  # 5분
GLOBAL_RATE_LIMIT_COUNT = 1       # 5분 내 1회 제한

# 전역 상태 변수
global_alert_sent_times = deque()
message_window = defaultdict(deque)
is_muted = False

# Thread Safety Lock (동시성 제어 핵심)
state_lock = threading.Lock()

BOT_USER_ID = None
BOT_ID = None

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
                "text": f"{ALERT_PREFIX} Test 메시지 : 노트 에러(RTZR_API)가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": RTZR_STT_SKT_ALERT_CH,
                "text": f"{ALERT_PREFIX} Test 메시지 입니다. (cc. {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} 노트 에러(PET_API) 5회 이상 감지중! {MENTION_KJH}님, {MENTION_KHR}님 확인 문의드립니다. (cc. {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} One Agent 에러가 감지되었습니다. (cc. {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} Perplexity 에러가 발생되어 확인 문의드립니다. {MENTION_KYH}님, {MENTION_GJH}님 (cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} Claude 에러가 발생되어 확인 문의드립니다. {MENTION_KYH}님, {MENTION_GJH}님 (cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} GPT 에러가 발생되어 확인 문의드립니다. {MENTION_KYH}님, {MENTION_GJH}님 (cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} Gemini 에러가 발생되어 확인 문의드립니다. {MENTION_KYH}님, {MENTION_GJH}님 (cc. {MENTION_YYJ}님, {MENTION_PJY}님, {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} Liner 에러가 발생되어 확인 문의드립니다. {MENTION_KAI}님, {MENTION_BSR}님 (cc. {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} A.X 에러가 발생되어 확인 문의드립니다. {MENTION_KSW}님, {MENTION_LYS}님 (cc. {MENTION_HEO}님)",
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
                "text": f"{ALERT_PREFIX} 에러가 감지되어 확인 문의드립니다. {MENTION_SYC}님, {MENTION_GMS}님 (cc. {MENTION_HEO}님)",
                "include_log": False,
            },
        ],
    },
    {
        "name": "TEST",
        "channel": TEST_ALERT_CH,
        "keyword": "test",
        "threshold": 5,
        "notify": [
            {
                "channel": TEST_ALERT_CH,
                "text": f"{ALERT_PREFIX} 테스트 알림: test 감지됨.",
                "include_log": False,
            },
        ],
    },
    {
        "name": "API",
        "channel": SVC_TMAP_DIV_CH,
        "keyword": "API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_TMAP_DIV_CH,
                "text": f"{ALERT_PREFIX} TMAP API 에러가 감지되어 티모비 채널에 전파하였습니다. (cc. {MENTION_GMS}님, {MENTION_JUR}님, {MENTION_HEO}님)",
                "include_log": False,
            },
            {
                "channel": OPEN_MONITORING_CH,
                "text": f"{ALERT_PREFIX} TMAP API 에러가 지속 감지되어 확인 문의드립니다. <!here>\n(cc. {MENTION_HEO}님)",
                "include_log": False,
            },
        ],
    },
]

# --------------------------------------------------------
# Helpers
# --------------------------------------------------------
def init_bot_identity():
    global BOT_USER_ID, BOT_ID
    try:
        resp = app.client.auth_test()
        BOT_USER_ID = resp.get("user_id")
        BOT_ID = resp.get("bot_id")
        print(f"[BOOT] BOT_USER_ID={BOT_USER_ID}, BOT_ID={BOT_ID}")
    except Exception as e:
        print(f"[BOOT] auth_test failed: {repr(e)}")

def prune_old_events(key, now_ts: float):
    dq = message_window[key]
    while dq and now_ts - dq[0] > WINDOW_SECONDS:
        dq.popleft()

def prune_global_alerts(now_ts: float):
    while global_alert_sent_times and (now_ts - global_alert_sent_times[0] > GLOBAL_RATE_WINDOW_SECONDS):
        global_alert_sent_times.popleft()

def keyword_hits_in_text(keyword: str, text: str) -> int:
    if not keyword or not text:
        return 0
    return text.lower().count(keyword.lower())

# ✅ [핵심] 선점(Reservation) 로직
# "보낼 수 있어?" 가 아니라 "나 보낸다!" 하고 깃발을 먼저 꽂습니다.
def try_reserve_global_slot(now_ts: float) -> bool:
    with state_lock:
        # 1. Mute 상태면 무조건 실패
        if is_muted:
            print("[SKIP] Muted state.")
            return False
        
        # 2. 시간 지난 기록 삭제
        prune_global_alerts(now_ts)
        
        # 3. 꽉 찼으면 실패 (엄격한 검사)
        if len(global_alert_sent_times) >= GLOBAL_RATE_LIMIT_COUNT:
            print(f"[SKIP] Rate limit reached. count={len(global_alert_sent_times)}")
            return False
        
        # 4. 자리 선점 (중요: 전송 전에 미리 넣음)
        global_alert_sent_times.append(now_ts)
        return True

# ✅ [핵심] 롤백(Rollback) 로직
# 전송하다가 에러나면 "아까 꽂은 깃발 취소"
def rollback_global_slot(now_ts: float):
    with state_lock:
        if global_alert_sent_times and global_alert_sent_times[-1] == now_ts:
            global_alert_sent_times.pop()
            print("[ROLLBACK] Alert send failed, slot restored.")

def send_alert_for_rule(rule, event) -> bool:
    now_ts = time.time()
    original_text = event.get("text", "") or ""
    rule_name = rule.get("name")
    src_channel = event.get("channel")

    # 1. [선점 시도] 티켓을 먼저 끊습니다. (실패하면 즉시 중단)
    if not try_reserve_global_slot(now_ts):
        return False

    # 2. [전송 수행] 티켓을 가진 스레드만 실행됩니다.
    errors = []
    success = False

    try:
        for action in rule.get("notify", []):
            target_channel = action["channel"]
            text = action["text"]
            if action.get("include_log"):
                text += f"\n\n```{original_text}```"

            try:
                app.client.chat_postMessage(channel=target_channel, text=text)
                success = True # 하나라도 성공하면 성공으로 간주
                print(f"[ALERT_SENT] rule={rule_name} src={src_channel} -> {target_channel}")
            except Exception as e:
                errors.append(f"{target_channel}: {e}")

    except Exception as e:
        errors.append(f"Fatal: {e}")

    # 3. [사후 처리] 전송 실패했으면 티켓 환불(롤백)
    if not success:
        rollback_global_slot(now_ts)
        if errors:
            print(f"[ALERT_FAIL] rule={rule_name} errors={errors}")
        return False
    
    return True

def process_message(event):
    now_ts = time.time()
    channel = event.get("channel")
    text = (event.get("text") or "")

    # Mute 체크 (CPU 낭비 방지용 early check)
    with state_lock:
        if is_muted:
            return

    # 1) RULES 기반 감지
    for rule in RULES:
        if channel != rule["channel"]:
            continue

        hits = keyword_hits_in_text(rule["keyword"], text)
        if hits <= 0:
            continue

        key = (channel, rule["name"])

        # 카운트 증가 로직
        triggered = False
        with state_lock:
            prune_old_events(key, now_ts)
            for _ in range(hits):
                message_window[key].append(now_ts)
            
            triggered = len(message_window[key]) >= rule["threshold"]

        if triggered:
            # 알림 시도 (여기서 Rate Limit 걸리면 False 반환)
            sent = send_alert_for_rule(rule, event)
            
            # ✅ 중요: 알림이 성공적으로 나갔을 때만 카운트 초기화
            # 실패(Rate Limit 등)했다면 카운트를 유지해서, 
            # 5분 뒤 제한이 풀리면 다음 메시지에서 즉시 알림이 나가도록 함
            if sent:
                with state_lock:
                    message_window[key].clear()
                return # 이번 메시지 처리 끝

    # 2) TMAP 채널 전용 룰
    if channel == SVC_TMAP_DIV_CH and "api" not in text.lower():
        key = (channel, "TMAP_API_MISSING")
        triggered = False
        with state_lock:
            prune_old_events(key, now_ts)
            message_window[key].append(now_ts)
            triggered = len(message_window[key]) >= 5
        
        if triggered:
            pseudo_rule = {
                "name": "TMAP_API_MISSING",
                "notify": [{
                    "channel": SVC_TMAP_DIV_CH,
                    "text": f"{ALERT_PREFIX} 내부 원인 추정 에러 감지. {MENTION_KHJ}님, {MENTION_PJH}님 (cc. {MENTION_GMS}님, {MENTION_JUR}님, {MENTION_HEO}님)",
                    "include_log": False
                }]
            }
            sent = send_alert_for_rule(pseudo_rule, event)
            if sent:
                with state_lock:
                    message_window[key].clear()
                return

# --------------------------------------------------------
# Slack message event
# --------------------------------------------------------
@app.event("message")
def handle_message(body, say):
    event = body.get("event", {})
    if event.get("subtype") is not None:
        return

    # 내 봇 무시
    if BOT_USER_ID and event.get("user") == BOT_USER_ID: return
    if BOT_ID and event.get("bot_id") == BOT_ID: return

    channel = event.get("channel")
    text = (event.get("text") or "").strip()
    cmd = text.lower()

    global is_muted

    # 명령어 처리 (명령어는 Mute 상태에서도 동작해야 함)
    if cmd.startswith("!mute"):
        with state_lock:
            is_muted = True
            message_window.clear() # 기존 카운트 모두 초기화
            global_alert_sent_times.clear() # 쿨타임 초기화
        try:
            app.client.chat_postMessage(channel=channel, text="🔇 Bot mute 상태입니다. (모든 알림 중단)")
        except Exception as e:
            print(f"[MUTE_CMD_FAIL] {e}")
        return

    if cmd.startswith("!unmute"):
        with state_lock:
            is_muted = False
            message_window.clear()
            global_alert_sent_times.clear()
        try:
            app.client.chat_postMessage(channel=channel, text="🔔 Bot unmute 되었습니다.")
        except Exception as e:
            print(f"[UNMUTE_CMD_FAIL] {e}")
        return

    process_message(event)

# --------------------------------------------------------
# Slash commands
# --------------------------------------------------------
@app.command("/mute")
def slash_mute(ack, respond):
    global is_muted
    ack()
    with state_lock:
        is_muted = True
        message_window.clear()
        global_alert_sent_times.clear()
    respond("🔇 Bot mute 설정 완료")

@app.command("/unmute")
def slash_unmute(ack, respond):
    global is_muted
    ack()
    with state_lock:
        is_muted = False
        message_window.clear()
        global_alert_sent_times.clear()
    respond("🔔 Bot unmute 완료")

# --------------------------------------------------------
# main
# --------------------------------------------------------
if __name__ == "__main__":
    init_bot_identity()
    SocketModeHandler(app, SLACK_APP_TOKEN).start()
