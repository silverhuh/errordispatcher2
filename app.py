import os
import time
from collections import defaultdict, deque

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# --------------------------------------------------------
# 환경 변수 (Railway 환경변수에서 주입)
# --------------------------------------------------------
# SLACK_BOT_TOKEN, SLACK_APP_TOKEN 을 Railway 환경변수에 설정해 두고 사용합니다.
app = App(token=os.environ["SLACK_BOT_TOKEN"])

# 경고 아이콘 prefix
ALERT_PREFIX = "⚠️ "

# --------------------------------------------------------
# 채널/유저 ID 설정
# --------------------------------------------------------
SVC_WATCHTOWER_CH = "C04M1UCMCFQ"           # svc_watchtower
SVC_TMAP_DIV_CH = "C09BY22G12Q"             # svc_watchtower_tmap_divergence
SVC_BTV_DIV_CH = "C077QK6NB4K"              # svc_watchtower_btv_divergence

RTZR_STT_SKT_ALERT_CH = "C091J89DQF7"       # rtzr-stt-skt-alert
EXT_GIP_REPAIRING_CH = "C06L4C7HUCF"        # ext_gip_repairing
LINER_ADOT_CH = "C08DRU0U7CK"               # liner-adot
ERROR_AX_CH = "C09SQLEU8N8"                 # error_A.X
TEST_ALERT_CH = "C092DJVHVPY"               # Test용 채널

# 유저 멘션 ID
MENTION_HEO_EUNSEOK = "<@U04MGC3BFCY>"

MENTION_KIM_DONGWOO = "<@U03H53S4B2B>"
MENTION_NO_JUNGKYU = "<@U03L9HG1Q49>"
MENTION_JUNG_JUYOUNG = "<@U03J9DUADJ4>"

MENTION_KIM_JIHWAN = "<@U04M5AFPQHF>"
MENTION_KIM_HAKRAE = "<@U04LSM49TR8>"

MENTION_KIM_YONGHYUN = "<@U063M2LKNA1>"
MENTION_GU_JINHYUN = "<@U063M2QM89K>"
MENTION_YANG_YOUNGJOON = "<@U04LSHPDC03>"
MENTION_PARK_JIYOON = "<@U05319QDEET>"

MENTION_KAI = "<@U06NSJVR0GH>"
MENTION_BAEK_SEUNGRYEOL = "<@U08DS680G7L>"

MENTION_KIM_SEONGWAN = "<@U04MGC174HE>"
MENTION_LEE_YOUNGSOON = "<@U04LV5K4PA8>"

MENTION_GO_MINSEOK = "<@U04M5A7194H>"
MENTION_KANG_TAEHEE = "<@U04LPNR61BP>"
MENTION_JO_UKRAE = "<@U05BK5TSBRV>"

MENTION_SHIN_YUNCHUL = "<@U04LSHQMADR>"

# --------------------------------------------------------
# 공통 설정
# --------------------------------------------------------
WINDOW_SECONDS = 3 * 60        # 3분
ALERT_COOLDOWN_SECONDS = 10 * 60  # 10분 내 1회만 발화

# (channel_id, rule_name) 별로 최근 n분간 발생 시간 저장
message_window = defaultdict(deque)  # key: (channel, rule_name) -> deque[timestamp]
# 마지막 트리거된 메시지 (원본 로그 전달용)
last_message_by_rule = {}  # key: (channel, rule_name) -> event(dict)

# 전역 쿨다운 및 mute 상태
last_alert_sent_at = 0.0
is_muted = False

# --------------------------------------------------------
# 규칙 정의
# --------------------------------------------------------
RULES = [
    # svc_watchtower / RTZR_API 3분 이내 5회 이상
    {
        "name": "RTZR_API",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "RTZR_API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}노트 에러(RTZR_API)가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": RTZR_STT_SKT_ALERT_CH,
                "text": (
                    f"{ALERT_PREFIX}RTZR_API 5회 이상 감지중! "
                    f"{MENTION_KIM_DONGWOO}, {MENTION_NO_JUNGKYU}, {MENTION_JUNG_JUYOUNG} "
                    f"확인 문의드립니다. (cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False,
            },
        ],
    },
    # svc_watchtower / PET_API 3분 이내 5회 이상
    {
        "name": "PET_API",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "PET_API",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": (
                    f"{ALERT_PREFIX}노트 에러(PET_API) 5회 이상 감지중! "
                    f"{MENTION_KIM_JIHWAN}, {MENTION_KIM_HAKRAE} 확인 문의드립니다. "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False,
            },
        ],
    },
    # svc_watchtower / builtin.one 3분 이내 7회 이상
    {
        "name": "BUILTIN_ONE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "builtin.one",
        "threshold": 7,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}One Agent 에러가 감지되었습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
        ],
    },
    # svc_watchtower / Perplexity 3분 이내 5회 이상
    {
        "name": "PERPLEXITY",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Perplexity",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}Perplexity 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX}Perplexity 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True,
            },
        ],
    },
    # svc_watchtower / Claude 3분 이내 5회 이상
    {
        "name": "CLAUDE",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Claude",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}Claude 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX}Claude 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True,
            },
        ],
    },
    # svc_watchtower / MODEL_LABEL: GPT 3분 이내 5회 이상
    {
        "name": "GPT",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "MODEL_LABEL: GPT",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}GPT 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX}GPT 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True,
            },
        ],
    },
    # svc_watchtower / Gemini 3분 이내 5회 이상
    {
        "name": "GEMINI",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Gemini",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}Gemini 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": EXT_GIP_REPAIRING_CH,
                "text": (
                    f"{ALERT_PREFIX}Gemini 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True,
            },
        ],
    },
    # svc_watchtower / Liner 3분 이내 5회 이상
    {
        "name": "LINER",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "Liner",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}Liner 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": LINER_ADOT_CH,
                "text": (
                    f"{ALERT_PREFIX}Liner 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KAI}, {MENTION_BAEK_SEUNGRYEOL} "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True,
            },
        ],
    },
    # svc_watchtower / A.X 3분 이내 5회 이상
    {
        "name": "AX",
        "channel": SVC_WATCHTOWER_CH,
        "keyword": "A.X",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_WATCHTOWER_CH,
                "text": f"{ALERT_PREFIX}A.X 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False,
            },
            {
                "channel": ERROR_AX_CH,
                "text": (
                    f"{ALERT_PREFIX}A.X 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_SEONGWAN}, {MENTION_LEE_YOUNGSOON} "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True,
            },
        ],
    },
    # svc_watchtower_tmap_divergence / agent.tmap 3분 이내 5회 이상
    {
        "name": "AGENT_TMAP",
        "channel": SVC_TMAP_DIV_CH,
        "keyword": "agent.tmap",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_TMAP_DIV_CH,
                "text": (
                    f"{ALERT_PREFIX}에러가 감지되어 확인 문의드립니다. "
                    f"{MENTION_GO_MINSEOK}, {MENTION_KANG_TAEHEE} "
                    f"(cc. {MENTION_JO_UKRAE}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False,
            },
        ],
    },
    # svc_watchtower_btv_divergence / REQUEST_ID 3분 이내 5회 이상
    {
        "name": "REQUEST_ID",
        "channel": SVC_BTV_DIV_CH,
        "keyword": "REQUEST_ID",
        "threshold": 5,
        "notify": [
            {
                "channel": SVC_BTV_DIV_CH,
                "text": (
                    f"{ALERT_PREFIX}에러가 감지되어 확인 문의드립니다. "
                    f"{MENTION_SHIN_YUNCHUL}, {MENTION_GO_MINSEOK} "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False,
            },
        ],
    },
    # C092DJVHVPY / Test 3분 이내 5회 이상
    {
        "name": "TEST",
        "channel": TEST_ALERT_CH,
        "keyword": "Test",
        "threshold": 5,
        "notify": [
            {
                "channel": TEST_ALERT_CH,
                "text": "장애 Test",
                "include_log": False,
            },
        ],
    },
]

# --------------------------------------------------------
# 헬퍼 함수들
# --------------------------------------------------------
def prune_old_events(key, now_ts, window_seconds):
    """주어진 key에 대해 window_seconds 보다 오래된 timestamp 제거"""
    dq = message_window[key]
    while dq and now_ts - dq[0] > window_seconds:
        dq.popleft()


def can_send_alert(now_ts):
    """10분 쿨다운 및 mute 여부 확인"""
    global last_alert_sent_at, is_muted
    if is_muted:
        return False
    if now_ts - last_alert_sent_at < ALERT_COOLDOWN_SECONDS:
        return False
    return True


def send_alert_for_rule(rule, event):
    """규칙 만족 시 알림 발송"""
    global last_alert_sent_at

    now_ts = time.time()
    if not can_send_alert(now_ts):
        return

    original_text = event.get("text", "")

    for action in rule["notify"]:
        text = action["text"]
        if action.get("include_log"):
            # svc_watchtower의 에러 log 1개를 함께 전달
            text = text + f"\n\n원본 로그:\n```{original_text}```"

        try:
            app.client.chat_postMessage(
                channel=action["channel"],
                text=text,
            )
        except Exception as e:
            print(f"Failed to send alert for {rule['name']}: {e}")

    last_alert_sent_at = now_ts


def process_message(event):
    """Slack message 이벤트 처리"""
    channel = event.get("channel")
    text = event.get("text", "") or ""
    if not text:
        return

    now_ts = time.time()

    for rule in RULES:
        # 채널이 다르면 스킵
        if channel != rule["channel"]:
            continue
        # 키워드 포함 안되면 스킵 (단순 substring)
        if rule["keyword"] not in text:
            continue

        key = (channel, rule["name"])
        prune_old_events(key, now_ts, WINDOW_SECONDS)

        # 이번 이벤트 추가
        message_window[key].append(now_ts)
        last_message_by_rule[key] = event

        # threshold 체크
        if len(message_window[key]) >= rule["threshold"]:
            # 조건 만족 시 알림 발송
            send_alert_for_rule(rule, last_message_by_rule[key])
            # 한 번 트리거 후 window 비워서 중복 트리거 감소
            message_window[key].clear()


# --------------------------------------------------------
# Slack 이벤트 핸들러
#   → 여기서 !mute / !unmute 처리
# --------------------------------------------------------
@app.event("message")
def handle_message_events(body, say, logger):
    global is_muted, last_alert_sent_at, message_window

    event = body.get("event", {})
    # 봇이 보낸 메시지면 무시
    if event.get("subtype") == "bot_message":
        return
    if event.get("bot_id"):
        return

    text = (event.get("text") or "").strip()

    # 1) 채팅에서 직접 !mute 입력 시 봇 발언 제한
    if text == "!mute":
        is_muted = True
        say("🔇 알림 봇이 *mute* 상태가 되었습니다. ('!unmute' 또는 `/unmute`로 해제 가능)")
        return

    # 2) 채팅에서 직접 !unmute 입력 시 봇 발언 재개 + 카운트/쿨다운 초기화
    if text == "!unmute":
        is_muted = False
        last_alert_sent_at = 0.0
        message_window.clear()
        say("🔔 알림 봇 *mute 해제* 되었습니다. (카운트 및 쿨다운도 초기화)")
        return

    # 나머지 일반 메시지는 기존 감지 로직으로 처리
    try:
        process_message(event)
    except Exception as e:
        logger.error(f"Error processing message: {e}")


# --------------------------------------------------------
# /mute, /unmute Slash Command (기존 기능 유지)
# --------------------------------------------------------
@app.command("/mute")
def handle_mute(ack, respond, command):
    """
    봇 발화 전체 mute (Slash Command)
    """
    global is_muted
    ack()
    is_muted = True
    respond("🔇 알림 봇이 *mute* 상태가 되었습니다. (/unmute 또는 '!unmute'로 해제 가능)")


@app.command("/unmute")
def handle_unmute(ack, respond, command):
    """
    봇 발화 다시 활성화 (Slash Command)
    """
    global is_muted, last_alert_sent_at, message_window
    ack()
    is_muted = False
    # 다시 켤 때는 이전 카운트/쿨다운 초기화
    last_alert_sent_at = 0.0
    message_window.clear()
    respond("🔔 알림 봇 *mute 해제* 되었습니다. (카운트 및 쿨다운도 초기화)")


# --------------------------------------------------------
# 메인
# --------------------------------------------------------
if __name__ == "__main__":
    handler = SocketModeHandler(app, os.environ["SLACK_APP_TOKEN"])
    handler.start()
