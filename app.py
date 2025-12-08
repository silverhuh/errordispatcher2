import os
import time
from collections import defaultdict, deque

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

# --------------------------------------------------------
# 슬랙 토큰 가져오기 (Railway Variables에서 넣을 예정)
# --------------------------------------------------------
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")

if not SLACK_BOT_TOKEN or not SLACK_APP_TOKEN:
    print("❌ SLACK_BOT_TOKEN 또는 SLACK_APP_TOKEN 환경변수가 없습니다.")
    print("Railway → Variables 탭에서 두 값(xoxb..., xapp...)을 넣어주세요.")
    exit(1)

app = App(token=SLACK_BOT_TOKEN)

# --------------------------------------------------------
# 설정 값들
# --------------------------------------------------------
ALERT_PREFIX = "⚠️ "

SVC_WATCHTOWER_CH = "C04M1UCMCFQ"
SVC_TMAP_DIV_CH = "C09BY22G12Q"
SVC_BTV_DIV_CH = "C077QK6NB4K"
RTZR_STT_SKT_ALERT_CH = "C091J89DQF7"
EXT_GIP_REPAIRING_CH = "C06L4C7HUCF"
LINER_ADOT_CH = "C08DRU0U7CK"
ERROR_AX_CH = "C09SQLEU8N8"
TEST_ALERT_CH = "C092DJVHVPY"

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

WINDOW_SECONDS = 3 * 60
ALERT_COOLDOWN_SECONDS = 10 * 60

message_window = defaultdict(deque)
last_message_by_rule = {}
last_alert_sent_at = 0
is_muted = False

# --------------------------------------------------------
# 규칙 (기존 그대로 유지)
# --------------------------------------------------------
RULES = [
    {
        "name": "TEST",
        "channel": TEST_ALERT_CH,
        "keyword": "Test",
        "threshold": 5,
        "notify": [
            {"channel": TEST_ALERT_CH, "text": "장애 Test", "include_log": False}
        ],
    },
]

# --------------------------------------------------------
# 헬퍼 함수
# --------------------------------------------------------
def prune_old_events(key, now_ts, window_seconds):
    dq = message_window[key]
    while dq and now_ts - dq[0] > window_seconds:
        dq.popleft()

def can_send_alert(now_ts):
    global last_alert_sent_at, is_muted
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
        try:
            app.client.chat_postMessage(channel=action["channel"], text=text)
        except Exception as e:
            print(f"Failed to send alert: {e}")

    last_alert_sent_at = now_ts


def process_message(event):
    channel = event.get("channel")
    text = event.get("text", "") or ""
    if not text:
        return

    now_ts = time.time()
    for rule in RULES:
        if channel != rule["channel"]:
            continue
        if rule["keyword"] not in text:
            continue

        key = (channel, rule["name"])
        prune_old_events(key, now_ts, WINDOW_SECONDS)
        message_window[key].append(now_ts)
        last_message_by_rule[key] = event

        if len(message_window[key]) >= rule["threshold"]:
            send_alert_for_rule(rule, event)
            message_window[key].clear()

# --------------------------------------------------------
# Slack 이벤트 핸들러
# --------------------------------------------------------
@app.event("message")
def handle_message_events(body, say, logger):
    global is_muted, last_alert_sent_at, message_window

    event = body.get("event", {})
    if event.get("subtype") == "bot_message":
        return

    text = (event.get("text") or "").strip()

    if text == "!mute":
        is_muted = True
        say("🔇 알림 봇이 mute 되었습니다.")
        return

    if text == "!unmute":
        is_muted = False
        last_alert_sent_at = 0
        message_window.clear()
        say("🔔 mute 해제되었습니다.")
        return

    try:
        process_message(event)
    except Exception as e:
        logger.error(f"Error: {e}")

# --------------------------------------------------------
# 메인 실행
# --------------------------------------------------------
if __name__ == "__main__":
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()
