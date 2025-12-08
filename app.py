import os
import time
from collections import defaultdict, deque

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler


# =========================================================
#  환경 변수 (Railway Variables 활용)
# =========================================================
SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_APP_TOKEN = os.environ["SLACK_APP_TOKEN"]

app = App(token=SLACK_BOT_TOKEN)


# =========================================================
#  공통 설정
# =========================================================
ALERT_PREFIX = "❗ "          # 모든 메시지 앞에 붙일 아이콘
WINDOW_SECONDS = 180          # 3분(180초)
ALERT_COOLDOWN_SECONDS = 600  # 10분 내 1회 발화 제한

message_window = defaultdict(deque)
last_message_by_rule = {}

last_alert_sent_at = 0
is_muted = False


# =========================================================
#  Slack 채널 ID 정의 (Full Name)
# =========================================================
CHANNEL_SVC_WATCHTOWER = "C04M1UCMCFQ"
CHANNEL_SVC_TMAP_DIVERGENCE = "C09BY22G12Q"
CHANNEL_SVC_BTV_DIVERGENCE = "C077QK6NB4K"

CHANNEL_RTZR_STT_SKT_ALERT = "C091J89DQF7"
CHANNEL_EXT_GIP_REPAIRING = "C06L4C7HUCF"
CHANNEL_LINER_ADOT = "C08DRU0U7CK"
CHANNEL_ERROR_AX = "C09SQLEU8N8"

CHANNEL_ERROR_TEST = "C092DJVHVPY"


# =========================================================
#  Slack 멘션 ID 정의 (Full Name)
# =========================================================
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


# =========================================================
#  규칙 정의
# =========================================================
RULES = [
    # ----------------------------------------------------
    # svc_watchtower
    # ----------------------------------------------------
    {
        "name": "RTZR_API",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "RTZR_API",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}노트 에러(RTZR_API)가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_RTZR_STT_SKT_ALERT,
                "text": (
                    f"{ALERT_PREFIX}RTZR_API 5회 이상 감지중! "
                    f"{MENTION_KIM_DONGWOO}, {MENTION_NO_JUNGKYU}, {MENTION_JUNG_JUYOUNG} "
                    f"확인 문의드립니다. (cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False
            }
        ],
    },

    {
        "name": "PET_API",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "PET_API",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": (
                    f"{ALERT_PREFIX}노트 에러(PET_API) 5회 이상 감지중! "
                    f"{MENTION_KIM_JIHWAN}, {MENTION_KIM_HAKRAE} 확인 문의드립니다. "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False
            }
        ],
    },

    {
        "name": "BUILTIN_ONE",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "builtin.one",
        "threshold": 7,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}One Agent 에러가 감지되었습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            }
        ],
    },

    {
        "name": "PERPLEXITY",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "Perplexity",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}Perplexity 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_EXT_GIP_REPAIRING,
                "text": (
                    f"{ALERT_PREFIX}Perplexity 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True
            }
        ],
    },

    {
        "name": "CLAUDE",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "Claude",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}Claude 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_EXT_GIP_REPAIRING,
                "text": (
                    f"{ALERT_PREFIX}Claude 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True
            }
        ],
    },

    {
        "name": "GPT",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "MODEL_LABEL: GPT",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}GPT 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_EXT_GIP_REPAIRING,
                "text": (
                    f"{ALERT_PREFIX}GPT 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True
            }
        ],
    },

    {
        "name": "GEMINI",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "Gemini",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}Gemini 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_EXT_GIP_REPAIRING,
                "text": (
                    f"{ALERT_PREFIX}Gemini 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_YONGHYUN}, {MENTION_GU_JINHYUN} "
                    f"(cc. {MENTION_YANG_YOUNGJOON}, {MENTION_PARK_JIYOON}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True
            }
        ],
    },

    {
        "name": "LINER",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "Liner",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}Liner 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_LINER_ADOT,
                "text": (
                    f"{ALERT_PREFIX}Liner 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KAI}, {MENTION_BAEK_SEUNGRYEOL} "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True
            }
        ],
    },

    {
        "name": "AX",
        "channel": CHANNEL_SVC_WATCHTOWER,
        "keyword": "A.X",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_WATCHTOWER,
                "text": f"{ALERT_PREFIX}A.X 에러가 감지되어 담당자 전달하였습니다. (cc. {MENTION_HEO_EUNSEOK})",
                "include_log": False
            },
            {
                "channel": CHANNEL_ERROR_AX,
                "text": (
                    f"{ALERT_PREFIX}A.X 에러가 발생되어 확인 문의드립니다. "
                    f"{MENTION_KIM_SEONGWAN}, {MENTION_LEE_YOUNGSOON} "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": True
            }
        ],
    },


    # ----------------------------------------------------
    # svc_watchtower_tmap_divergence
    # ----------------------------------------------------
    {
        "name": "AGENT_TMAP",
        "channel": CHANNEL_SVC_TMAP_DIVERGENCE,
        "keyword": "agent.tmap",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_TMAP_DIVERGENCE,
                "text": (
                    f"{ALERT_PREFIX}에러가 감지되어 확인 문의드립니다. "
                    f"{MENTION_GO_MINSEOK}, {MENTION_KANG_TAEHEE} "
                    f"(cc. {MENTION_JO_UKRAE}, {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False
            }
        ],
    },


    # ----------------------------------------------------
    # svc_watchtower_btv_divergence
    # ----------------------------------------------------
    {
        "name": "REQUEST_ID",
        "channel": CHANNEL_SVC_BTV_DIVERGENCE,
        "keyword": "REQUEST_ID",
        "threshold": 5,
        "notify": [
            {
                "channel": CHANNEL_SVC_BTV_DIVERGENCE,
                "text": (
                    f"{ALERT_PREFIX}에러가 감지되어 확인 문의드립니다. "
                    f"{MENTION_SHIN_YUNCHUL}, {MENTION_GO_MINSEOK} "
                    f"(cc. {MENTION_HEO_EUNSEOK})"
                ),
                "include_log": False
            }
        ],
    },


    # ----------------------------------------------------
    # error_test
    # ----------------------------------------------------
    {
        "name": "TEST",
        "channel": CHANNEL_ERROR_TEST,
        "keyword": "test",
        "threshold": 3,
        "notify": [
            {
                "channel": CHANNEL_ERROR_TEST,
                "text": f"{ALERT_PREFIX}확인",
                "include_log": False
            }
        ]
    }
]


# =========================================================
#  헬퍼 함수
# =========================================================
def prune_old_events(key, now):
    dq = message_window[key]
    while dq and now - dq[0] > WINDOW_SECONDS:
        dq.popleft()


def can_send_alert(now):
    if is_muted:
        return False
    return now - last_alert_sent_at >= ALERT_COOLDOWN_SECONDS


def send_alert(rule, event):
    global last_alert_sent_at

    now = time.time()
    if not can_send_alert(now):
        return

    original_text = event.get("text", "")

    for dest in rule["notify"]:
        msg = dest["text"]

        if dest["include_log"]:
            msg += f"\n```{original_text}```"

        try:
            app.client.chat_postMessage(
                channel=dest["channel"],
                text=msg
            )
        except Exception as e:
            print(f"[ERROR] Failed to send alert [{rule['name']}]: {e}")

    last_alert_sent_at = now


def process_message(event):
    channel = event.get("channel")
    text = event.get("text") or ""

    now = time.time()

    for rule in RULES:
        if channel != rule["channel"]:
            continue
        if rule["keyword"] not in text:
            continue

        key = (channel, rule["name"])

        prune_old_events(key, now)
        message_window[key].append(now)
        last_message_by_rule[key] = event

        if len(message_window[key]) >= rule["threshold"]:
            send_alert(rule, event)
            message_window[key].clear()


# =========================================================
#  메시지 이벤트 핸들러 (!mute / !unmute 포함)
# =========================================================
@app.event("message")
def handle_message_events(body, say, logger):
    global is_muted, last_alert_sent_at

    event = body.get("event", {})

    # 봇이 보낸 메시지는 무시
    if event.get("subtype") == "bot_message":
        return
    if event.get("bot_id"):
        return

    text = (event.get("text") or "").strip()

    # mute
    if text == "!mute":
        is_muted = True
        say("🔇 알림 봇이 *mute* 상태로 전환되었습니다.")
        return

    # unmute
    if text == "!unmute":
        is_muted = False
        last_alert_sent_at = 0
        message_window.clear()
        say("🔔 알림 봇이 *unmute* 되었습니다. (카운트 및 쿨다운 초기화)")
        return

    # 일반 메시지 처리
    try:
        process_message(event)
    except Exception as e:
        logger.error(f"[ERROR] processing message: {e}")


# =========================================================
#  Slash command 핸들러 (/mute /unmute)
# =========================================================
@app.command("/mute")
def command_mute(ack, respond):
    global is_muted
    ack()
    is_muted = True
    respond("🔇 Bot muted.")


@app.command("/unmute")
def command_unmute(ack, respond):
    global is_muted, last_alert_sent_at
    ack()
    is_muted = False
    last_alert_sent_at = 0
    message_window.clear()
    respond("🔔 Bot unmuted.")


# =========================================================
#  메인 실행부
# =========================================================
if __name__ == "__main__":
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()
