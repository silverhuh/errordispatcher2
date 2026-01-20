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
# ✅ 전역 발언 제한(레이트리밋) 설정
# --------------------------------------------------------
GLOBAL_RATE_WINDOW_SECONDS = 300  # 5분
GLOBAL_RATE_LIMIT_COUNT = 1       # ✅ 5분 동안 1회

# 모드 선택:
# - "trigger": 룰 1번 트리거(알림 1세트) = 1회로 카운트 (추천)
# - "send"   : chat_postMessage 1번 = 1회로 카운트 (진짜 '발언 1번'에 가장 가까움)
GLOBAL_RATE_MODE = os.environ.get("GLOBAL_RATE_MODE", "trigger").strip().lower()
if GLOBAL_RATE_MODE not in ("trigger", "send"):
    GLOBAL_RATE_MODE = "trigger"

# (선택) 멀티 인스턴스 환경에서 진짜 전역 1회를 원하면 Redis 사용 권장
USE_REDIS_RATE_LIMIT = os.environ.get("USE_REDIS_RATE_LIMIT", "0").strip() == "1"
REDIS_URL = os.environ.get("REDIS_URL")  # 예: redis://:pass@host:6379/0

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

message_window = defaultdict(deque)  # (channel, rule) -> deque[timestamps]
is_muted = False

# 내 봇 식별용
BOT_USER_ID = None
BOT_ID = None  # event.get("bot_id") 비교용(있으면 더 안전)

# --------------------------------------------------------
# ✅ 전역 레이트리밋(단일 프로세스용) 상태 + 락
# --------------------------------------------------------
global_alert_sent_times = deque()  # timestamps
global_rate_lock = threading.Lock()

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
