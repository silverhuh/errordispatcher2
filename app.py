# app.py
import os
import time
from collections import defaultdict, deque
from flask import Flask, request
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from dotenv import load_dotenv

load_dotenv()

# ── Slack 초기화
slack_app = App(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"],
)
flask_app = Flask(__name__)
handler = SlackRequestHandler(slack_app)

# ── 채널/멘션 (실제 멘션은 <@UXXXX> 형식 권장)
CHANNEL_A = os.environ.get("CHANNEL_A_ID", "C04M1UCMCFQ")
CHANNEL_B = os.environ.get("CHANNEL_B_ID", "C08DRU0U7CK")

MENTION_HEO    = os.environ.get("MENTION_HEO",    "<@U04MGC3BFCY>님")
MENTION_CHAE   = os.environ.get("MENTION_CHAE",   "<@U04M5AGSF17>님")
MENTION_CHO    = os.environ.get("MENTION_CHO",    "<@U06ECTJLK9P>님")
MENTION_KARTER = os.environ.get("MENTION_KARTER", "<@U06NSJVR0GH>님")
MENTION_SUNNY  = os.environ.get("MENTION_SUNNY",  "<@U08DS680G7L>님")
MENTION_KIMH   = os.environ.get("MENTION_KIMH",   "<@U04LSM49TR8>님")
MENTION_KIMJ   = os.environ.get("MENTION_KIMJ",   "<@U04M5AD6X7B>님")
MENTION_SONG   = os.environ.get("MENTION_SONG",   "<@U04LSM6SCLS>님")
MENTION_SHIN   = os.environ.get("MENTION_SHIN",   "<@U04LSHQMADR>님")
MENTION_YANG   = os.environ.get("MENTION_YANG",   "<@U04LSHPDC03>님")

# ── 공통 파라미터
KEYWORD_WINDOW_SECONDS    = 120     # 2분
KEYWORD_THRESHOLD         = 7       # 7회
GLOBAL_COOLDOWN_SECONDS   = 300     # 5분(봇 발언 전역 쿨다운)
A_CHANNEL_BURST_WINDOW    = 600     # 10분
A_CHANNEL_BURST_THRESHOLD = 20      # 20회
A_CHANNEL_BURST_SILENT    = 600     # 최근 10분간 봇 발언 無

# ── 채널별 발언 허용 상태 / 카운터
channel_speaking_enabled = defaultdict(lambda: True)  # 채널 mute 상태
keyword_hits = defaultdict(deque)        # (channel, keyword) → timestamps
channel_msg_times = defaultdict(deque)   # (channel) → timestamps(모든 메시지)
last_bot_speak_at = 0.0                  # 전역 마지막 발언 시각

# ── 명령어
MUTE_CMD = "!mute"
UNMUTE_CMD = "!unmute"

def can_speak(min_gap: int) -> bool:
    return (time.time() - last_bot_speak_at) >= min_gap

def record_hit(channel_id: str, key: str, now: float, window: int):
    q = keyword_hits[(channel_id, key)]
    q.append(now)
    while q and now - q[0] > window:
        q.popleft()
    return q

def record_message(channel_id: str, now: float, window: int):
    q = channel_msg_times[channel_id]
    q.append(now)
    while q and now - q[0] > window:
        q.popleft()
    return q

def post_to(client, channel: str, text: str):
    client.chat_postMessage(channel=channel, text=text)

@slack_app.event("message")
def on_message(body, say, client, logger):
    """
    [우선순위]
    0) 전역 쿨다운(5분 내 1회)
    1) A채널 'liner' 2분/7회 → A/B 동시 전파(문구 다름)
    2) 'MULTI LLM' 2분/7회
    3) 'rtzr_api' 2분/7회
    4) 'music' 2분/7회
    5) 'btv' 2분/7회
    6) 'apollo.builtin.one' 2분/7회
    7) '오류 감지' 2분/7회
    8) A채널 버스트: 10분/20회 & 최근 10분간 봇 발언 無
    """
    global last_bot_speak_at

    event = body.get("event", {}) or {}
    text = (event.get("text") or "").strip()
    if not text:
        return
    if event.get("subtype") == "bot_message":
        return

    channel_id = event.get("channel")
    lower = text.lower()
    now = time.time()

    # ── !mute / !unmute (항상 처리)
    if lower == MUTE_CMD:
        channel_speaking_enabled[channel_id] = False
        say("🔇 이 채널에서 봇 발언이 *제한*되었습니다. `!unmute`로 해제할 수 있어요.")
        return
    if lower == UNMUTE_CMD:
        channel_speaking_enabled[channel_id] = True
        say("🔊 이 채널에서 봇 발언이 *허용*되었습니다. 감사합니다.")
        return

    # ── 채널이 mute면 모든 트리거 무시 (교차 전파 포함)
    if not channel_speaking_enabled[channel_id]:
        logger.info(f"[SKIP] muted channel={channel_id}")
        return

    # ── A채널 버스트 카운트를 위해 모든 메시지 기록
    a_burst_queue = None
    if channel_id == CHANNEL_A:
        a_burst_queue = record_message(CHANNEL_A, now, A_CHANNEL_BURST_WINDOW)

    # ── 1) A채널 'liner'
    if channel_id == CHANNEL_A and ("liner" in lower):
        q = record_hit(CHANNEL_A, "liner", now, KEYWORD_WINDOW_SECONDS)
        if len(q) >= KEYWORD_THRESHOLD and can_speak(GLOBAL_COOLDOWN_SECONDS):
            msg_a = f"liner 에러가 감지되어 liner-adot 슬랙 채널에 전파하였습니다. (cc. {MENTION_HEO}, {MENTION_CHAE}, {MENTION_CHO})"
            msg_b = f"{MENTION_KARTER}, {MENTION_SUNNY}, liner 모델 에러가 지속 감지되어 확인 문의드립니다. (cc. {MENTION_HEO}, {MENTION_CHAE}, {MENTION_CHO})"
            post_to(client, CHANNEL_A, f"⚠️ {msg_a}")
            post_to(client, CHANNEL_B, f"⚠️ {msg_b}")
            last_bot_speak_at = now
            q.clear()
            return

    # ── 공통 키워드 트리거
    def trigger(keyword: str, alert_text: str):
        global last_bot_speak_at
        if keyword in lower:
            q = record_hit(channel_id, keyword, now, KEYWORD_WINDOW_SECONDS)
            if len(q) >= KEYWORD_THRESHOLD and can_speak(GLOBAL_COOLDOWN_SECONDS):
                say(f"⚠️ {alert_text}")
                last_bot_speak_at = now
                q.clear()
                return True
        return False

    # 2)~7)
    if trigger("multi llm",      f"{MENTION_HEO}, MULTI LLM 에러 확인 문의드립니다. (cc. {MENTION_CHAE}, {MENTION_CHO})"): return
    if trigger("rtzr_api",       f"{MENTION_KIMH}, {MENTION_KIMJ}, 리턴제로 API 에러 확인 문의드립니다. (cc. {MENTION_HEO}, {MENTION_CHAE})"): return
    if trigger("music",          f"{MENTION_SONG}, 뮤직 에러 확인 문의드립니다. (cc. {MENTION_HEO}, {MENTION_CHAE})"): return
    if trigger("btv",            f"{MENTION_SHIN}, 에이닷 btv 에러 확인 문의드립니다. (cc. {MENTION_HEO}, {MENTION_CHAE})"): return
    if trigger("apollo.builtin.one", f"{MENTION_HEO}, One Agent 에러 확인 문의드립니다. (cc. {MENTION_CHAE}, {MENTION_YANG})"): return
    if trigger("오류 감지",       f"{MENTION_HEO}, PET 및 LLM 연동 오류 확인 문의드립니다. (cc. {MENTION_CHAE})"): return

    # ── 8) A채널 버스트 (10분/20회) + 최근 10분간 봇 발언 無
    if channel_id == CHANNEL_A and a_burst_queue is not None:
        if (len(a_burst_queue) >= A_CHANNEL_BURST_THRESHOLD) and ((now - last_bot_speak_at) >= A_CHANNEL_BURST_SILENT):
            post_to(
                client,
                CHANNEL_A,
                f"⚠️ 간헐적 장애가 빈번히 발생중(10분 동안 20회 이상 에러 감지). 모니터링 주의 필요! (cc. {MENTION_HEO})"
            )
            last_bot_speak_at = now
            a_burst_queue.clear()
            return

@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
