import os
import time
from flask import Flask, request
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from collections import deque, defaultdict
from dotenv import load_dotenv

# 환경변수 불러오기
load_dotenv()

# Slack 초기화
slack_app = App(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"]
)

flask_app = Flask(__name__)
handler = SlackRequestHandler(slack_app)

# 키워드 → 알림 메시지 (실제 멘션 포함)
KEYWORDS = {
    "adotbtv": "<@U04LSHQMADR>님, <@U04LC5FQJP9>님, 에이닷 btv 에러 확인 문의드립니다.",
    "liner": "<@U06ECTJLK9P>님, liner 에러 확인 문의드립니다.",
    "music": "<@U04LSM6SCLS>님, 뮤직 에러 확인 문의드립니다.",
    "rtzr_api": "<@U04M5AD6X7B>님, <@U04LSHJ7S91>님, 리턴제로 API 에러 확인 문의드립니다."
}

# 설정
KEYWORD_WINDOW_SECONDS = 120  # 2분
BOT_COOLDOWN_SECONDS = 60     # 1분
THRESHOLD = 5                 # 트리거 발생 기준 횟수

# 명령어
MUTE_CMD = "!mute"
UNMUTE_CMD = "!unmute"

# 키워드 별 감지 시간 큐
keyword_timestamps = defaultdict(deque)

# 채널별 발언 허용 상태 (기본 True: 발언 허용)
channel_speaking_enabled = defaultdict(lambda: True)

# 마지막 발언 시간 (봇 전체 쿨다운)
last_bot_response_time = 0

@slack_app.event("message")
def handle_message_events(body, say, logger):
    global last_bot_response_time

    event = body.get("event", {})
    text = (event.get("text") or "").strip()
    if not text:
        return

    # 봇 자신의 메시지/스레드 브로드캐스트 등은 무시
    if event.get("subtype") == "bot_message":
        return

    channel_id = event.get("channel")
    lowercase_text = text.lower()
    now = time.time()

    # 🛠️ say 래퍼: 모든 메시지에 cc 문구를 추가
    def post(msg: str):
        say(f"{msg}\n\n(cc. <@U04MGC3BFCY>, <@U04M5AGSF17>)")

    # 1) 채널 제어 명령
    if lowercase_text == MUTE_CMD:
        channel_speaking_enabled[channel_id] = False
        post("🔇 이 채널에서 봇 발언이 *제한*되었습니다. `!unmute`로 해제할 수 있어요.")
        logger.info(f"[MUTE] channel={channel_id}")
        return

    if lowercase_text == UNMUTE_CMD:
        channel_speaking_enabled[channel_id] = True
        post("🔊 이 채널에서 봇 발언이 *허용*되었습니다. 감사합니다.")
        logger.info(f"[UNMUTE] channel={channel_id}")
        return

    # 2) 발언 제한 상태면 무시
    if not channel_speaking_enabled[channel_id]:
        logger.info(f"[SKIP] channel muted. channel={channel_id}")
        return

    # 3) 키워드 트리거 감지
    for keyword, alert_message in KEYWORDS.items():
        if keyword in lowercase_text:
            queue = keyword_timestamps[keyword]
            queue.append(now)

            # 오래된 항목 제거
            while queue and now - queue[0] > KEYWORD_WINDOW_SECONDS:
                queue.popleft()

            # 트리거 조건 충족 시
            if len(queue) >= THRESHOLD:
                if now - last_bot_response_time >= BOT_COOLDOWN_SECONDS:
                    post(f"⚠️ {alert_message}")
                    logger.info(f"[ALERT] keyword={keyword} → sent: {alert_message}")
                    last_bot_response_time = now
                    queue.clear()
                else:
                    logger.info(f"[SKIP] cooldown. keyword={keyword}, count={len(queue)}")

@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
