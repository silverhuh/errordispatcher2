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
    "apollo.builtin.one": "<@U04LSHPDC03> One Agent 에러 확인 문의드립니다.",
    "liner": "<@U06ECTJLK9P> liner 에러 확인 문의드립니다.",
    "music": "<@U04LSM6SCLS> 뮤직 에러 확인 문의드립니다.",
    "rtzr_api": "<@U04M5AD6X7B>, <@U04LSHJ7S91> 리턴제로 API 에러 확인 문의드립니다."
}

# 설정
KEYWORD_WINDOW_SECONDS = 180  # 3분
BOT_COOLDOWN_SECONDS = 300    # 5분

# 키워드 별 감지 시간 큐
keyword_timestamps = defaultdict(deque)

# 마지막 발언 시간
last_bot_response_time = 0

@slack_app.event("message")
def handle_message_events(body, say, logger):
    global last_bot_response_time

    text = body["event"].get("text", "")
    if not text:
        return

    lowercase_text = text.lower()
    now = time.time()

    for keyword, alert_message in KEYWORDS.items():
        if keyword in lowercase_text:
            queue = keyword_timestamps[keyword]
            queue.append(now)

            # 오래된 항목 제거
            while queue and now - queue[0] > KEYWORD_WINDOW_SECONDS:
                queue.popleft()

            # 트리거 조건 만족
            if len(queue) >= 5:
                if now - last_bot_response_time >= BOT_COOLDOWN_SECONDS:
                    say(f"⚠️ {alert_message}")
                    logger.info(f"[ALERT] {keyword} 감지됨 → 메시지 전송: {alert_message}")
                    last_bot_response_time = now
                    queue.clear()
                else:
                    logger.info(f"[SKIP] 봇 쿨다운 중 → {keyword} 감지되었지만 메시지 생략")

@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))