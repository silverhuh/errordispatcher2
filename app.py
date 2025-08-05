import os
import time
from flask import Flask, request
from slack_bolt import App
from slack_bolt.adapter.flask import SlackRequestHandler
from collections import deque
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Slack App 초기화
slack_app = App(
    token=os.environ["SLACK_BOT_TOKEN"],
    signing_secret=os.environ["SLACK_SIGNING_SECRET"]
)

# Flask 서버
flask_app = Flask(__name__)
handler = SlackRequestHandler(slack_app)

# 감지 타겟
KEYWORD = "허은석"
THRESHOLD = 5
WINDOW_SECONDS = 300  # 5분

# 메시지 타임스탬프를 저장할 큐
message_times = deque()

@slack_app.event("message")
def handle_message_events(body, logger, say):
    try:
        text = body["event"].get("text", "")
        ts = float(body["event"]["ts"])

        if KEYWORD in text:
            message_times.append(ts)
            logger.info(f"'{KEYWORD}' 감지됨 at {ts}. 전체 기록: {len(message_times)}")

            # 오래된 메시지 제거
            while message_times and time.time() - message_times[0] > WINDOW_SECONDS:
                message_times.popleft()

            if len(message_times) >= THRESHOLD:
                say("⚠️ '허은석'이 5분 내 5회 이상 감지되었습니다. 조치하세요.")
                message_times.clear()  # 경고 후 초기화

    except Exception as e:
        logger.error(f"에러 발생: {e}")

# Slack 엔드포인트 라우팅
@flask_app.route("/slack/events", methods=["POST"])
def slack_events():
    return handler.handle(request)

if __name__ == "__main__":
    flask_app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))