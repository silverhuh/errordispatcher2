import os
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from collections import deque
import time

# ---- Slack Tokens ----
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_APP_TOKEN = os.environ.get("SLACK_APP_TOKEN")

app = App(token=SLACK_BOT_TOKEN)

# ---- 감지 설정 ----
TARGET_CHANNEL = "C092DJVHVPY"   # 감시할 채널 ID
KEYWORD = "test"                  # 감지할 키워드
THRESHOLD = 3                     # 트리거 횟수
WINDOW_SECONDS = 3 * 60           # 3분 윈도우

# 최근 메시지 발생 시간을 저장하는 큐
message_times = deque()

@app.event("message")
def handle_message_events(body, say, logger):
    event = body.get("event", {})
    channel = event.get("channel")
    text = (event.get("text") or "").lower().strip()

    # 봇 메시지는 무시
    if event.get("subtype") == "bot_message":
        return

    # 감시 채널 외는 무시
    if channel != TARGET_CHANNEL:
        return

    # 키워드 포함 여부
    if KEYWORD not in text:
        return

    now = time.time()

    # 오래된 기록 제거
    while message_times and now - message_times[0] > WINDOW_SECONDS:
        message_times.popleft()

    # 현재 메시지 추가
    message_times.append(now)

    print(f"[DEBUG] test keyword count = {len(message_times)}")

    # 임계치 도달 → 메시지 발송
    if len(message_times) >= THRESHOLD:
        say("테스트")          # <= Slack 메시지 자동 전송
        message_times.clear()  # 다시 초기화


# ---- MAIN ----
if __name__ == "__main__":
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()
