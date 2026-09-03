new WebSocket("/ws/live");
new EventSource("/sse/events");
new WebSocket(`wss://127.0.0.1:8081/ws/live`);
const feed = "ws://127.0.0.1:8081/ws/live";
