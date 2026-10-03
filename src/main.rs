use axum::{
    Json, Router,
    extract::{
        State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
};
use futures_util::StreamExt;
use serde::Serialize;
use serde_json::json;
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::broadcast;
use tower_http::trace::TraceLayer;

const BUILD_ID: &str = env!("SEVENBOARD_BUILD_ID");
const INDEX_HTML: &str = include_str!("../web/index.html");

#[derive(Clone)]
struct AppState {
    build_id: &'static str,
    started_at: u64,
    db_mode: Arc<str>,
    events: broadcast::Sender<String>,
}

#[derive(Serialize)]
struct Health {
    status: &'static str,
    service: &'static str,
    build_id: &'static str,
    runtime: &'static str,
    uptime_seconds: u64,
}

#[derive(Serialize)]
struct Ready {
    status: &'static str,
    service: &'static str,
    build_id: &'static str,
    database: &'static str,
    reason: &'static str,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/api/v1/meta", get(meta))
        .route("/ws/status", get(ws_status))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn healthz(State(state): State<AppState>) -> Json<Health> {
    Json(Health {
        status: "ok",
        service: "7board",
        build_id: state.build_id,
        runtime: "rust",
        uptime_seconds: now_unix().saturating_sub(state.started_at),
    })
}

async fn readyz(State(state): State<AppState>) -> Response {
    if state.db_mode.as_ref() == "mysql-shadow" {
        return (
            StatusCode::OK,
            Json(Ready {
                status: "degraded",
                service: "7board",
                build_id: state.build_id,
                database: "mysql-shadow",
                reason: "read-model connection is configured by the deployment",
            }),
        )
            .into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Ready {
            status: "blocked",
            service: "7board",
            build_id: state.build_id,
            database: "unconfigured",
            reason: "7Board canary does not claim production database acceptance",
        }),
    )
        .into_response()
}

async fn meta(State(state): State<AppState>) -> Json<serde_json::Value> {
    Json(json!({
        "service": "7board",
        "build_id": state.build_id,
        "runtime": "rust",
        "database_mode": state.db_mode.as_ref(),
        "redis_required": false,
        "php_required": false,
        "websocket": {"path": "/ws/status", "bounded_events": 1024, "payload": "heartbeat-only-canary"},
        "admin_data": "not_connected",
        "next_migration": "mysql-read-model"
    }))
}

async fn ws_status(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    let rx = state.events.subscribe();
    ws.on_upgrade(move |socket| status_socket(socket, rx))
}

async fn status_socket(mut socket: WebSocket, mut rx: broadcast::Receiver<String>) {
    let _ = socket
        .send(Message::Text(
            json!({"type":"hello","service":"7board","mode":"canary"})
                .to_string()
                .into(),
        ))
        .await;
    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let msg = json!({"type":"heartbeat","ts":now_unix()}).to_string();
                if socket.send(Message::Text(msg.into())).await.is_err() { break; }
            }
            event = rx.recv() => match event {
                Ok(msg) => if socket.send(Message::Text(msg.into())).await.is_err() { break; },
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    let _ = socket.send(Message::Text(json!({"type":"resync_required"}).to_string().into())).await;
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = socket.next() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(Message::Ping(payload))) => { let _ = socket.send(Message::Pong(payload)).await; }
                Some(Ok(_)) => {},
                Some(Err(_)) => break,
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind: SocketAddr = env::var("SEVENBOARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:18120".into())
        .parse()?;
    let db_mode: Arc<str> = env::var("SEVENBOARD_DB_MODE")
        .unwrap_or_else(|_| "unconfigured".into())
        .into();
    let (events, _) = broadcast::channel(1024);
    let state = AppState {
        build_id: BUILD_ID,
        started_at: now_unix(),
        db_mode,
        events,
    };
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!(
        "7Board canary build={} listening={} db_mode={}",
        BUILD_ID, bind, state.db_mode
    );
    axum::serve(listener, app(state))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn state(mode: &str) -> AppState {
        let (events, _) = broadcast::channel(2);
        AppState {
            build_id: "test",
            started_at: now_unix(),
            db_mode: mode.into(),
            events,
        }
    }

    #[tokio::test]
    async fn health_is_rust_canary() {
        let response = app(state("unconfigured"))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["service"], "7board");
        assert_eq!(value["runtime"], "rust");
    }

    #[tokio::test]
    async fn ready_does_not_claim_database_without_shadow_mode() {
        let response = app(state("unconfigured"))
            .oneshot(
                axum::http::Request::builder()
                    .uri("/readyz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
