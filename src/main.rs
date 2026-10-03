use axum::{
    Json, Router,
    extract::{
        Query, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use bcrypt::verify as bcrypt_verify;
use futures_util::{SinkExt, StreamExt};
use md5::Md5;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::{
    Row,
    mysql::{MySqlPool, MySqlPoolOptions},
};
use std::{
    collections::HashMap,
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{RwLock, broadcast};
use tower_http::trace::TraceLayer;
use uuid::Uuid;

const BUILD_ID: &str = match option_env!("SEVENBOARD_BUILD_ID") {
    Some(value) => value,
    None => "local-dev",
};
const INDEX_HTML: &str = include_str!("../web/index.html");
const SESSION_TTL_SECONDS: u64 = 8 * 60 * 60;

#[derive(Clone)]
struct AppState {
    build_id: &'static str,
    started_at: u64,
    db_mode: Arc<str>,
    db_site: Arc<str>,
    db: Option<MySqlPool>,
    db_error: Arc<str>,
    sessions: Arc<RwLock<HashMap<String, Session>>>,
    events: broadcast::Sender<String>,
    admin_events: broadcast::Sender<String>,
}

#[derive(Clone)]
struct Session {
    user_id: i64,
    email: String,
    expires_at: u64,
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

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_at: u64,
    user_id: i64,
    is_admin: bool,
    read_only: bool,
}

#[derive(Serialize)]
struct MeResponse {
    user_id: i64,
    email: String,
    is_admin: bool,
    read_only: bool,
    database_site: String,
}

#[derive(Serialize)]
struct SummaryResponse {
    database_site: String,
    read_only: bool,
    nodes: i64,
    users: i64,
    orders: i64,
    load_history: i64,
}

#[derive(Deserialize)]
struct NodeQuery {
    limit: Option<u64>,
    cursor: Option<i64>,
}

#[derive(Serialize)]
struct NodeRow {
    id: i64,
    node_type: String,
    name: String,
    host: Option<String>,
    port: Option<i64>,
    server_port: Option<i64>,
    enabled: bool,
    shown: bool,
    sort: i64,
    updated_unix: Option<i64>,
}

#[derive(Serialize)]
struct NodesResponse {
    database_site: String,
    read_only: bool,
    count: usize,
    next_cursor: Option<i64>,
    nodes: Vec<NodeRow>,
}

#[derive(Deserialize)]
struct WsAuth {
    #[serde(rename = "type")]
    message_type: String,
    token: String,
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
        .route("/api/v1/admin/login", post(admin_login))
        .route("/api/v1/admin/me", get(admin_me))
        .route("/api/v1/admin/summary", get(admin_summary))
        .route("/api/v1/admin/nodes", get(admin_nodes))
        .route("/ws/status", get(ws_status))
        .route("/ws/admin", get(ws_admin))
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
    if state.db.is_some() {
        return (
            StatusCode::OK,
            Json(Ready {
                status: "degraded",
                service: "7board",
                build_id: state.build_id,
                database: "mysql-shadow",
                reason: "read-only shadow reader is connected; write APIs are disabled",
            }),
        )
            .into_response();
    }

    let (database, reason) = if state.db_mode.as_ref() == "mysql-shadow" {
        (
            "unavailable",
            "mysql shadow reader is configured but the connection is unavailable",
        )
    } else {
        (
            "unconfigured",
            "7Board canary has no database connection and cannot claim admin acceptance",
        )
    };
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(Ready {
            status: "blocked",
            service: "7board",
            build_id: state.build_id,
            database,
            reason,
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
        "database_site": state.db_site.as_ref(),
        "database_connected": state.db.is_some(),
        "database_read_only": true,
        "redis_required": false,
        "php_required": false,
        "write_apis": false,
        "websocket": {
            "public_path": "/ws/status",
            "admin_path": "/ws/admin",
            "bounded_events": 64,
            "payload": "heartbeat-and-change-snapshot"
        },
        "admin_data": if state.db.is_some() { "mysql-shadow-read-model" } else { "not_connected" },
        "db_error": state.db_error.as_ref()
    }))
}

fn api_error(status: StatusCode, message: &'static str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    value
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(ToOwned::to_owned)
}

async fn session_for_token(state: &AppState, token: &str) -> Option<Session> {
    let mut sessions = state.sessions.write().await;
    let session = sessions.get(token).cloned();
    match session {
        Some(session) if session.expires_at > now_unix() => Some(session),
        Some(_) => {
            sessions.remove(token);
            None
        }
        None => None,
    }
}

async fn require_session(headers: &HeaderMap, state: &AppState) -> Result<Session, Response> {
    let token = bearer_token(headers)
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
    session_for_token(state, &token)
        .await
        .ok_or_else(|| api_error(StatusCode::UNAUTHORIZED, "invalid or expired session"))
}

fn php_compatible_password_verify(
    algorithm: Option<&str>,
    salt: Option<&str>,
    password: &str,
    stored_hash: &str,
) -> bool {
    let algo = algorithm.unwrap_or("").trim().to_ascii_lowercase();
    match algo.as_str() {
        "md5" => {
            let mut hasher = Md5::new();
            hasher.update(password.as_bytes());
            format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(stored_hash)
        }
        "sha256" => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(stored_hash)
        }
        "md5salt" => {
            let mut hasher = Md5::new();
            hasher.update(password.as_bytes());
            hasher.update(salt.unwrap_or("").as_bytes());
            format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(stored_hash)
        }
        "sha256salt" => {
            let mut hasher = Sha256::new();
            hasher.update(password.as_bytes());
            hasher.update(salt.unwrap_or("").as_bytes());
            format!("{:x}", hasher.finalize()).eq_ignore_ascii_case(stored_hash)
        }
        _ => bcrypt_verify(password, stored_hash).unwrap_or(false),
    }
}

async fn admin_login(State(state): State<AppState>, Json(payload): Json<LoginRequest>) -> Response {
    let Some(pool) = state.db.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "mysql shadow reader is not ready",
        );
    };
    let email = payload.email.trim();
    if email.is_empty() || payload.password.is_empty() {
        return api_error(StatusCode::BAD_REQUEST, "email and password are required");
    }

    let row = match sqlx::query(
        "SELECT id, email, password, password_algo, password_salt, \
         CAST(is_admin AS SIGNED) AS is_admin, CAST(banned AS SIGNED) AS banned \
         FROM v2_user WHERE email = ? LIMIT 1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await
    {
        Ok(row) => row,
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "admin lookup failed"),
    };

    let Some(row) = row else {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid administrator credentials",
        );
    };
    let user_id = row.try_get::<i64, _>("id").unwrap_or_default();
    let stored_email = row
        .try_get::<String, _>("email")
        .unwrap_or_else(|_| email.to_owned());
    let stored_hash = row.try_get::<String, _>("password").unwrap_or_default();
    let algorithm = row
        .try_get::<Option<String>, _>("password_algo")
        .unwrap_or_default();
    let salt = row
        .try_get::<Option<String>, _>("password_salt")
        .unwrap_or_default();
    let is_admin = row.try_get::<i64, _>("is_admin").unwrap_or_default() != 0;
    let banned = row.try_get::<i64, _>("banned").unwrap_or_default() != 0;
    if banned
        || !is_admin
        || !php_compatible_password_verify(
            algorithm.as_deref(),
            salt.as_deref(),
            &payload.password,
            &stored_hash,
        )
    {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "invalid administrator credentials",
        );
    }

    let token = Uuid::new_v4().to_string();
    let expires_at = now_unix() + SESSION_TTL_SECONDS;
    let mut sessions = state.sessions.write().await;
    if sessions.len() >= 1024
        && let Some(oldest) = sessions
            .iter()
            .min_by_key(|(_, session)| session.expires_at)
            .map(|(token, _)| token.clone())
    {
        sessions.remove(&oldest);
    }
    sessions.insert(
        token.clone(),
        Session {
            user_id,
            email: stored_email,
            expires_at,
        },
    );

    Json(LoginResponse {
        token,
        expires_at,
        user_id,
        is_admin: true,
        read_only: true,
    })
    .into_response()
}

async fn admin_me(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Ok(session) = require_session(&headers, &state).await else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid or expired session");
    };
    Json(MeResponse {
        user_id: session.user_id,
        email: session.email,
        is_admin: true,
        read_only: true,
        database_site: state.db_site.to_string(),
    })
    .into_response()
}

async fn admin_summary(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_session(&headers, &state).await {
        return response;
    }
    let Some(pool) = state.db.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "mysql shadow reader is not ready",
        );
    };
    let row = match sqlx::query(
        "SELECT \
         CAST((SELECT COUNT(*) FROM v2_server) AS SIGNED) AS nodes, \
         CAST((SELECT COUNT(*) FROM v2_user) AS SIGNED) AS users, \
         CAST((SELECT COUNT(*) FROM v2_order) AS SIGNED) AS orders, \
         CAST((SELECT COUNT(*) FROM v2_server_machine_load_history) AS SIGNED) AS load_history",
    )
    .fetch_one(pool)
    .await
    {
        Ok(row) => row,
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "summary query failed"),
    };
    Json(SummaryResponse {
        database_site: state.db_site.to_string(),
        read_only: true,
        nodes: row.try_get("nodes").unwrap_or_default(),
        users: row.try_get("users").unwrap_or_default(),
        orders: row.try_get("orders").unwrap_or_default(),
        load_history: row.try_get("load_history").unwrap_or_default(),
    })
    .into_response()
}

async fn admin_nodes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<NodeQuery>,
) -> Response {
    if let Err(response) = require_session(&headers, &state).await {
        return response;
    }
    let Some(pool) = state.db.as_ref() else {
        return api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "mysql shadow reader is not ready",
        );
    };
    let limit = query.limit.unwrap_or(200).clamp(1, 500) as i64;
    let cursor = query.cursor.unwrap_or(0);
    let rows = match sqlx::query(
        "SELECT id, type AS node_type, name, host, port, server_port, \
         CAST(enabled AS SIGNED) AS enabled, CAST(v2_server.show AS SIGNED) AS shown, \
         CAST(sort AS SIGNED) AS sort, \
         UNIX_TIMESTAMP(updated_at) AS updated_unix \
         FROM v2_server WHERE id > ? ORDER BY id ASC LIMIT ?",
    )
    .bind(cursor)
    .bind(limit)
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows,
        Err(_) => return api_error(StatusCode::INTERNAL_SERVER_ERROR, "node query failed"),
    };

    let mut nodes = Vec::with_capacity(rows.len());
    for row in rows {
        nodes.push(NodeRow {
            id: row.try_get("id").unwrap_or_default(),
            node_type: row
                .try_get::<Option<String>, _>("node_type")
                .unwrap_or_default()
                .unwrap_or_else(|| "unknown".to_owned()),
            name: row
                .try_get::<Option<String>, _>("name")
                .unwrap_or_default()
                .unwrap_or_default(),
            host: row.try_get("host").unwrap_or_default(),
            port: row.try_get("port").unwrap_or_default(),
            server_port: row.try_get("server_port").unwrap_or_default(),
            enabled: row.try_get::<i64, _>("enabled").unwrap_or_default() != 0,
            shown: row.try_get::<i64, _>("shown").unwrap_or_default() != 0,
            sort: row.try_get("sort").unwrap_or_default(),
            updated_unix: row.try_get("updated_unix").unwrap_or_default(),
        });
    }
    let next_cursor = if nodes.len() == limit as usize {
        nodes.last().map(|node| node.id)
    } else {
        None
    };
    Json(NodesResponse {
        database_site: state.db_site.to_string(),
        read_only: true,
        count: nodes.len(),
        next_cursor,
        nodes,
    })
    .into_response()
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

async fn ws_admin(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| admin_socket(socket, state))
}

async fn admin_socket(mut socket: WebSocket, state: AppState) {
    let first = tokio::time::timeout(Duration::from_secs(10), socket.recv()).await;
    let token = match first {
        Ok(Some(Ok(Message::Text(text)))) => serde_json::from_str::<WsAuth>(text.as_str())
            .ok()
            .filter(|auth| auth.message_type == "auth")
            .map(|auth| auth.token),
        _ => None,
    };
    let Some(token) = token else {
        let _ = socket
            .send(Message::Text(
                json!({"type":"error","error":"auth_required"})
                    .to_string()
                    .into(),
            ))
            .await;
        return;
    };
    if session_for_token(&state, &token).await.is_none() {
        let _ = socket
            .send(Message::Text(
                json!({"type":"error","error":"invalid_or_expired_session"})
                    .to_string()
                    .into(),
            ))
            .await;
        return;
    }
    let Some(pool) = state.db.as_ref() else {
        let _ = socket
            .send(Message::Text(
                json!({"type":"error","error":"mysql_shadow_not_ready"})
                    .to_string()
                    .into(),
            ))
            .await;
        return;
    };

    let mut events = state.admin_events.subscribe();
    let (mut sender, mut receiver) = socket.split();
    let _ = sender
        .send(Message::Text(
            json!({
                "type":"hello",
                "service":"7board",
                "database_site":state.db_site.as_ref(),
                "read_only":true
            })
            .to_string()
            .into(),
        ))
        .await;

    match read_nodes(pool, 0, 200).await {
        Ok(snapshot) => {
            let _ = sender
                .send(Message::Text(
                    json!({
                        "type":"node_snapshot",
                        "count":snapshot.nodes.len(),
                        "next_cursor":snapshot.next_cursor
                    })
                    .to_string()
                    .into(),
                ))
                .await;
        }
        Err(_) => {
            let _ = sender
                .send(Message::Text(
                    json!({"type":"error","error":"initial_node_query_failed"})
                        .to_string()
                        .into(),
                ))
                .await;
        }
    }

    let mut ticker = tokio::time::interval(Duration::from_secs(5));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if sender.send(Message::Text(json!({"type":"heartbeat","ts":now_unix()}).to_string().into())).await.is_err() { break; }
            }
            event = events.recv() => match event {
                Ok(message) => if sender.send(Message::Text(message.into())).await.is_err() { break; },
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if sender.send(Message::Text(json!({"type":"resync_required"}).to_string().into())).await.is_err() { break; }
                }
                Err(broadcast::error::RecvError::Closed) => break,
            },
            incoming = receiver.next() => match incoming {
                Some(Ok(Message::Close(_))) | None => break,
                Some(Ok(Message::Ping(payload))) => { if sender.send(Message::Pong(payload)).await.is_err() { break; } }
                Some(Ok(_)) => {},
                Some(Err(_)) => break,
            }
        }
    }
}

async fn read_nodes(
    pool: &MySqlPool,
    cursor: i64,
    limit: i64,
) -> Result<NodesResponse, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id, type AS node_type, name, host, port, server_port, \
         CAST(enabled AS SIGNED) AS enabled, CAST(v2_server.show AS SIGNED) AS shown, \
         CAST(sort AS SIGNED) AS sort, UNIX_TIMESTAMP(updated_at) AS updated_unix \
         FROM v2_server WHERE id > ? ORDER BY id ASC LIMIT ?",
    )
    .bind(cursor)
    .bind(limit)
    .fetch_all(pool)
    .await?;
    let mut nodes = Vec::with_capacity(rows.len());
    for row in rows {
        nodes.push(NodeRow {
            id: row.try_get("id").unwrap_or_default(),
            node_type: row
                .try_get::<Option<String>, _>("node_type")
                .unwrap_or_default()
                .unwrap_or_else(|| "unknown".to_owned()),
            name: row
                .try_get::<Option<String>, _>("name")
                .unwrap_or_default()
                .unwrap_or_default(),
            host: row.try_get("host").unwrap_or_default(),
            port: row.try_get("port").unwrap_or_default(),
            server_port: row.try_get("server_port").unwrap_or_default(),
            enabled: row.try_get::<i64, _>("enabled").unwrap_or_default() != 0,
            shown: row.try_get::<i64, _>("shown").unwrap_or_default() != 0,
            sort: row.try_get("sort").unwrap_or_default(),
            updated_unix: row.try_get("updated_unix").unwrap_or_default(),
        });
    }
    let next_cursor = if nodes.len() == limit as usize {
        nodes.last().map(|node| node.id)
    } else {
        None
    };
    Ok(NodesResponse {
        database_site: String::new(),
        read_only: true,
        count: nodes.len(),
        next_cursor,
        nodes,
    })
}

fn spawn_scheduler(state: &AppState) {
    let Some(pool) = state.db.clone() else {
        return;
    };
    let events = state.admin_events.clone();
    tokio::spawn(async move {
        let mut last_signature: Option<(i64, i64, String)> = None;
        loop {
            let row = sqlx::query(
                "SELECT CAST(COUNT(*) AS SIGNED) AS node_count, \
                 CAST(COALESCE(MAX(id), 0) AS SIGNED) AS max_id, \
                 COALESCE(CAST(MAX(updated_at) AS CHAR), '') AS max_updated \
                 FROM v2_server",
            )
            .fetch_one(&pool)
            .await;
            if let Ok(row) = row {
                let node_count = row.try_get::<i64, _>("node_count").unwrap_or_default();
                let max_id = row.try_get::<i64, _>("max_id").unwrap_or_default();
                let max_updated = row.try_get::<String, _>("max_updated").unwrap_or_default();
                let signature = (node_count, max_id, max_updated);
                if last_signature.as_ref() != Some(&signature) {
                    last_signature = Some(signature);
                    let _ = events.send(
                        json!({
                            "type":"node_change",
                            "node_count":node_count,
                            "max_id":max_id
                        })
                        .to_string(),
                    );
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

async fn build_state() -> AppState {
    let db_mode: Arc<str> = env::var("SEVENBOARD_DB_MODE")
        .unwrap_or_else(|_| "unconfigured".to_owned())
        .into();
    let db_site: Arc<str> = env::var("SEVENBOARD_DB_SITE")
        .unwrap_or_else(|_| "unconfigured".to_owned())
        .into();
    let max_connections = env::var("SEVENBOARD_DB_MAX_CONNECTIONS")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(4)
        .clamp(1, 16);
    let (db, db_error) = if db_mode.as_ref() == "mysql-shadow" {
        match env::var("SEVENBOARD_DB_URL") {
            Ok(url) if !url.trim().is_empty() => {
                match connect_shadow_db(&url, max_connections).await {
                    Ok(pool) => (Some(pool), "connected"),
                    Err(error) => {
                        let kind = match error {
                            sqlx::Error::Database(_) => {
                                "database authentication or selection failed"
                            }
                            sqlx::Error::Configuration(_) => "connection URL configuration failed",
                            sqlx::Error::Tls(_) => "TLS connection failed",
                            sqlx::Error::Io(_) => "network I/O failed",
                            sqlx::Error::PoolTimedOut => "connection pool timeout",
                            sqlx::Error::Protocol(_) => "MySQL protocol failed",
                            _ => "connection failed",
                        };
                        (None, kind)
                    }
                }
            }
            _ => (None, "not configured"),
        }
    } else {
        (None, "shadow mode disabled")
    };
    let (events, _) = broadcast::channel(1024);
    let (admin_events, _) = broadcast::channel(64);
    AppState {
        build_id: BUILD_ID,
        started_at: now_unix(),
        db_mode,
        db_site,
        db,
        db_error: db_error.into(),
        sessions: Arc::new(RwLock::new(HashMap::new())),
        events,
        admin_events,
    }
}

async fn connect_shadow_db(url: &str, max_connections: u32) -> Result<MySqlPool, sqlx::Error> {
    let pool = MySqlPoolOptions::new()
        .min_connections(0)
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect(url)
        .await?;
    sqlx::query("SELECT 1").execute(&pool).await?;
    Ok(pool)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind: SocketAddr = env::var("SEVENBOARD_BIND")
        .unwrap_or_else(|_| "127.0.0.1:18120".to_owned())
        .parse()?;
    let state = build_state().await;
    spawn_scheduler(&state);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!(
        "7Board canary build={} listening={} db_mode={} db_site={} db_connected={}",
        BUILD_ID,
        bind,
        state.db_mode,
        state.db_site,
        state.db.is_some()
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
        let (admin_events, _) = broadcast::channel(2);
        AppState {
            build_id: "test",
            started_at: now_unix(),
            db_mode: mode.into(),
            db_site: "test".into(),
            db: None,
            db_error: "test".into(),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            events,
            admin_events,
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

    #[test]
    fn php_bcrypt_default_and_legacy_hashes_are_supported() {
        let bcrypt_hash = bcrypt::hash("secret", bcrypt::DEFAULT_COST).unwrap();
        assert!(php_compatible_password_verify(
            None,
            None,
            "secret",
            &bcrypt_hash
        ));
        assert!(!php_compatible_password_verify(
            None,
            None,
            "wrong",
            &bcrypt_hash
        ));
        let mut md5 = Md5::new();
        md5.update(b"secret");
        let md5_hash = format!("{:x}", md5.finalize());
        assert!(php_compatible_password_verify(
            Some("md5"),
            None,
            "secret",
            &md5_hash
        ));
    }
}
