use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::env;
use std::sync::Arc;
use tower_http::services::ServeDir;

#[derive(Clone)]
struct AppState {
    portainer_url: String,
    portainer_api_key: String,
    auth_user: String,
    auth_pass: String,
}

#[derive(Deserialize)]
struct BcryptRequest {
    password: String,
}

#[derive(Serialize)]
struct BcryptResponse {
    escaped: String,
}

#[derive(Deserialize)]
struct DeployRequest {
    name: String,
    image: String,
    port: u16,
    domain: String,
    auth_user: Option<String>,
    auth_password: Option<String>,
    endpoint_id: Option<i64>,
}

#[derive(Serialize)]
struct DeployResponse {
    success: bool,
    message: String,
    compose: String,
}

#[derive(Deserialize)]
struct SearchQuery {
    q: String,
}

#[derive(Serialize, Deserialize)]
struct DockerHubResult {
    name: String,
    description: String,
    is_official: bool,
    star_count: i64,
}

#[derive(Deserialize)]
struct DockerHubApiResponse {
    results: Vec<DockerHubApiResult>,
}

#[derive(Deserialize)]
struct DockerHubApiResult {
    repo_name: String,
    short_description: Option<String>,
    star_count: Option<i64>,
    is_official: Option<bool>,
}

async fn check_auth(headers: &HeaderMap, state: &AppState) -> bool {
    let Some(auth) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(auth_str) = auth.to_str() else {
        return false;
    };
    let Some(encoded) = auth_str.strip_prefix("Basic ") else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded) else {
        return false;
    };
    let Ok(decoded_str) = String::from_utf8(decoded) else {
        return false;
    };
    let Some((user, pass)) = decoded_str.split_once(':') else {
        return false;
    };
    user == state.auth_user && pass == state.auth_pass
}

fn unauthorized() -> axum::response::Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Basic realm=\"yamld\"")],
        "Authentication required",
    )
        .into_response()
}

/// Sanitize a user-provided name into something safe to use as a Traefik
/// router/service name and Docker Compose service key: lowercase,
/// alphanumeric and hyphens only.
fn slugify(input: &str) -> String {
    let mut out = String::new();
    let mut last_was_dash = false;
    for c in input.to_lowercase().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_was_dash = false;
        } else if !last_was_dash && !out.is_empty() {
            out.push('-');
            last_was_dash = true;
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    if out.is_empty() {
        "app".to_string()
    } else {
        out
    }
}

fn build_compose(req: &DeployRequest, slug: &str) -> String {
    let mut labels = vec![
        "      - traefik.enable=true".to_string(),
        format!(
            "      - traefik.http.routers.{slug}.rule=Host(`{domain}`)",
            slug = slug,
            domain = req.domain
        ),
        format!("      - traefik.http.routers.{slug}.entrypoints=https", slug = slug),
        format!("      - traefik.http.routers.{slug}.tls=true", slug = slug),
        format!(
            "      - traefik.http.routers.{slug}.tls.certresolver=letsencrypt",
            slug = slug
        ),
        format!(
            "      - traefik.http.services.{slug}.loadbalancer.server.port={port}",
            slug = slug,
            port = req.port
        ),
    ];

    if let (Some(user), Some(pass)) = (&req.auth_user, &req.auth_password) {
        if !user.is_empty() && !pass.is_empty() {
            let hash = bcrypt::hash(pass, 10).unwrap_or_default();
            let escaped = hash.replace('$', "$$");
            labels.push(format!(
                "      - traefik.http.routers.{slug}.middlewares={slug}-auth",
                slug = slug
            ));
            labels.push(format!(
                "      - traefik.http.middlewares.{slug}-auth.basicauth.users={user}:{escaped}",
                slug = slug,
                user = user,
                escaped = escaped
            ));
        }
    }

    format!(
        "services:\n  {slug}:\n    image: {image}\n    container_name: {slug}\n    restart: unless-stopped\n    networks:\n      - coolify\n    labels:\n{labels}\n\nnetworks:\n  coolify:\n    external: true\n",
        slug = slug,
        image = req.image,
        labels = labels.join("\n")
    )
}

async fn generate_bcrypt(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<BcryptRequest>,
) -> Result<Json<BcryptResponse>, axum::response::Response> {
    if !check_auth(&headers, &state).await {
        return Err(unauthorized());
    }
    let hash = bcrypt::hash(&req.password, 10).unwrap_or_default();
    let escaped = hash.replace('$', "$$");
    Ok(Json(BcryptResponse { escaped }))
}

async fn search_dockerhub(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(params): Query<SearchQuery>,
) -> Result<Json<Vec<DockerHubResult>>, axum::response::Response> {
    if !check_auth(&headers, &state).await {
        return Err(unauthorized());
    }
    if params.q.trim().is_empty() {
        return Ok(Json(vec![]));
    }

    let client = reqwest::Client::new();
    let url = format!(
        "https://hub.docker.com/v2/search/repositories/?query={}&page_size=20",
        urlencoding_lite(&params.q)
    );

    let resp = client
        .get(&url)
        .header("User-Agent", "yamld/0.1")
        .send()
        .await;

    match resp {
        Ok(r) => match r.json::<DockerHubApiResponse>().await {
            Ok(parsed) => {
                let results = parsed
                    .results
                    .into_iter()
                    .map(|r| DockerHubResult {
                        name: r.repo_name,
                        description: r.short_description.unwrap_or_default(),
                        is_official: r.is_official.unwrap_or(false),
                        star_count: r.star_count.unwrap_or(0),
                    })
                    .collect();
                Ok(Json(results))
            }
            Err(e) => Err((
                StatusCode::BAD_GATEWAY,
                format!("Could not parse Docker Hub response: {}", e),
            )
                .into_response()),
        },
        Err(e) => Err((
            StatusCode::BAD_GATEWAY,
            format!("Could not reach Docker Hub: {}", e),
        )
            .into_response()),
    }
}

/// Minimal percent-encoding for a search query string, no external dep needed.
fn urlencoding_lite(input: &str) -> String {
    let mut out = String::new();
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            b' ' => out.push('+'),
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

async fn deploy_stack(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<DeployRequest>,
) -> Result<Json<DeployResponse>, axum::response::Response> {
    if !check_auth(&headers, &state).await {
        return Err(unauthorized());
    }

    if req.name.trim().is_empty() || req.image.trim().is_empty() || req.domain.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name, image, and domain are required").into_response());
    }

    let slug = slugify(&req.name);
    let compose = build_compose(&req, &slug);

    let endpoint_id = req.endpoint_id.unwrap_or(1);
    let client = reqwest::Client::new();

    let url = format!(
        "{}/api/stacks/create/standalone/string?endpointId={}",
        state.portainer_url.trim_end_matches('/'),
        endpoint_id
    );

    let body = serde_json::json!({
        "name": slug,
        "stackFileContent": compose,
        "env": []
    });

    let result = client
        .post(&url)
        .header("X-API-Key", &state.portainer_api_key)
        .json(&body)
        .send()
        .await;

    match result {
        Ok(resp) => {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            if status.is_success() {
                Ok(Json(DeployResponse {
                    success: true,
                    message: format!("Deployed '{}'", slug),
                    compose,
                }))
            } else {
                Err((
                    StatusCode::BAD_GATEWAY,
                    Json(DeployResponse {
                        success: false,
                        message: format!("Portainer returned {}: {}", status, text),
                        compose,
                    }),
                )
                    .into_response())
            }
        }
        Err(e) => Err((
            StatusCode::BAD_GATEWAY,
            Json(DeployResponse {
                success: false,
                message: format!("Failed to reach Portainer: {}", e),
                compose,
            }),
        )
            .into_response()),
    }
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let state = Arc::new(AppState {
        portainer_url: env::var("PORTAINER_URL")
            .unwrap_or_else(|_| "https://portainer.devc-vps.duckdns.org".to_string()),
        portainer_api_key: env::var("PORTAINER_API_KEY").unwrap_or_default(),
        auth_user: env::var("AUTH_USER").unwrap_or_else(|_| "admin".to_string()),
        auth_pass: env::var("AUTH_PASS").unwrap_or_else(|_| "changeme".to_string()),
    });

    let api_routes = Router::new()
        .route("/health", get(health))
        .route("/bcrypt", post(generate_bcrypt))
        .route("/search", get(search_dockerhub))
        .route("/deploy", post(deploy_stack))
        .with_state(state.clone());

    let app = Router::new()
        .nest("/api", api_routes)
        .nest_service("/", ServeDir::new("static"));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8800").await.unwrap();
    tracing::info!("yamld listening on :8800");
    axum::serve(listener, app).await.unwrap();
}
