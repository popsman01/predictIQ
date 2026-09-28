//! Integration tests for the CSRF protection middleware.
//!
//! These tests exercise the Origin/Referer validation performed by
//! `predictiq_api::csrf` for state-changing newsletter requests, including the
//! `X-Api-Key` short-circuit path.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use predictiq_api::csrf::csrf_protection_middleware;
use tower::ServiceExt;

/// Build a minimal router that runs the CSRF middleware in front of a handler
/// which always succeeds, so we can assert purely on the middleware decision.
fn app() -> axum::Router {
    axum::Router::new()
        .route("/newsletter/subscribe", axum::routing::post(|| async { StatusCode::OK }))
        .layer(axum::middleware::from_fn(csrf_protection_middleware))
}

fn post(uri: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}

#[tokio::test]
async fn matching_allowed_origin_passes() {
    let request = Request::builder()
        .method("POST")
        .uri("/newsletter/subscribe")
        .header("origin", "https://app.predictiq.io")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn mismatched_origin_is_rejected() {
    let request = Request::builder()
        .method("POST")
        .uri("/newsletter/subscribe")
        .header("origin", "https://evil.example.com")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn missing_origin_and_referer_on_mutating_request_is_rejected() {
    // Per the documented policy, a state-changing request without an
    // Origin or Referer header is rejected.
    let response = app().oneshot(post("/newsletter/subscribe")).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn matching_referer_passes_when_origin_absent() {
    let request = Request::builder()
        .method("POST")
        .uri("/newsletter/subscribe")
        .header("referer", "https://app.predictiq.io/newsletter")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn api_key_short_circuits_origin_validation() {
    // A valid API key bypasses the Origin/Referer check entirely, even when
    // the Origin header is missing or untrusted.
    let request = Request::builder()
        .method("POST")
        .uri("/newsletter/subscribe")
        .header("x-api-key", "test-api-key")
        .body(Body::empty())
        .unwrap();

    let response = app().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
