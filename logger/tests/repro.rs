use std::net::{Ipv4Addr, SocketAddr};

use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_proto::tonic::collector::trace::v1::trace_service_server::TraceServiceServer;
use portpicker::pick_unused_port;
use pretty_assertions::assert_eq;
use serde_json::{json, Value};
use shuttle_common::{
    claims::Scope,
    tracing::{FILEPATH_KEY, LINENO_KEY, MESSAGE_KEY, NAMESPACE_KEY, TARGET_KEY},
};
use shuttle_common_tests::JwtScopesLayer;
use shuttle_logger::{Service, ShuttleLogsOtlp, Sqlite};
use shuttle_proto::logger::{
    logger_client::LoggerClient, logger_server::LoggerServer, LogItem, LogLevel, LogsRequest,
};
use tonic::{transport::Server, Request};
use tracing::{error, instrument, warn};
use tracing_subscriber::prelude::*;

/// Used for assertions.
#[derive(Debug, Eq, PartialEq)]
struct MinLogItem {
    level: LogLevel,
    fields: Value,
}

impl From<LogItem> for MinLogItem {
    fn from(log: LogItem) -> Self {
        assert_eq!(log.service_name, "test");

        let fields = if log.fields.is_empty() {
            Value::Null
        } else {
            let mut fields: Value = serde_json::from_slice(&log.fields).unwrap();

            let map = fields.as_object_mut().unwrap();

            let message = map.get(MESSAGE_KEY).unwrap();
            // Span logs don't contain a target field
            if !message.as_str().unwrap().starts_with("[span] ") {
                let target = map.remove(TARGET_KEY).unwrap();
                assert_eq!(target, "repro");
            } else {
                // We want to remove what's not of interest for checking
                // the spans are containing the right information.
                let _ = map.remove("busy_ns").unwrap();
                let _ = map.remove("idle_ns").unwrap();
                let _ = map.remove("thread.id").unwrap();
                let _ = map.remove("thread.name").unwrap();
            }

            let filepath = map.remove(FILEPATH_KEY).unwrap();
            assert_eq!(filepath, "logger/tests/repro.rs");

            map.remove(LINENO_KEY).unwrap();
            map.remove(NAMESPACE_KEY).unwrap();

            fields
        };

        Self {
            level: log.level(),
            fields,
        }
    }
}

/// Spawns the logger server and returns the port number.
async fn spawn_server() -> u16 {
    let port = pick_unused_port().unwrap();
    let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
    tokio::task::spawn(async move {
        let sqlite = Sqlite::new_in_memory().await;
        Server::builder()
            .layer(JwtScopesLayer::new(vec![Scope::Logs]))
            .add_service(TraceServiceServer::new(ShuttleLogsOtlp::new(
                sqlite.get_sender(),
            )))
            .add_service(LoggerServer::new(Service::new(sqlite.get_sender(), sqlite)))
            .serve(addr)
            .await
            .unwrap()
    });
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    port
}

#[tokio::test]
async fn test_get_logs1() {
    let deployment_id = "test-deployment1";
    let port = spawn_server().await;

    // Start a subscriber and generate some logs.
    generate_logs(port, deployment_id.into());

    // Get the generated logs
    let dst = format!("http://localhost:{port}");
    let mut client = LoggerClient::connect(dst).await.unwrap();
    let response = client
        .get_logs(Request::new(LogsRequest {
            deployment_id: deployment_id.into(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert the results.
    let expected = vec![
        MinLogItem {
            level: LogLevel::Info,
            fields: json!({"message": "[span] log_things", "deployment_id": format!("\"{deployment_id}\"") }),
        },
        MinLogItem {
            level: LogLevel::Error,
            fields: json!({"message": "error"}),
        },
        MinLogItem {
            level: LogLevel::Warn,
            fields: json!({"message": "warn"}),
        },
    ];
    assert_eq!(
        response
            .log_items
            .into_iter()
            .map(MinLogItem::from)
            .collect::<Vec<_>>(),
        expected
    );
}

#[tokio::test]
async fn test_get_logs2() {
    let deployment_id = "test-deployment2";
    let port = spawn_server().await;

    // Start a subscriber and generate some logs.
    generate_logs(port, deployment_id.into());

    // Get the generated logs
    let dst = format!("http://localhost:{port}");
    let mut client = LoggerClient::connect(dst).await.unwrap();
    let response = client
        .get_logs(Request::new(LogsRequest {
            deployment_id: deployment_id.into(),
        }))
        .await
        .unwrap()
        .into_inner();

    // Assert the results.
    let expected = vec![
        MinLogItem {
            level: LogLevel::Info,
            fields: json!({"message": "[span] log_things", "deployment_id": format!("\"{deployment_id}\"") }),
        },
        MinLogItem {
            level: LogLevel::Error,
            fields: json!({"message": "error"}),
        },
        MinLogItem {
            level: LogLevel::Warn,
            fields: json!({"message": "warn"}),
        },
    ];
    assert_eq!(
        response
            .log_items
            .into_iter()
            .map(MinLogItem::from)
            .collect::<Vec<_>>(),
        expected
    );
}

/// Set up a tracing subscriber and produce logs.
fn generate_logs(port: u16, deployment_id: String) {
    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(
            opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(format!("http://127.0.0.1:{port}")),
        )
        .with_trace_config(opentelemetry::sdk::trace::config().with_resource(
            opentelemetry::sdk::Resource::new(vec![
                KeyValue::new("service.name", "test"),
                KeyValue::new("deployment_id", deployment_id.clone()),
            ]),
        ))
        .install_batch(opentelemetry::runtime::Tokio)
        .unwrap();
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    let _guard = tracing_subscriber::registry()
        .with(otel_layer)
        .set_default();

    log_things(deployment_id);
}

#[instrument]
fn log_things(deployment_id: String) {
    error!("error");
    warn!("warn");
}
