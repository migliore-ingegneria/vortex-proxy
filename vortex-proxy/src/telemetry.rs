//! Telemetry and OpenTelemetry integration for Vortex Proxy.
//!
//! Configures a non-blocking, MPSC-backed batch exporter for W3C trace contexts.

use opentelemetry::global;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{BatchConfig, RandomIdGenerator, Sampler};
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Initializes the global tracing subscriber with an OTLP exporter pipeline.
pub fn init_telemetry() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set W3C Trace Context as the global propagator
    global::set_text_map_propagator(TraceContextPropagator::new());

    // Configure the OTLP exporter (gRPC)
    let exporter = opentelemetry_otlp::new_exporter()
        .tonic()
        .with_endpoint("http://localhost:4317"); // Default OpenTelemetry Collector endpoint

    // Configure the batch span processor to use a dedicated background Tokio task
    // effectively acting as an MPSC queue that unblocks the proxy workers.
    let batch_config = BatchConfig::default()
        .with_max_queue_size(8192)
        .with_max_export_batch_size(512);

    let tracer = opentelemetry_otlp::new_pipeline()
        .tracing()
        .with_exporter(exporter)
        .with_trace_config(
            opentelemetry_sdk::trace::Config::default()
                // Default to 1% sampling for extremely high throughput (100M+ loads)
                // in production this would be configurable.
                .with_sampler(Sampler::TraceIdRatioBased(0.01))
                .with_id_generator(RandomIdGenerator::default())
                .with_resource(Resource::new(vec![opentelemetry::KeyValue::new(
                    "service.name",
                    "vortex-proxy",
                )])),
        )
        .with_batch_config(batch_config)
        .install_batch(opentelemetry_sdk::runtime::Tokio)?;

    // Create the tracing layer
    let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer);

    // Create a filter to control log verbosity
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    // Combine and set as the global default
    Registry::default()
        .with(env_filter)
        .with(telemetry_layer)
        // Also log to stdout for local debugging
        .with(tracing_subscriber::fmt::layer())
        .init();

    Ok(())
}

/// Helper function to format and record telemetry metric logs for proxy ingress traffic.
pub fn record_proxy_ingress_metric(path: &str, status_code: u16) {
    tracing::info!(
        target: "vortex_ingress",
        path = path,
        status = status_code,
        "Ingress request recorded"
    );
}

/// OpenTelemetry header injector implementation for hyper `HeaderMap`.
pub struct HeaderInjector<'a>(pub &'a mut hyper::HeaderMap);

impl<'a> opentelemetry::propagation::Injector for HeaderInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = hyper::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = hyper::header::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}

/// Injects W3C trace context headers (`traceparent`, `tracestate`) into an outgoing HTTP header map.
pub fn inject_trace_context(cx: &opentelemetry::Context, headers: &mut hyper::HeaderMap) {
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(cx, &mut HeaderInjector(headers));
    });
}

/// Parsed fields of a W3C `traceparent` header.
#[derive(Debug, PartialEq, Eq)]
pub struct W3CTraceParent<'a> {
    /// W3C trace specification version.
    pub version: &'a str,
    /// 16-byte hex trace ID.
    pub trace_id: &'a str,
    /// 8-byte hex parent span ID.
    pub parent_id: &'a str,
    /// 8-bit trace flags.
    pub trace_flags: &'a str,
}

/// Zero-allocation parser for W3C `traceparent` header format: `version-trace_id-parent_id-trace_flags`.
pub fn parse_w3c_traceparent(header_value: &str) -> Option<W3CTraceParent<'_>> {
    let mut iter = header_value.split('-');
    let version = iter.next()?;
    let trace_id = iter.next()?;
    let parent_id = iter.next()?;
    let trace_flags = iter.next()?;

    if iter.next().is_some() {
        return None;
    }

    if version.len() != 2 || trace_id.len() != 32 || parent_id.len() != 16 || trace_flags.len() != 2 {
        return None;
    }

    Some(W3CTraceParent {
        version,
        trace_id,
        parent_id,
        trace_flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_proxy_ingress_metric() {
        record_proxy_ingress_metric("/api/v1/health", 200);
        record_proxy_ingress_metric("/api/v1/stream", 404);
    }

    #[test]
    fn test_w3c_traceparent_parsing() {
        let valid_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let parsed = parse_w3c_traceparent(valid_header).expect("Failed to parse valid traceparent");
        assert_eq!(parsed.version, "00");
        assert_eq!(parsed.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert_eq!(parsed.parent_id, "00f067aa0ba902b7");
        assert_eq!(parsed.trace_flags, "01");

        let invalid_header = "00-short-id-01";
        assert!(parse_w3c_traceparent(invalid_header).is_none());
    }

    #[test]
    fn test_trace_context_injection() {
        global::set_text_map_propagator(TraceContextPropagator::new());
        let cx = opentelemetry::Context::new();
        let mut headers = hyper::HeaderMap::new();

        inject_trace_context(&cx, &mut headers);
        // TraceContextPropagator injects traceparent if active span exists or context holds valid trace metadata
    }
}
