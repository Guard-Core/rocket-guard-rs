//! The telemetry agent built from the `agent_*` config fields (feature
//! `agent`): the reference `guard_agent(config.to_agent_config())` step of
//! the adapter constructor.
//!
//! guard-agent-rs depends on the guard-core-rs facade (its `guard-core`
//! feature supplies the `TelemetryHandler` bridge), so the facade cannot
//! depend on it back; every adapter owns this mapping instead.

use guard_agent_rs::bridge::GuardAgentTelemetry;
use guard_agent_rs::{AgentConfig, BufferOverflowPolicy as AgentOverflow, GuardAgent};
use guard_core_engine::security_config::{BufferOverflowPolicy, SecurityConfig};
use guard_core_rs::composite::TelemetryHandler;
use std::collections::BTreeMap;
use std::sync::Arc;

/// Map the config's `agent_*` fields onto the agent's own config (the
/// reference `SecurityConfig.to_agent_config`): `None` unless `enable_agent`
/// is set with an `agent_api_key`; an unset optional field keeps the agent's
/// default.
pub(crate) fn agent_config(config: &SecurityConfig) -> Option<AgentConfig> {
    let api_key = config
        .agent_api_key
        .clone()
        .filter(|_| config.enable_agent)?;
    let mut agent = AgentConfig::new(api_key);
    agent.endpoint.clone_from(&config.agent_endpoint);
    agent.project_id.clone_from(&config.agent_project_id);
    agent.buffer_size = config.agent_buffer_size;
    agent.flush_interval = config.agent_flush_interval;
    agent.dynamic_rule_interval = config.dynamic_rule_interval;
    agent.status_interval = config.agent_status_interval;
    agent.enable_events = config.agent_enable_events;
    agent.enable_metrics = config.agent_enable_metrics;
    agent.timeout = config.agent_timeout;
    agent.retry_attempts = config.agent_retry_attempts;
    agent
        .project_encryption_key
        .clone_from(&config.agent_project_encryption_key);
    agent.guard_version.clone_from(&config.agent_guard_version);
    agent.install_id.clone_from(&config.agent_install_id);
    agent
        .payload_signing_secret
        .clone_from(&config.agent_payload_signing_secret);
    if let Some(ratio) = config.agent_high_watermark_ratio {
        agent.high_watermark_ratio = ratio;
    }
    if let Some(flushes) = config.agent_max_concurrent_flushes {
        agent.max_concurrent_flushes = usize::try_from(flushes).unwrap_or(usize::MAX);
    }
    if let Some(policy) = config.agent_buffer_overflow_policy {
        agent.buffer_overflow_policy = match policy {
            BufferOverflowPolicy::Drop => AgentOverflow::Drop,
            BufferOverflowPolicy::Block => AgentOverflow::Block,
            BufferOverflowPolicy::Raise => AgentOverflow::Raise,
        };
    }
    if let Some(factor) = config.agent_backoff_factor {
        agent.backoff_factor = factor;
    }
    if let Some(headers) = &config.agent_sensitive_headers {
        agent.sensitive_headers.clone_from(headers);
    }
    if let Some(size) = config.agent_max_payload_size {
        agent.max_payload_size = usize::try_from(size).unwrap_or(usize::MAX);
    }
    if let Some(enabled) = config.agent_compression_enabled {
        agent.compression_enabled = enabled;
    }
    if let Some(threshold) = config.agent_compression_threshold {
        agent.compression_threshold = usize::try_from(threshold).unwrap_or(usize::MAX);
    }
    if let Some(hook) = config.on_error.clone() {
        agent.on_error = Some(Arc::new(move |stage, error| {
            hook(&stage.to_string(), &error.to_string(), &BTreeMap::new());
        }));
    }
    Some(agent)
}

/// Build and start the agent the config describes, as the telemetry sink the
/// wiring takes. `Ok(None)` when the config asks for none; `Err` carries why
/// the agent could not be built (no tokio runtime to run it on, or the agent
/// rejected the config).
pub(crate) fn build(config: &SecurityConfig) -> Result<Option<Arc<dyn TelemetryHandler>>, String> {
    let Some(agent_config) = agent_config(config) else {
        return Ok(None);
    };
    let runtime = tokio::runtime::Handle::try_current()
        .map_err(|error| format!("the agent needs a tokio runtime: {error}"))?;
    let agent = Arc::new(GuardAgent::new(agent_config).map_err(|error| error.to_string())?);
    // The start paths block on the runtime, which the request path must not
    // do: the agent starts as a task on it (the reference starts it at the
    // first request's lazy initialization).
    let starting = Arc::clone(&agent);
    runtime.spawn(async move { starting.start().await });
    Ok(Some(Arc::new(GuardAgentTelemetry::new(agent, runtime))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GuardFairing;

    fn config() -> SecurityConfig {
        SecurityConfig {
            enable_redis: false,
            enable_agent: true,
            agent_api_key: Some("a-key-of-at-least-ten".to_owned()),
            agent_endpoint: "http://127.0.0.1:1".to_owned(),
            agent_install_id: Some("install-1".to_owned()),
            ..SecurityConfig::default()
        }
    }

    #[test]
    fn no_agent_without_the_switch_or_the_key() {
        let mut off = config();
        off.enable_agent = false;
        assert!(agent_config(&off).is_none());
        let mut keyless = config();
        keyless.agent_api_key = None;
        assert!(agent_config(&keyless).is_none());
        assert!(matches!(build(&off), Ok(None)));
    }

    #[test]
    fn every_agent_field_maps_onto_the_agent_config() {
        let mut config = config();
        config.agent_project_id = Some("proj".to_owned());
        config.agent_buffer_size = 7;
        config.agent_flush_interval = 11;
        config.dynamic_rule_interval = 120;
        config.agent_status_interval = 90;
        config.agent_high_watermark_ratio = Some(0.5);
        config.agent_max_concurrent_flushes = Some(3);
        config.agent_buffer_overflow_policy = Some(BufferOverflowPolicy::Raise);
        config.agent_enable_events = false;
        config.agent_enable_metrics = false;
        config.agent_timeout = 9;
        config.agent_retry_attempts = 2;
        config.agent_backoff_factor = Some(1.5);
        config.agent_sensitive_headers = Some(vec!["x-secret".to_owned()]);
        config.agent_max_payload_size = Some(2048);
        config.agent_project_encryption_key = Some("k".to_owned());
        config.agent_guard_version = Some("1.2.3".to_owned());
        config.agent_compression_enabled = Some(false);
        config.agent_compression_threshold = Some(4096);
        config.agent_payload_signing_secret = Some("s".to_owned());
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        config.on_error = Some(Arc::new(move |stage, message, _context| {
            sink.lock()
                .expect("sink")
                .push(format!("{stage}:{message}"));
        }));
        let agent = agent_config(&config).expect("agent config");
        assert_eq!(agent.api_key, "a-key-of-at-least-ten");
        assert_eq!(agent.endpoint, "http://127.0.0.1:1");
        assert_eq!(agent.project_id.as_deref(), Some("proj"));
        assert_eq!((agent.buffer_size, agent.flush_interval), (7, 11));
        assert_eq!(
            (agent.dynamic_rule_interval, agent.status_interval),
            (120, 90)
        );
        assert!((agent.high_watermark_ratio - 0.5).abs() < f64::EPSILON);
        assert_eq!(agent.max_concurrent_flushes, 3);
        assert_eq!(agent.buffer_overflow_policy, AgentOverflow::Raise);
        assert!(!agent.enable_events && !agent.enable_metrics);
        assert_eq!((agent.timeout, agent.retry_attempts), (9, 2));
        assert!((agent.backoff_factor - 1.5).abs() < f64::EPSILON);
        assert_eq!(agent.sensitive_headers, vec!["x-secret".to_owned()]);
        assert_eq!(agent.max_payload_size, 2048);
        assert_eq!(agent.project_encryption_key.as_deref(), Some("k"));
        assert_eq!(agent.guard_version.as_deref(), Some("1.2.3"));
        assert!(!agent.compression_enabled);
        assert_eq!(agent.compression_threshold, 4096);
        assert_eq!(agent.install_id.as_deref(), Some("install-1"));
        assert_eq!(agent.payload_signing_secret.as_deref(), Some("s"));
        for policy in [BufferOverflowPolicy::Drop, BufferOverflowPolicy::Block] {
            config.agent_buffer_overflow_policy = Some(policy);
            let mapped = agent_config(&config).expect("agent config");
            assert_eq!(mapped.buffer_overflow_policy.as_str(), policy.as_str());
        }
        let hook = agent.on_error.expect("hook");
        hook(
            guard_agent_rs::ErrorStage::FlushEvents,
            &guard_agent_rs::GuardAgentError::BufferFull { capacity: 1 },
        );
        assert_eq!(seen.lock().expect("sink").len(), 1);
    }

    #[test]
    fn without_a_runtime_the_agent_cannot_be_built() {
        let error = build(&config()).err().expect("no runtime");
        assert!(error.contains("tokio runtime"), "{error}");
    }

    #[test]
    fn a_failed_agent_degrades_unless_strict() {
        let mut lax = config();
        lax.agent_strict = false;
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = Arc::clone(&seen);
        lax.on_error = Some(Arc::new(move |stage, _message, _context| {
            sink.lock().expect("sink").push(stage.to_owned());
        }));
        let layer = GuardFairing::from_security_config(&lax).expect("degrades");
        let stats = layer.agent_stats();
        assert!(!stats.enabled && stats.degraded);
        assert_eq!(seen.lock().expect("sink").as_slice(), ["agent_init"]);

        let mut strict = config();
        strict.agent_strict = true;
        let error = GuardFairing::from_security_config(&strict).expect_err("strict");
        assert!(matches!(error, crate::GuardConfigError::Agent(_)));
    }

    #[tokio::test]
    async fn inside_a_runtime_the_config_builds_the_agent() {
        let layer = GuardFairing::from_security_config(&config()).expect("layer");
        let stats = layer.agent_stats();
        assert!(stats.enabled && !stats.degraded);
    }

    #[tokio::test]
    async fn an_agent_the_host_injects_wins_over_the_config() {
        struct Sink;
        impl TelemetryHandler for Sink {
            fn handler_name(&self) -> &'static str {
                "Sink"
            }
            fn health_check(&self) -> bool {
                true
            }
            fn send_event(
                &self,
                _event: &guard_core_rs::events::SecurityEvent,
            ) -> Result<(), guard_core_rs::composite::TelemetryError> {
                Ok(())
            }
            fn send_metric(
                &self,
                _metric: &guard_core_rs::metrics::SecurityMetric,
            ) -> Result<(), guard_core_rs::composite::TelemetryError> {
                Ok(())
            }
            fn start(&self) -> Result<(), guard_core_rs::composite::TelemetryError> {
                Ok(())
            }
            fn stop(&self) -> Result<(), guard_core_rs::composite::TelemetryError> {
                Ok(())
            }
        }
        let options = crate::WiringOptions {
            agent: Some(Arc::new(Sink)),
            logfire_client: None,
        };
        let layer = GuardFairing::from_security_config_with(&config(), &options).expect("layer");
        assert!(layer.agent_stats().enabled);
    }
}
