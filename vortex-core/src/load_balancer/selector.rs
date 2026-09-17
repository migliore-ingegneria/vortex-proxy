//! Load Balancing Selector logic

use crate::domain::backend::SharedBackend;
use crate::domain::routing::SharedRoutingTable;

/// Selects the optimal backend using the Peak EWMA algorithm.
pub fn select_best_backend(routing_table: &SharedRoutingTable) -> Option<SharedBackend> {
    let backends = routing_table.snapshot();

    use crate::domain::circuit_breaker::CircuitState;

    backends
        .iter()
        .filter(|b| b.is_healthy() && b.circuit_breaker.state() != CircuitState::Open)
        .min_by(|a, b| {
            let score_a = a.ewma.calculate_score();
            let score_b = b.ewma.calculate_score();
            score_a
                .partial_cmp(&score_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .cloned()
}

/// Returns all healthy, active backends sorted by their Peak EWMA routing score.
pub fn select_healthy_backends(routing_table: &SharedRoutingTable) -> Vec<SharedBackend> {
    let backends = routing_table.snapshot();
    use crate::domain::circuit_breaker::CircuitState;

    let mut healthy: Vec<SharedBackend> = backends
        .iter()
        .filter(|b| b.is_healthy() && b.circuit_breaker.state() != CircuitState::Open)
        .cloned()
        .collect();

    healthy.sort_by(|a, b| {
        let score_a = a.ewma.calculate_score();
        let score_b = b.ewma.calculate_score();
        score_a
            .partial_cmp(&score_b)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    healthy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::domain::backend::{Backend, BackendId};
    use crate::domain::routing::RoutingTable;

    #[test]
    fn test_select_best_backend_returns_lowest_ewma_score() {
        let b1 = Arc::new(Backend::new(BackendId(1), "127.0.0.1:8080".parse().unwrap()));
        let b2 = Arc::new(Backend::new(BackendId(2), "127.0.0.1:8081".parse().unwrap()));

        b1.ewma.observe_latency(200.0);
        b2.ewma.observe_latency(20.0);

        let routing_table = Arc::new(RoutingTable::new(vec![b1.clone(), b2.clone()]));
        let selected = select_best_backend(&routing_table).unwrap();

        assert_eq!(selected.id.0, 2);
    }

    #[test]
    fn test_select_healthy_backends_filters_unhealthy_and_sorts() {
        let b1 = Arc::new(Backend::new(BackendId(1), "127.0.0.1:8080".parse().unwrap()));
        let b2 = Arc::new(Backend::new(BackendId(2), "127.0.0.1:8081".parse().unwrap()));

        b1.set_healthy(false);
        b2.ewma.observe_latency(15.0);

        let routing_table = Arc::new(RoutingTable::new(vec![b1.clone(), b2.clone()]));
        let healthy = select_healthy_backends(&routing_table);

        assert_eq!(healthy.len(), 1);
        assert_eq!(healthy[0].id.0, 2);
    }
}
