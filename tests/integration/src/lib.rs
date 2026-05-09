#[cfg(test)]
mod tests {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use pubkegaard_discovery::{pointer_for, verify_document_bytes};
    use pubkegaard_firewall::FirewallPlan;
    use pubkegaard_policy::EffectivePolicy;
    use pubkegaard_types::{
        Device, DiscoveryDocument, Endpoint, Permissions, PubkyId, Route, RouteKind, TrustGrant,
        WireGuardPublicKey, DISCOVERY_TYPE, VERSION_1,
    };
    use pubkegaard_wireguard::PeerConfig;

    fn identity() -> PubkyId {
        PubkyId::parse("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo").unwrap()
    }

    fn discovery() -> DiscoveryDocument {
        DiscoveryDocument {
            r#type: DISCOVERY_TYPE.to_string(),
            version: VERSION_1,
            identity: identity(),
            sequence: 1,
            created_at_ms: 1,
            expires_at_ms: 10_000,
            devices: vec![Device {
                device_id: "dev1".into(),
                wg_public_key: WireGuardPublicKey::parse(STANDARD.encode([8u8; 32])).unwrap(),
                addresses: vec!["100.88.1.2/32".parse().unwrap()],
                endpoints: vec![Endpoint {
                    host: "203.0.113.10".into(),
                    port: 51820,
                    priority: 10,
                }],
                routes: vec![Route {
                    cidr: "100.88.1.2/32".parse().unwrap(),
                    kind: RouteKind::Mesh,
                }],
                capabilities: Permissions {
                    mesh: true,
                    ..Permissions::default()
                },
            }],
        }
    }

    #[test]
    fn discovery_pointer_round_trip_verifies() {
        let document = discovery();
        let identity = identity();
        let pointer = pointer_for(&identity, &document).unwrap();
        let bytes = serde_json::to_vec(&document).unwrap();
        let verified = verify_document_bytes(&pointer, &bytes, &identity, 1, None).unwrap();
        assert_eq!(verified.identity, identity);
    }

    #[test]
    fn mesh_policy_and_wireguard_config_align() {
        let document = discovery();
        let grant = TrustGrant::mesh_only(identity());
        let policy = EffectivePolicy::compile(grant, 1).unwrap();
        assert!(policy.permits_route(&document.devices[0].routes[0]));
        let peer = PeerConfig::mesh_from_device(&document.devices[0]).unwrap();
        assert!(peer
            .render_peer_section()
            .contains("AllowedIPs = 100.88.1.2/32"));
    }

    #[test]
    fn revocation_has_firewall_rollback_plan() {
        let peer = "100.88.1.2/32".parse().unwrap();
        let plan = FirewallPlan::mesh_peer("pkg0", peer);
        assert_eq!(plan.rollback.len(), 1);
    }
}
