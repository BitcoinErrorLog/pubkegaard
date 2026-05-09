use ipnet::IpNet;
use pubkegaard_types::{Route, RouteKind, TrustGrant, ValidationError};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePolicy {
    grant: TrustGrant,
}

impl EffectivePolicy {
    pub fn compile(grant: TrustGrant, now_ms: u64) -> Result<Self, ValidationError> {
        grant.validate(now_ms)?;
        Ok(Self { grant })
    }

    pub fn permits_route(&self, route: &Route) -> bool {
        if self.is_denied(route.cidr) {
            return false;
        }

        match route.kind {
            RouteKind::Mesh => {
                self.grant.permissions.mesh
                    && route.cidr.prefix_len() == route.cidr.max_prefix_len()
            }
            RouteKind::Lan => {
                self.grant.permissions.lan_client && self.is_explicitly_allowed(route.cidr)
            }
            RouteKind::ExitIpv4 => {
                self.grant.permissions.exit_client && route.cidr == "0.0.0.0/0".parse().unwrap()
            }
            RouteKind::ExitIpv6 => {
                self.grant.permissions.exit_client && route.cidr == "::/0".parse().unwrap()
            }
        }
    }

    pub fn authorize_routes<'a>(
        &self,
        routes: impl IntoIterator<Item = &'a Route>,
    ) -> Result<Vec<Route>, ValidationError> {
        let mut accepted = Vec::new();
        for route in routes {
            if self.permits_route(route) {
                accepted.push(route.clone());
            } else {
                return Err(ValidationError::RouteDenied);
            }
        }
        Ok(accepted)
    }

    pub fn permissions(&self) -> &pubkegaard_types::Permissions {
        &self.grant.permissions
    }

    fn is_denied(&self, route: IpNet) -> bool {
        self.grant.denied_routes.contains(&route)
    }

    fn is_explicitly_allowed(&self, route: IpNet) -> bool {
        self.grant.allowed_routes.contains(&route)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubkegaard_types::{PubkyId, Route};

    fn subject() -> PubkyId {
        PubkyId::parse("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo").unwrap()
    }

    #[test]
    fn mesh_only_allows_host_route() {
        let grant = TrustGrant::mesh_only(subject());
        let policy = EffectivePolicy::compile(grant, 0).unwrap();
        let route = Route {
            cidr: "100.88.1.2/32".parse().unwrap(),
            kind: RouteKind::Mesh,
        };
        assert!(policy.permits_route(&route));
    }

    #[test]
    fn mesh_only_rejects_default_route() {
        let grant = TrustGrant::mesh_only(subject());
        let policy = EffectivePolicy::compile(grant, 0).unwrap();
        let route = Route {
            cidr: "0.0.0.0/0".parse().unwrap(),
            kind: RouteKind::ExitIpv4,
        };
        assert!(!policy.permits_route(&route));
    }
}
