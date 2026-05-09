use ipnet::IpNet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FirewallAction {
    EnsureTable { family: String, table: String },
    AllowMeshInput { interface: String, peer: IpNet },
    AllowForwardToInternet { interface: String, peer: IpNet },
    DenyForwardToPrivateRanges { interface: String, peer: IpNet },
    RemovePeer { interface: String, peer: IpNet },
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FirewallPlan {
    pub actions: Vec<FirewallAction>,
    pub rollback: Vec<FirewallAction>,
}

impl FirewallPlan {
    pub fn mesh_peer(interface: impl Into<String>, peer: IpNet) -> Self {
        let interface = interface.into();
        Self {
            actions: vec![
                FirewallAction::EnsureTable {
                    family: "inet".into(),
                    table: "pubkegaard".into(),
                },
                FirewallAction::AllowMeshInput {
                    interface: interface.clone(),
                    peer,
                },
            ],
            rollback: vec![FirewallAction::RemovePeer { interface, peer }],
        }
    }

    pub fn exit_server_peer(interface: impl Into<String>, peer: IpNet) -> Self {
        let interface = interface.into();
        Self {
            actions: vec![
                FirewallAction::EnsureTable {
                    family: "inet".into(),
                    table: "pubkegaard".into(),
                },
                FirewallAction::DenyForwardToPrivateRanges {
                    interface: interface.clone(),
                    peer,
                },
                FirewallAction::AllowForwardToInternet {
                    interface: interface.clone(),
                    peer,
                },
            ],
            rollback: vec![FirewallAction::RemovePeer { interface, peer }],
        }
    }

    pub fn render_nftables_preview(&self) -> Vec<String> {
        self.actions.iter().map(render_action).collect()
    }
}

fn render_action(action: &FirewallAction) -> String {
    match action {
        FirewallAction::EnsureTable { family, table } => {
            format!("add table {} {}", family, table)
        }
        FirewallAction::AllowMeshInput { interface, peer } => {
            format!("allow input iifname {} ip saddr {}", interface, peer)
        }
        FirewallAction::AllowForwardToInternet { interface, peer } => {
            format!(
                "allow forward iifname {} ip saddr {} oifname != {}",
                interface, peer, interface
            )
        }
        FirewallAction::DenyForwardToPrivateRanges { interface, peer } => {
            format!(
                "deny private forward iifname {} ip saddr {}",
                interface, peer
            )
        }
        FirewallAction::RemovePeer { interface, peer } => {
            format!("remove rules for iifname {} ip saddr {}", interface, peer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mesh_plan_has_rollback() {
        let peer = "100.88.1.2/32".parse().unwrap();
        let plan = FirewallPlan::mesh_peer("pkg0", peer);
        assert!(!plan.actions.is_empty());
        assert_eq!(plan.rollback.len(), 1);
    }
}
