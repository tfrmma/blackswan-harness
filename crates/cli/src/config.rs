use serde::Deserialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;

// Declarative shape of a scenario config file. `schedule` reuses
// blackswan_core::ScenarioStep directly rather than a copy of the same
// three fields, it's already the right shape and already Deserialize.
#[derive(Debug, Deserialize)]
pub struct Config {
    pub name: String,
    pub seed: u64,
    pub injectors: HashMap<String, InjectorConfig>,
    pub schedule: Vec<blackswan_core::ScenarioStep>,
}

// One variant per real FaultInjector this binary knows how to build, see
// build.rs. Adding a ninth injector means adding a variant here and a
// match arm there, nothing else in this crate needs to change.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InjectorConfig {
    XdpPacketLoss { iface: String, drop_every_n: u32 },
    XdpCorruption { iface: String, corrupt_every_n: u32, offset: u32, mask: u8 },
    XdpPartition { iface: String, src_ip: Ipv4Addr, src_port: u16 },
    CgroupMemoryPressure { pid: u32, limit_bytes: u64, mode: PressureModeConfig },
    TimeSkew { argv: Vec<String>, monotonic_offset_secs: i64, boottime_offset_secs: i64 },
    FixSilentReject { listen_addr: String, upstream_addr: String },
    FixAckWithoutExecution { listen_addr: String, upstream_addr: String },
    FixRateLimitThrottle { listen_addr: String, upstream_addr: String, threshold: u64 },
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PressureModeConfig {
    Hard,
    Soft,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_one(toml_body: &str) -> InjectorConfig {
        #[derive(Deserialize)]
        struct Wrapper {
            injector: InjectorConfig,
        }
        let wrapped = format!("[injector]\n{toml_body}");
        toml::from_str::<Wrapper>(&wrapped).expect("parse injector config").injector
    }

    #[test]
    fn parses_every_injector_variant() {
        assert!(matches!(
            parse_one("type = \"xdp_packet_loss\"\niface = \"eth0\"\ndrop_every_n = 5"),
            InjectorConfig::XdpPacketLoss { .. }
        ));
        assert!(matches!(
            parse_one("type = \"xdp_corruption\"\niface = \"eth0\"\ncorrupt_every_n = 5\noffset = 60\nmask = 255"),
            InjectorConfig::XdpCorruption { .. }
        ));
        assert!(matches!(
            parse_one("type = \"xdp_partition\"\niface = \"eth0\"\nsrc_ip = \"10.0.0.1\"\nsrc_port = 4000"),
            InjectorConfig::XdpPartition { .. }
        ));
        assert!(matches!(
            parse_one("type = \"cgroup_memory_pressure\"\npid = 1234\nlimit_bytes = 8388608\nmode = \"hard\""),
            InjectorConfig::CgroupMemoryPressure { .. }
        ));
        assert!(matches!(
            parse_one("type = \"time_skew\"\nargv = [\"sleep\", \"100\"]\nmonotonic_offset_secs = 1000\nboottime_offset_secs = 1000"),
            InjectorConfig::TimeSkew { .. }
        ));
        assert!(matches!(
            parse_one("type = \"fix_silent_reject\"\nlisten_addr = \"127.0.0.1:9001\"\nupstream_addr = \"127.0.0.1:9002\""),
            InjectorConfig::FixSilentReject { .. }
        ));
        assert!(matches!(
            parse_one(
                "type = \"fix_ack_without_execution\"\nlisten_addr = \"127.0.0.1:9001\"\nupstream_addr = \"127.0.0.1:9002\""
            ),
            InjectorConfig::FixAckWithoutExecution { .. }
        ));
        assert!(matches!(
            parse_one(
                "type = \"fix_rate_limit_throttle\"\nlisten_addr = \"127.0.0.1:9001\"\nupstream_addr = \"127.0.0.1:9002\"\nthreshold = 3"
            ),
            InjectorConfig::FixRateLimitThrottle { .. }
        ));
    }

    #[test]
    fn parses_a_full_scenario_config_with_lowercase_actions() {
        let toml_str = r#"
name = "demo"
seed = 42

[injectors.throttle]
type = "fix_rate_limit_throttle"
listen_addr = "127.0.0.1:19100"
upstream_addr = "127.0.0.1:19101"
threshold = 3

[[schedule]]
at_ns = 0
fault_id = "throttle"
action = "arm"

[[schedule]]
at_ns = 5000000000
fault_id = "throttle"
action = "disarm"
"#;
        let config: Config = toml::from_str(toml_str).expect("parse full config");
        assert_eq!(config.name, "demo");
        assert_eq!(config.schedule.len(), 2);
        assert!(config.injectors.contains_key("throttle"));
    }
}
