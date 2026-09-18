use aya::maps::Array;
use aya::Bpf;
use blackswan_core::HarnessError;

// Shared by every XDP-based injector: write a single u32 config value into a
// legacy array map at index 0. Extracted once XdpCorruptionInjector made
// this the second copy of the same four lines that XdpPacketLossInjector
// already had, not before, no point abstracting from a single example.
pub fn set_u32_map(bpf: &mut Bpf, injector_id: &str, map_name: &str, value: u32) -> Result<(), HarnessError> {
    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| HarnessError::ArmFailed(injector_id.to_string(), format!("no map named {map_name}")))?;

    let mut array: Array<_, u32> =
        Array::try_from(map).map_err(|e| HarnessError::ArmFailed(injector_id.to_string(), e.to_string()))?;

    array
        .set(0, value, 0)
        .map_err(|e| HarnessError::ArmFailed(injector_id.to_string(), e.to_string()))
}

// same as set_u32_map, 16 bytes instead of 4, for IPv6 addresses (XdpPartitionInjector's
// partition_src_ip6). Ipv6Addr::octets() is already network byte order, no
// ne_bytes/ntohl dance needed here the way the v4 path needs for its u32.
pub fn set_bytes16_map(bpf: &mut Bpf, injector_id: &str, map_name: &str, value: [u8; 16]) -> Result<(), HarnessError> {
    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| HarnessError::ArmFailed(injector_id.to_string(), format!("no map named {map_name}")))?;

    let mut array: Array<_, [u8; 16]> =
        Array::try_from(map).map_err(|e| HarnessError::ArmFailed(injector_id.to_string(), e.to_string()))?;

    array
        .set(0, value, 0)
        .map_err(|e| HarnessError::ArmFailed(injector_id.to_string(), e.to_string()))
}
