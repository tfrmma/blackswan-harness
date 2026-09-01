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

    let mut array: Array<_, u32> = Array::try_from(map)
        .map_err(|e| HarnessError::ArmFailed(injector_id.to_string(), e.to_string()))?;

    array
        .set(0, value, 0)
        .map_err(|e| HarnessError::ArmFailed(injector_id.to_string(), e.to_string()))
}
