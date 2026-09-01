// SplitMix64 (Vigna, public domain, https://prng.di.unimi.it/splitmix64.c).
// Deterministic, fast, statistically fine for fault-injection probability
// draws, not claiming it's suitable for anything cryptographic.
//
// Skipped the rand/rand_chacha crates on purpose here, this is 20 lines of a
// well specified algorithm and pulling in a whole RNG ecosystem plus its
// transitive deps for coin flips felt like the wrong tradeoff for this repo.
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn from_seed(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    // [0.0, 1.0), using the top 53 bits so the result is uniform over the
    // representable f64 mantissa. Good enough for "drop this packet 2% of
    // the time" style checks.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    pub fn gen_bool(&mut self, probability: f64) -> bool {
        self.next_f64() < probability
    }

    pub fn gen_range_u64(&mut self, low: u64, high: u64) -> u64 {
        debug_assert!(low < high, "gen_range_u64: low must be < high");
        low + self.next_u64() % (high - low)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_sequence() {
        let mut a = DeterministicRng::from_seed(42);
        let mut b = DeterministicRng::from_seed(42);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn different_seed_diverges() {
        let mut a = DeterministicRng::from_seed(1);
        let mut b = DeterministicRng::from_seed(2);
        assert_ne!(a.next_u64(), b.next_u64());
    }

    #[test]
    fn matches_reference_vector() {
        // First output for seed 1234567, cross-checked against the reference
        // splitmix64.c so a silent typo in the constants doesn't slip in
        // undetected.
        let mut rng = DeterministicRng::from_seed(1234567);
        assert_eq!(rng.next_u64(), 6457827717110365317);
    }

    #[test]
    fn next_f64_stays_in_unit_range() {
        let mut rng = DeterministicRng::from_seed(7);
        for _ in 0..10_000 {
            let f = rng.next_f64();
            assert!((0.0..1.0).contains(&f));
        }
    }
}
