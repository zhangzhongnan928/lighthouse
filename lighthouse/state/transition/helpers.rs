use super::Hash256;
use super::TransitionError;

pub fn get_signed_parent_hashes(
    cycle_length: u8,
    block_slot: u64,
    attestation_slot: u64,
    current_hashes: Vec<Hash256>,
    oblique_hashes: Vec<Hash256>)
    -> Result<Vec<Hash256>, TransitionError>
{
    // This cast places a limit on cycle_length. If you change it, check math
    // for overflow.
    let cycle_length: u64 = cycle_length as u64;

    if current_hashes.len() as u64 != (cycle_length * 2) {
        return Err(TransitionError::InvalidInput(String::from(
                    "current_hashes.len() must equal cycle_length * 2")));
    }
    if attestation_slot >= block_slot {
        return Err(TransitionError::InvalidInput(String::from(
                    "attestation_slot must be less than block_slot")));
    }
    if oblique_hashes.len() as u64 > cycle_length {
        return Err(TransitionError::InvalidInput(String::from(
                    "oblique_hashes.len() must be <= cycle_length * 2")));
    }

    /*
     * Cannot underflow as block_slot cannot be less
     * than attestation_slot.
     */
    let attestation_distance = block_slot - attestation_slot;

    if attestation_distance > cycle_length {
        return Err(TransitionError::InvalidInput(String::from(
                    "attestation_slot must be withing one cycle of block_slot")));
    }

    /*
     * Cannot underflow because attestation_distance cannot
     * be larger than cycle_length.
     */
    let start = cycle_length - attestation_distance;

    /*
     * Overflow is potentially impossible, but proof is complicated
     * enough to just use checked math.
     *
     * Math is:
     * start + cycle_length - oblique_hashes.len()
     */
    let end = start.checked_add(cycle_length)
        .and_then(|x| x.checked_sub(oblique_hashes.len() as u64))
        .ok_or(TransitionError::IntWrapping)?;


    let mut hashes = Vec::new();
    hashes.extend_from_slice(
        &current_hashes[(start as usize)..(end as usize)]);
    hashes.append(&mut oblique_hashes.clone());

    Ok(hashes)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn get_range_of_hashes(from: usize, to: usize) -> Vec<Hash256> {
        (from..to).map(|i| get_hash(&vec![i as u8])).collect()
    }

    fn get_hash(value: &[u8]) -> Hash256 {
        Hash256::from_slice(value)
    }

    #[test]
    fn test_get_signed_hashes_no_oblique() {
        /*
         * Google Slides example.
         */
        let cycle_length: u8 = 8;
        let block_slot: u64 = 19;
        let attestation_slot: u64 = 15;
        let current_hashes = get_range_of_hashes(3, 19);
        let oblique_hashes = vec![];
        let result = get_signed_parent_hashes(
            cycle_length,
            block_slot,
            attestation_slot,
            current_hashes,
            oblique_hashes);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.len(), cycle_length as usize);
        let expected_result = get_range_of_hashes(7, 15);
        assert_eq!(result, expected_result);
    }
}
