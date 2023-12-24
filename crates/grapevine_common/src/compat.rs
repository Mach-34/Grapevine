use super::Fr as Fr_ff;
use babyjubjub_rs::Fr as Fr_ff_ce;
use ff::PrimeField;
use ff_ce::{PrimeField as PrimeField_ce, PrimeFieldRepr as PrimeFieldRepr_ce};
use poseidon_rs::FrRepr;

/**
 * Converts between Fr types
 * @notice Mismatch: babyjubjub_rs::Fr uses ff_ce v0.11 and nova_snark uses ff v0.13
 *         Default to using ff v0.13 and use this converter to handle translation
 *
 * @param el - the Fr element from babyjubjub-rs
 * @return - Fr element compatible with ff v0.13 (larger repo)
 */
pub fn convert_ff_ce_to_ff(el: &Fr_ff_ce) -> Fr_ff {    
    Fr_ff::from_repr(ff_ce_to_le_bytes(el)).unwrap()
}

/**
 * Extracts the little endian byte representation of a ff_ce Fr element
 *
 * @param el - the Fr element to convert to bytes
 * @return - little endian bytes of the field element
 */
pub fn ff_ce_to_le_bytes(el: &Fr_ff_ce) -> [u8; 32] {
    el.into_repr()
        .0
        .iter()
        .map(|limb| limb.to_le_bytes())
        .flatten()
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

/**
 * Wraps little endian byte representation of Fr in ff_ce Fr element
 * 
 * @param bytes - the little endian bytes to convert to Fr element
 * @return - ff_ce Fr element
 */
pub fn ff_ce_from_le_bytes(bytes: [u8; 32]) -> Fr_ff_ce {
    let mut repr = FrRepr::default();
    repr.read_le(&bytes[..]).unwrap();
    Fr_ff_ce::from_repr(repr).unwrap()
}

pub fn convert_ff_to_ff_ce(el: &Fr_ff) -> Fr_ff_ce {
    ff_ce_from_le_bytes(el.to_repr())
}

#[cfg(test)]
mod test {

    use super::*;
    use rand::{thread_rng, Rng};

    #[test]
    fn test_conversion() {
        // get random 31 bytes
        let mut rng = thread_rng();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes[..]);
        bytes[31] = 0;

        // instantiate Fr_bjj
        let mut repr = FrRepr::default();
        repr.read_le(&bytes[..]).unwrap();
        let fr_ff_ce = Fr_ff_ce::from_repr(repr).unwrap();

        // instantiate Fr_default
        let fr_ff = Fr_ff::from_repr(bytes).unwrap();

        // convert between types
        let fr_ff_ce_to_ff = convert_ff_ce_to_ff(&fr_ff_ce);
        let fr_ff_to_ff_ce = convert_ff_to_ff_ce(&fr_ff);

        // check converted types match
        assert!(fr_ff_ce.eq(&fr_ff_to_ff_ce));
        assert!(fr_ff.eq(&fr_ff_ce_to_ff));

        // round trip conversion for types
        let fr_ff_ce_roundtrip = convert_ff_to_ff_ce(&fr_ff_ce_to_ff);
        let fr_ff_roundtrip = convert_ff_ce_to_ff(&fr_ff_to_ff_ce);

        // check round trip conversions match
        assert!(fr_ff_ce.eq(&fr_ff_ce_roundtrip));
        assert!(fr_ff.eq(&fr_ff_roundtrip));
    }
}
