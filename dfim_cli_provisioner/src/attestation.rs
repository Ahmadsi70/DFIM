//! TPM 2.0 quote protocol and remote-verifier policy.

use dfim_core_engine::{constant_time_hash_eq, sha256_digest_chunked};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// TPM-generated attestation magic.
pub const TPM_GENERATED_VALUE: u32 = 0xFF54_4347;
/// TPM structure tag for quote attestations.
pub const TPM_ST_ATTEST_QUOTE: u16 = 0x8018;
/// TPM algorithm identifier for SHA-256.
pub const TPM_ALG_SHA256: u16 = 0x000B;
/// Fixed PCR set required by the DFIM enterprise profile.
pub const ATTESTED_PCRS: [u8; 5] = [0, 2, 4, 7, 14];
/// Number of PCR values carried in DFIM evidence.
pub const ATTESTED_PCR_COUNT: usize = ATTESTED_PCRS.len();

const PCR_SELECTION_BITMAP: [u8; 3] = [0x95, 0x40, 0x00];
const QUALIFYING_DATA_DOMAIN: &[u8] = b"DFIM-ATTEST-V1";
const CHALLENGE_MAGIC: [u8; 8] = *b"DFIMCHL1";
const EVIDENCE_MAGIC: [u8; 8] = *b"DFIMATS1";
const POLICY_MAGIC: [u8; 8] = *b"DFIMPOL1";
const WIRE_VERSION: u32 = 1;
const CHALLENGE_WIRE_LEN: usize = 92;
const EVIDENCE_PREFIX_LEN: usize = 240;
const POLICY_WIRE_LEN: usize = 253;
const MAX_QUOTE_LEN: usize = 4096;

/// Verifier-issued freshness challenge bound to the expected DFIM state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationChallenge {
    pub nonce: [u8; 32],
    pub release_counter: u64,
    pub policy_generation: u64,
    pub merkle_root: [u8; 32],
}

/// TPM quote and synchronized PCR values returned by an attester.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestationEvidence {
    pub quote: Vec<u8>,
    pub signature: [u8; 64],
    pub pcr_values: [[u8; 32]; ATTESTED_PCR_COUNT],
}

/// Enrollment and allowlist policy held exclusively by the remote verifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttestationPolicy {
    pub ak_public_key_sec1: [u8; 33],
    pub expected_pcr_values: [[u8; 32]; ATTESTED_PCR_COUNT],
    pub minimum_release: u64,
    pub expected_policy_generation: u64,
    pub expected_merkle_root: [u8; 32],
}

/// Trusted fields returned after every quote gate succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedAttestation {
    pub release_counter: u64,
    pub policy_generation: u64,
    pub merkle_root: [u8; 32],
}

struct ParsedQuote {
    extra_data: [u8; 32],
    pcr_digest: [u8; 32],
}

/// Produces TPM qualifying data that binds freshness, release, policy, and image identity.
pub fn attestation_qualifying_data(challenge: &AttestationChallenge) -> [u8; 32] {
    let release = challenge.release_counter.to_be_bytes();
    let generation = challenge.policy_generation.to_be_bytes();
    sha256_digest_chunked(&[
        QUALIFYING_DATA_DOMAIN,
        &challenge.nonce,
        &release,
        &generation,
        &challenge.merkle_root,
    ])
}

/// Serializes a verifier challenge into the canonical DFIM attestation envelope.
pub fn encode_attestation_challenge(challenge: &AttestationChallenge) -> [u8; CHALLENGE_WIRE_LEN] {
    let mut output = [0u8; CHALLENGE_WIRE_LEN];
    output[..8].copy_from_slice(&CHALLENGE_MAGIC);
    output[8..12].copy_from_slice(&WIRE_VERSION.to_le_bytes());
    output[12..44].copy_from_slice(&challenge.nonce);
    output[44..52].copy_from_slice(&challenge.release_counter.to_le_bytes());
    output[52..60].copy_from_slice(&challenge.policy_generation.to_le_bytes());
    output[60..92].copy_from_slice(&challenge.merkle_root);
    output
}

/// Parses a canonical verifier challenge and rejects unknown versions or lengths.
pub fn parse_attestation_challenge(data: &[u8]) -> Result<AttestationChallenge, String> {
    if data.len() != CHALLENGE_WIRE_LEN {
        return Err("invalid attestation challenge length".into());
    }
    if data[..8] != CHALLENGE_MAGIC || read_le_u32(&data[8..12])? != WIRE_VERSION {
        return Err("unsupported attestation challenge envelope".into());
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&data[12..44]);
    let mut merkle_root = [0u8; 32];
    merkle_root.copy_from_slice(&data[60..92]);
    Ok(AttestationChallenge {
        nonce,
        release_counter: read_le_u64(&data[44..52])?,
        policy_generation: read_le_u64(&data[52..60])?,
        merkle_root,
    })
}

/// Serializes quote bytes, signature, and synchronized PCR values for transport.
#[cfg_attr(not(all(feature = "tpm", target_os = "linux")), allow(dead_code))]
pub fn encode_attestation_evidence(evidence: &AttestationEvidence) -> Result<Vec<u8>, String> {
    if evidence.quote.is_empty() || evidence.quote.len() > MAX_QUOTE_LEN {
        return Err("TPM quote length is outside the DFIM envelope limit".into());
    }
    let capacity = EVIDENCE_PREFIX_LEN
        .checked_add(evidence.quote.len())
        .ok_or_else(|| "attestation evidence length overflow".to_string())?;
    let mut output = Vec::with_capacity(capacity);
    output.extend_from_slice(&EVIDENCE_MAGIC);
    output.extend_from_slice(&WIRE_VERSION.to_le_bytes());
    output.extend_from_slice(&(evidence.quote.len() as u32).to_le_bytes());
    output.extend_from_slice(&evidence.signature);
    for value in &evidence.pcr_values {
        output.extend_from_slice(value);
    }
    output.extend_from_slice(&evidence.quote);
    Ok(output)
}

/// Parses a canonical evidence envelope without trusting its embedded PCR values.
pub fn parse_attestation_evidence(data: &[u8]) -> Result<AttestationEvidence, String> {
    if data.len() < EVIDENCE_PREFIX_LEN {
        return Err("truncated attestation evidence envelope".into());
    }
    if data[..8] != EVIDENCE_MAGIC || read_le_u32(&data[8..12])? != WIRE_VERSION {
        return Err("unsupported attestation evidence envelope".into());
    }
    let quote_len = read_le_u32(&data[12..16])? as usize;
    if quote_len == 0 || quote_len > MAX_QUOTE_LEN {
        return Err("TPM quote length is outside the DFIM envelope limit".into());
    }
    let expected_len = EVIDENCE_PREFIX_LEN
        .checked_add(quote_len)
        .ok_or_else(|| "attestation evidence length overflow".to_string())?;
    if data.len() != expected_len {
        return Err("non-canonical attestation evidence length".into());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&data[16..80]);
    let mut pcr_values = [[0u8; 32]; ATTESTED_PCR_COUNT];
    let mut offset = 80;
    for value in &mut pcr_values {
        value.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
    }
    Ok(AttestationEvidence {
        quote: data[EVIDENCE_PREFIX_LEN..].to_vec(),
        signature,
        pcr_values,
    })
}

/// Serializes an enrolled remote-verifier policy into a canonical binary record.
pub fn encode_attestation_policy(policy: &AttestationPolicy) -> [u8; POLICY_WIRE_LEN] {
    let mut output = [0u8; POLICY_WIRE_LEN];
    output[..8].copy_from_slice(&POLICY_MAGIC);
    output[8..12].copy_from_slice(&WIRE_VERSION.to_le_bytes());
    output[12..45].copy_from_slice(&policy.ak_public_key_sec1);
    output[45..53].copy_from_slice(&policy.minimum_release.to_le_bytes());
    output[53..61].copy_from_slice(&policy.expected_policy_generation.to_le_bytes());
    output[61..93].copy_from_slice(&policy.expected_merkle_root);
    let mut offset = 93;
    for value in &policy.expected_pcr_values {
        output[offset..offset + 32].copy_from_slice(value);
        offset += 32;
    }
    output
}

/// Parses an enrolled verifier policy and rejects malformed trust anchors.
pub fn parse_attestation_policy(data: &[u8]) -> Result<AttestationPolicy, String> {
    if data.len() != POLICY_WIRE_LEN {
        return Err("invalid attestation policy length".into());
    }
    if data[..8] != POLICY_MAGIC || read_le_u32(&data[8..12])? != WIRE_VERSION {
        return Err("unsupported attestation policy envelope".into());
    }
    let mut ak_public_key_sec1 = [0u8; 33];
    ak_public_key_sec1.copy_from_slice(&data[12..45]);
    VerifyingKey::from_sec1_bytes(&ak_public_key_sec1)
        .map_err(|_| "attestation policy contains an invalid AK public key".to_string())?;
    let minimum_release = read_le_u64(&data[45..53])?;
    if minimum_release == 0 {
        return Err("attestation policy release floor must be positive".into());
    }
    let expected_policy_generation = read_le_u64(&data[53..61])?;
    if expected_policy_generation == 0 {
        return Err("attestation policy generation must be positive".into());
    }
    let mut expected_merkle_root = [0u8; 32];
    expected_merkle_root.copy_from_slice(&data[61..93]);
    let mut expected_pcr_values = [[0u8; 32]; ATTESTED_PCR_COUNT];
    let mut offset = 93;
    for value in &mut expected_pcr_values {
        value.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;
    }
    Ok(AttestationPolicy {
        ak_public_key_sec1,
        expected_pcr_values,
        minimum_release,
        expected_policy_generation,
        expected_merkle_root,
    })
}

/// Verifies AK signature, nonce binding, exact PCR selection/digest, and enrolled policy.
pub fn verify_attestation(
    evidence: &AttestationEvidence,
    challenge: &AttestationChallenge,
    policy: &AttestationPolicy,
) -> Result<VerifiedAttestation, String> {
    if challenge.release_counter < policy.minimum_release {
        return Err("attestation release counter is below the verifier floor".into());
    }
    if challenge.policy_generation != policy.expected_policy_generation {
        return Err("attestation policy generation mismatch".into());
    }
    if !constant_time_hash_eq(&challenge.merkle_root, &policy.expected_merkle_root) {
        return Err("attestation Merkle root is not enrolled".into());
    }

    let signature = Signature::from_slice(&evidence.signature)
        .map_err(|_| "malformed ECDSA quote signature".to_string())?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&policy.ak_public_key_sec1)
        .map_err(|_| "invalid enrolled AK public key".to_string())?;
    verifying_key
        .verify(&evidence.quote, &signature)
        .map_err(|_| "TPM quote signature verification failed".to_string())?;

    let parsed = parse_quote(&evidence.quote)?;
    let expected_extra_data = attestation_qualifying_data(challenge);
    if !constant_time_hash_eq(&parsed.extra_data, &expected_extra_data) {
        return Err("TPM quote nonce or DFIM context binding mismatch".into());
    }

    for (actual, expected) in evidence
        .pcr_values
        .iter()
        .zip(policy.expected_pcr_values.iter())
    {
        if !constant_time_hash_eq(actual, expected) {
            return Err("quoted PCR value is outside the enrolled allowlist".into());
        }
    }
    let pcr_slices: Vec<&[u8]> = evidence
        .pcr_values
        .iter()
        .map(|value| value.as_slice())
        .collect();
    let expected_pcr_digest = sha256_digest_chunked(&pcr_slices);
    if !constant_time_hash_eq(&parsed.pcr_digest, &expected_pcr_digest) {
        return Err("quoted PCR digest does not match supplied PCR values".into());
    }

    Ok(VerifiedAttestation {
        release_counter: challenge.release_counter,
        policy_generation: challenge.policy_generation,
        merkle_root: challenge.merkle_root,
    })
}

fn parse_quote(quote: &[u8]) -> Result<ParsedQuote, String> {
    let mut cursor = Cursor::new(quote);
    if cursor.read_u32()? != TPM_GENERATED_VALUE {
        return Err("invalid TPM attestation magic".into());
    }
    if cursor.read_u16()? != TPM_ST_ATTEST_QUOTE {
        return Err("TPM evidence is not a quote attestation".into());
    }
    cursor.skip_tpm2b()?;
    let extra = cursor.read_tpm2b()?;
    if extra.len() != 32 {
        return Err("TPM qualifying data must be SHA-256 sized".into());
    }
    let mut extra_data = [0u8; 32];
    extra_data.copy_from_slice(extra);

    cursor.read_u64()?;
    cursor.read_u32()?;
    cursor.read_u32()?;
    if cursor.read_u8()? != 1 {
        return Err("TPM clock is not marked safe".into());
    }
    cursor.read_u64()?;

    if cursor.read_u32()? != 1 {
        return Err("exactly one PCR bank is required".into());
    }
    if cursor.read_u16()? != TPM_ALG_SHA256 {
        return Err("only the SHA-256 PCR bank is accepted".into());
    }
    if cursor.read_u8()? != PCR_SELECTION_BITMAP.len() as u8 {
        return Err("unexpected TPM PCR bitmap length".into());
    }
    if cursor.take(PCR_SELECTION_BITMAP.len())? != PCR_SELECTION_BITMAP {
        return Err("TPM PCR selection differs from DFIM policy".into());
    }

    let digest = cursor.read_tpm2b()?;
    if digest.len() != 32 || !cursor.is_empty() {
        return Err("non-canonical TPM quote digest encoding".into());
    }
    let mut pcr_digest = [0u8; 32];
    pcr_digest.copy_from_slice(digest);
    Ok(ParsedQuote {
        extra_data,
        pcr_digest,
    })
}

fn read_le_u32(bytes: &[u8]) -> Result<u32, String> {
    if bytes.len() != 4 {
        return Err("invalid u32 field length".into());
    }
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn read_le_u64(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() != 8 {
        return Err("invalid u64 field length".into());
    }
    Ok(u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or_else(|| "TPM quote length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated TPM quote".into());
        }
        let output = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(output)
    }

    fn read_u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn read_u16(&mut self) -> Result<u16, String> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        Ok(u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_tpm2b(&mut self) -> Result<&'a [u8], String> {
        let length = self.read_u16()? as usize;
        self.take(length)
    }

    fn skip_tpm2b(&mut self) -> Result<(), String> {
        self.read_tpm2b().map(|_| ())
    }

    fn is_empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dfim_core_engine::sha256_digest;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
    use std::fmt::Debug;

    const AK_PRIVATE: [u8; 32] = [0x33; 32];

    fn must<T, E: Debug>(result: Result<T, E>) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("test fixture failed: {error:?}"),
        }
    }

    fn challenge(nonce: u8, release_counter: u64) -> AttestationChallenge {
        AttestationChallenge {
            nonce: [nonce; 32],
            release_counter,
            policy_generation: 12,
            merkle_root: [0xA5; 32],
        }
    }

    fn pcr_values() -> [[u8; 32]; ATTESTED_PCR_COUNT] {
        [[0x00; 32], [0x02; 32], [0x04; 32], [0x07; 32], [0x0E; 32]]
    }

    fn fixture(challenge: &AttestationChallenge) -> (AttestationEvidence, AttestationPolicy) {
        let values = pcr_values();
        let quote = marshal_quote(challenge, &values, &ATTESTED_PCRS);
        let signing_key = must(SigningKey::from_bytes(&AK_PRIVATE.into()));
        let signature: Signature = signing_key.sign(&quote);
        let encoded = VerifyingKey::from(&signing_key).to_sec1_point(true);
        let mut public_key = [0u8; 33];
        public_key.copy_from_slice(encoded.as_bytes());
        (
            AttestationEvidence {
                quote,
                signature: signature.to_bytes().into(),
                pcr_values: values,
            },
            AttestationPolicy {
                ak_public_key_sec1: public_key,
                expected_pcr_values: values,
                minimum_release: 8,
                expected_policy_generation: 12,
                expected_merkle_root: [0xA5; 32],
            },
        )
    }

    fn marshal_quote(
        challenge: &AttestationChallenge,
        values: &[[u8; 32]; ATTESTED_PCR_COUNT],
        selected_pcrs: &[u8; ATTESTED_PCR_COUNT],
    ) -> Vec<u8> {
        let mut quote = Vec::new();
        quote.extend_from_slice(&TPM_GENERATED_VALUE.to_be_bytes());
        quote.extend_from_slice(&TPM_ST_ATTEST_QUOTE.to_be_bytes());
        quote.extend_from_slice(&0u16.to_be_bytes());
        let extra_data = attestation_qualifying_data(challenge);
        quote.extend_from_slice(&(extra_data.len() as u16).to_be_bytes());
        quote.extend_from_slice(&extra_data);
        quote.extend_from_slice(&1u64.to_be_bytes());
        quote.extend_from_slice(&0u32.to_be_bytes());
        quote.extend_from_slice(&0u32.to_be_bytes());
        quote.push(1);
        quote.extend_from_slice(&1u64.to_be_bytes());
        quote.extend_from_slice(&1u32.to_be_bytes());
        quote.extend_from_slice(&TPM_ALG_SHA256.to_be_bytes());
        quote.push(3);
        let mut bitmap = [0u8; 3];
        for pcr in selected_pcrs {
            bitmap[(*pcr / 8) as usize] |= 1 << (*pcr % 8);
        }
        quote.extend_from_slice(&bitmap);
        let chunks: Vec<&[u8]> = values.iter().map(|value| value.as_slice()).collect();
        let digest = sha256_digest(&chunks.concat());
        quote.extend_from_slice(&(digest.len() as u16).to_be_bytes());
        quote.extend_from_slice(&digest);
        quote
    }

    #[test]
    fn verifier_accepts_fresh_policy_bound_quote() {
        let request = challenge(0x11, 9);
        let (evidence, policy) = fixture(&request);
        let result = must(verify_attestation(&evidence, &request, &policy));
        assert_eq!(result.release_counter, 9);
        assert_eq!(result.policy_generation, 12);
    }

    #[test]
    fn verifier_rejects_replayed_nonce() {
        let request = challenge(0x11, 9);
        let (evidence, policy) = fixture(&request);
        assert!(verify_attestation(&evidence, &challenge(0x22, 9), &policy).is_err());
    }

    #[test]
    fn verifier_rejects_signature_and_pcr_substitution() {
        let request = challenge(0x11, 9);
        let (mut evidence, policy) = fixture(&request);
        evidence.signature[0] ^= 1;
        assert!(verify_attestation(&evidence, &request, &policy).is_err());

        let (mut evidence, policy) = fixture(&request);
        evidence.pcr_values[4][0] ^= 1;
        assert!(verify_attestation(&evidence, &request, &policy).is_err());
    }

    #[test]
    fn verifier_rejects_wrong_pcr_selection_and_rollback() {
        let request = challenge(0x11, 9);
        let (mut evidence, policy) = fixture(&request);
        evidence.quote = marshal_quote(&request, &evidence.pcr_values, &[0, 2, 4, 7, 13]);
        let signing_key = must(SigningKey::from_bytes(&AK_PRIVATE.into()));
        let signature: Signature = signing_key.sign(&evidence.quote);
        evidence.signature = signature.to_bytes().into();
        assert!(verify_attestation(&evidence, &request, &policy).is_err());

        let rollback = challenge(0x11, 7);
        let (evidence, policy) = fixture(&rollback);
        assert!(verify_attestation(&evidence, &rollback, &policy).is_err());
    }

    #[test]
    fn challenge_and_evidence_wire_formats_round_trip() {
        let request = challenge(0x44, 21);
        let request_bytes = encode_attestation_challenge(&request);
        assert_eq!(must(parse_attestation_challenge(&request_bytes)), request);

        let (evidence, _) = fixture(&request);
        let evidence_bytes = must(encode_attestation_evidence(&evidence));
        assert_eq!(must(parse_attestation_evidence(&evidence_bytes)), evidence);
    }

    #[test]
    fn evidence_wire_format_rejects_truncation_and_trailing_data() {
        let request = challenge(0x44, 21);
        let (evidence, _) = fixture(&request);
        let mut encoded = must(encode_attestation_evidence(&evidence));
        assert!(parse_attestation_evidence(&encoded[..encoded.len() - 1]).is_err());
        encoded.push(0);
        assert!(parse_attestation_evidence(&encoded).is_err());
    }

    #[test]
    fn verifier_policy_wire_format_round_trips() {
        let request = challenge(0x55, 11);
        let (_, policy) = fixture(&request);
        let encoded = encode_attestation_policy(&policy);
        assert_eq!(must(parse_attestation_policy(&encoded)), policy);
        let mut zero_generation = encoded;
        zero_generation[53..61].fill(0);
        assert!(parse_attestation_policy(&zero_generation).is_err());
    }
}
