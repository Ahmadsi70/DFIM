//! Hardware Root of Trust — TPM 2.0 PCR-14 extension for Merkle attestation.
//!
//! Routes through standard Linux TCG device nodes (`/dev/tpmrm0`, `/dev/tpm0`).

use std::convert::TryFrom;
use std::path::Path;
use std::str::FromStr;

use crate::attestation::{
    attestation_qualifying_data, AttestationChallenge, AttestationEvidence, ATTESTED_PCR_COUNT,
};
use p256::ecdsa::VerifyingKey;
use tss_esapi::{
    abstraction::{ak, ek, AsymmetricAlgorithmSelection},
    handles::PcrHandle,
    interface_types::{
        algorithm::{HashingAlgorithm, SignatureSchemeAlgorithm},
        ecc::EccCurve,
    },
    structures::{
        Data, Digest, DigestValues, PcrSelectionList, PcrSelectionListBuilder, PcrSlot, Private,
        Public, Signature, SignatureScheme,
    },
    tcti_ldr::{DeviceConfig, TctiNameConf},
    traits::{Marshall, UnMarshall},
    Context,
};

/// Preferred Linux TPM 2.0 device paths (resource manager first, raw device fallback).
pub const TPM_DEVICE_CANDIDATES: &[&str] = &["/dev/tpmrm0", "/dev/tpm0"];

/// Optional TCTI override for CI simulators (`swtpm:host=127.0.0.1,port=2321`).
pub const DFIM_TPM_TCTI_ENV: &str = "DFIM_TPM_TCTI";

type PcrSnapshot = (u32, [[u8; 32]; ATTESTED_PCR_COUNT]);

/// Marshalled TPM-resident AK object plus its verifier enrollment key.
pub struct EnrolledAttestationKey {
    pub private_blob: Vec<u8>,
    pub public_blob: Vec<u8>,
    pub public_key_sec1: [u8; 33],
}

/// Extends `merkle_root` into TPM PCR-14 via the first available Linux TCTI device.
pub fn extend_merkle_root_to_hardware_tpm(
    merkle_root: &[u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let (device_path, mut context) = open_first_available_tpm_context()?;

    let digest = Digest::try_from(merkle_root.as_slice())?;
    let mut digests = DigestValues::new();
    digests.set(HashingAlgorithm::Sha256, digest);

    context.pcr_extend(PcrHandle::Pcr14, digests)?;

    eprintln!("[DFIM-TPM] Merkle root extended into PCR-14 via {device_path}");
    Ok(())
}

/// Creates a restricted ECC P-256 attestation key under the TPM endorsement key.
pub fn create_attestation_key() -> Result<EnrolledAttestationKey, Box<dyn std::error::Error>> {
    let (_, mut context) = open_first_available_tpm_context()?;
    let key_algorithm = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
    let endorsement_key = ek::create_ek_object_2(&mut context, key_algorithm, None)?;
    let created = ak::create_ak_2(
        &mut context,
        endorsement_key,
        HashingAlgorithm::Sha256,
        key_algorithm,
        SignatureSchemeAlgorithm::EcDsa,
        None,
        None,
    )?;
    let public_key_sec1 = ecc_public_to_sec1(&created.out_public)?;
    let private_blob = created.out_private.value().to_vec();
    let public_blob = created.out_public.marshall()?;
    context.flush_context(endorsement_key.into())?;
    Ok(EnrolledAttestationKey {
        private_blob,
        public_blob,
        public_key_sec1,
    })
}

/// Produces a synchronized PCR quote using a previously enrolled TPM AK.
pub fn quote_attestation(
    challenge: &AttestationChallenge,
    private_blob: &[u8],
    public_blob: &[u8],
) -> Result<AttestationEvidence, Box<dyn std::error::Error>> {
    let (_, mut context) = open_first_available_tpm_context()?;
    let key_algorithm = AsymmetricAlgorithmSelection::Ecc(EccCurve::NistP256);
    let endorsement_key = ek::create_ek_object_2(&mut context, key_algorithm, None)?;
    let private = Private::try_from(private_blob)?;
    let public = Public::unmarshall(public_blob)?;
    let loaded_ak = ak::load_ak(&mut context, endorsement_key, None, private, public)?;
    let selection = attested_pcr_selection()?;
    let (counter_before, pcr_values_before) = read_pcr_snapshot(&mut context, &selection)?;
    let qualifying_data = Data::try_from(attestation_qualifying_data(challenge).to_vec())?;
    let (attest, signature) = context.quote(
        loaded_ak,
        qualifying_data,
        SignatureScheme::Null,
        selection.clone(),
    )?;
    let (counter_after, pcr_values_after) = read_pcr_snapshot(&mut context, &selection)?;
    if counter_before != counter_after || pcr_values_before != pcr_values_after {
        return Err("PCR values changed while the TPM quote was generated".into());
    }
    let signature = normalize_ecdsa_signature(signature)?;
    let quote = attest.marshall()?;
    context.flush_context(loaded_ak.into())?;
    context.flush_context(endorsement_key.into())?;
    Ok(AttestationEvidence {
        quote,
        signature,
        pcr_values: pcr_values_after,
    })
}

fn attested_pcr_selection() -> Result<PcrSelectionList, Box<dyn std::error::Error>> {
    PcrSelectionListBuilder::new()
        .with_selection(
            HashingAlgorithm::Sha256,
            &[
                PcrSlot::Slot0,
                PcrSlot::Slot2,
                PcrSlot::Slot4,
                PcrSlot::Slot7,
                PcrSlot::Slot14,
            ],
        )
        .build()
        .map_err(Into::into)
}

fn read_pcr_snapshot(
    context: &mut Context,
    selection: &PcrSelectionList,
) -> Result<PcrSnapshot, Box<dyn std::error::Error>> {
    let (counter, returned_selection, digests) = context.pcr_read(selection.clone())?;
    if returned_selection != *selection || digests.len() != ATTESTED_PCR_COUNT {
        return Err("TPM returned an incomplete PCR selection".into());
    }
    let mut values = [[0u8; 32]; ATTESTED_PCR_COUNT];
    for (output, digest) in values.iter_mut().zip(digests.value()) {
        if digest.value().len() != output.len() {
            return Err("TPM returned a non-SHA-256 PCR value".into());
        }
        output.copy_from_slice(digest.value());
    }
    Ok((counter, values))
}

fn normalize_ecdsa_signature(signature: Signature) -> Result<[u8; 64], Box<dyn std::error::Error>> {
    let Signature::EcDsa(signature) = signature else {
        return Err("TPM AK returned a non-ECDSA signature".into());
    };
    if signature.hashing_algorithm() != HashingAlgorithm::Sha256 {
        return Err("TPM AK returned a non-SHA-256 signature".into());
    }
    let mut output = [0u8; 64];
    copy_left_padded(signature.signature_r().value(), &mut output[..32])?;
    copy_left_padded(signature.signature_s().value(), &mut output[32..])?;
    Ok(output)
}

fn copy_left_padded(source: &[u8], output: &mut [u8]) -> Result<(), Box<dyn std::error::Error>> {
    if source.is_empty() || source.len() > output.len() {
        return Err("invalid TPM ECC signature component length".into());
    }
    let start = output.len() - source.len();
    output[start..].copy_from_slice(source);
    Ok(())
}

fn ecc_public_to_sec1(public: &Public) -> Result<[u8; 33], Box<dyn std::error::Error>> {
    let Public::Ecc { unique, .. } = public else {
        return Err("TPM AK public object is not ECC".into());
    };
    let x = unique.x().value();
    let y = unique.y().value();
    if x.is_empty() || x.len() > 32 || y.is_empty() || y.len() > 32 {
        return Err("TPM AK is not a P-256 public key".into());
    }
    let mut encoded = [0u8; 33];
    encoded[0] = 0x02 | (y[y.len() - 1] & 1);
    encoded[33 - x.len()..].copy_from_slice(x);
    VerifyingKey::from_sec1_bytes(&encoded)
        .map_err(|_| "TPM returned an invalid P-256 AK public key")?;
    Ok(encoded)
}

fn open_first_available_tpm_context() -> Result<(String, Context), Box<dyn std::error::Error>> {
    if let Ok(tcti_name) = std::env::var(DFIM_TPM_TCTI_ENV) {
        if !tcti_name.is_empty() {
            let tcti = TctiNameConf::from_str(&tcti_name)?;
            let context = Context::new(tcti)?;
            return Ok((tcti_name, context));
        }
    }

    let mut last_err: Option<String> = None;
    for candidate in TPM_DEVICE_CANDIDATES {
        if !Path::new(candidate).exists() {
            continue;
        }
        match try_open_tpm_context(candidate) {
            Ok(ctx) => return Ok(((*candidate).to_string(), ctx)),
            Err(err) => last_err = Some(format!("{candidate}: {err}")),
        }
    }
    Err(format!(
        "no accessible Linux TPM device (tried {}): {}",
        TPM_DEVICE_CANDIDATES.join(", "),
        last_err.unwrap_or_else(|| "none present".into())
    )
    .into())
}

fn try_open_tpm_context(device_path: &str) -> Result<Context, Box<dyn std::error::Error>> {
    let device = DeviceConfig::from_str(device_path)?;
    let tcti = TctiNameConf::Device(device);
    Context::new(tcti).map_err(|err| err.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_candidates_prefer_resource_manager() {
        assert_eq!(TPM_DEVICE_CANDIDATES[0], "/dev/tpmrm0");
        assert_eq!(TPM_DEVICE_CANDIDATES[1], "/dev/tpm0");
    }

    #[test]
    fn tpm_tcti_env_constant_is_stable() {
        assert_eq!(DFIM_TPM_TCTI_ENV, "DFIM_TPM_TCTI");
    }
}
