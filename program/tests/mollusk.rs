use {
    mollusk_svm::{result::ProgramResult, Mollusk},
    p256::ecdsa::{signature::Signer, Signature, SigningKey},
    pinocchio::error::ProgramError,
    solana_account::Account,
    solana_address::Address,
    solana_instruction::{AccountMeta, Instruction},
    solana_secp256r1_verify::{
        constants::{
            COMPRESSED_PUBKEY_SERIALIZED_SIZE, SCALAR_BYTES, SECP256R1_ORDER,
            SIGNATURE_SERIALIZED_SIZE,
        },
        verify,
    },
    std::{env, path::PathBuf},
};

const PROGRAM_SO_STEM: &str = "solana_secp256r1_program";
const SINGLE_MESSAGE: &[u8] = b"deterministic secp256r1 verify benchmark";
const PUBLIC_KEY_OFFSET: usize = 0;
const SIGNATURE_OFFSET: usize = COMPRESSED_PUBKEY_SERIALIZED_SIZE;
const S_OFFSET: usize = SIGNATURE_OFFSET + SCALAR_BYTES;
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;

fn sbf_program_path() -> Option<String> {
    if let Some(out_dir) = env::var_os("SBF_OUT_DIR") {
        let path = PathBuf::from(out_dir).join(PROGRAM_SO_STEM);
        let so_path = path.with_extension("so");
        assert!(
            so_path.exists(),
            "SBF artifact not found at {}; run make build-sbf-program first",
            so_path.display()
        );
        return Some(path.to_string_lossy().into_owned());
    }

    eprintln!("skipping Mollusk SBF tests: set SBF_OUT_DIR to target/deploy");
    None
}

fn make_mollusk() -> Option<(Mollusk, Address)> {
    let program_path = sbf_program_path()?;
    let program_id = Address::new_unique();
    let mut mollusk = Mollusk::default();
    mollusk.add_program(&program_id, &program_path);
    Some((mollusk, program_id))
}

fn instruction(program_id: Address, data: Vec<u8>) -> Instruction {
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&[7; 32]).unwrap()
}

/// Signs `message` and returns the low-s form of the signature, which is the
/// form the program accepts by default.
fn low_s_signature(message: &[u8]) -> Signature {
    let signature: Signature = signing_key().sign(message);
    signature.normalize_s().unwrap_or(signature)
}

fn signature_instruction(
    program_id: Address,
    signature: &Signature,
    message: &[u8],
) -> Instruction {
    let public_key = signing_key()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let signature = signature.to_bytes().into();

    verify(&program_id, &public_key, &signature, message)
}

fn signed_instruction(program_id: Address, message: &[u8]) -> Instruction {
    signature_instruction(program_id, &low_s_signature(message), message)
}

#[test]
fn verifies_single_signature_on_sbf_and_reports_compute_units() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = signed_instruction(program_id, SINGLE_MESSAGE);
    let result = mollusk.process_instruction(&ix, &[]);

    assert!(
        result.program_result.is_ok(),
        "verify failed: {:?}",
        result.program_result
    );
    println!(
        "secp256r1 verify: 1 signature, {} message bytes, {} CUs",
        SINGLE_MESSAGE.len(),
        result.compute_units_consumed
    );
}

#[test]
fn rejects_high_s_signature_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let (r, s) = low_s_signature(SINGLE_MESSAGE).split_scalars();
    let high_s = Signature::from_scalars(r, -s).unwrap();
    let ix = signature_instruction(program_id, &high_s, SINGLE_MESSAGE);

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
fn rejects_out_of_range_s_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.data[S_OFFSET..MESSAGE_OFFSET].copy_from_slice(&SECP256R1_ORDER);

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
#[ignore = "the elliptic-curve check is not implemented until the SIMD-0565 syscalls are available"]
fn rejects_tampered_message_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.data[MESSAGE_OFFSET] ^= 1;

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
#[ignore = "the elliptic-curve check is not implemented until the SIMD-0565 syscalls are available"]
fn rejects_tampered_public_key_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.data[PUBLIC_KEY_OFFSET + 1] ^= 1;

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}

#[test]
fn rejects_accounts_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let account = Address::new_unique();
    let mut ix = signed_instruction(program_id, SINGLE_MESSAGE);
    ix.accounts = vec![AccountMeta::new_readonly(account, false)];
    let accounts = [(account, Account::default())];

    let result = mollusk.process_instruction(&ix, &accounts);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidArgument),
    );
}

#[test]
fn rejects_short_instruction_on_sbf() {
    let Some((mollusk, program_id)) = make_mollusk() else {
        return;
    };
    let ix = instruction(program_id, vec![0; MESSAGE_OFFSET - 1]);

    let result = mollusk.process_instruction(&ix, &[]);
    assert_eq!(
        result.program_result,
        ProgramResult::Failure(ProgramError::InvalidInstructionData),
    );
}
