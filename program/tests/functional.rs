use {
    p256::ecdsa::{signature::Signer as _, Signature, SigningKey},
    solana_program_test::{tokio, ProgramTest},
    solana_secp256r1_verify::{
        constants::{
            COMPRESSED_PUBKEY_SERIALIZED_SIZE, SCALAR_BYTES, SECP256R1_ORDER,
            SIGNATURE_SERIALIZED_SIZE,
        },
        verify, ID,
    },
    solana_signer::Signer,
    solana_transaction::{
        AccountMeta, Address, Instruction, InstructionError, Transaction, TransactionError,
    },
    std::env,
};

const PROGRAM_NAME: &str = "solana_secp256r1_program";
const SINGLE_MESSAGE: &[u8] = b"deterministic secp256r1 verify benchmark";
const PUBLIC_KEY_OFFSET: usize = 0;
const SIGNATURE_OFFSET: usize = COMPRESSED_PUBKEY_SERIALIZED_SIZE;
const S_OFFSET: usize = SIGNATURE_OFFSET + SCALAR_BYTES;
const MESSAGE_OFFSET: usize = SIGNATURE_OFFSET + SIGNATURE_SERIALIZED_SIZE;

fn program_test() -> Option<ProgramTest> {
    if env::var_os("SBF_OUT_DIR").is_none() {
        eprintln!("skipping SBF tests: set SBF_OUT_DIR to target/deploy");
        return None;
    }

    let mut program_test = ProgramTest::default();
    program_test.prefer_bpf(true);
    program_test.add_program(PROGRAM_NAME, ID, None);
    Some(program_test)
}

/// Processes `instruction` in its own transaction and returns the result
/// along with the compute units the transaction consumed.
async fn process(instruction: Instruction) -> Option<(Result<(), TransactionError>, u64)> {
    let (banks_client, payer, recent_blockhash) = program_test()?.start().await;
    let transaction = Transaction::new_signed_with_payer(
        &[instruction],
        Some(&payer.pubkey()),
        &[&payer],
        recent_blockhash,
    );

    let result = banks_client
        .process_transaction_with_metadata(transaction)
        .await
        .unwrap();
    let compute_units = result.metadata.unwrap().compute_units_consumed;
    Some((result.result, compute_units))
}

fn instruction_error(error: InstructionError) -> Result<(), TransactionError> {
    Err(TransactionError::InstructionError(0, error))
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

fn signature_instruction(signature: &Signature, message: &[u8]) -> Instruction {
    let public_key = signing_key()
        .verifying_key()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .unwrap();
    let signature = signature.to_bytes().into();

    verify(&ID, &public_key, &signature, message)
}

fn signed_instruction(message: &[u8]) -> Instruction {
    signature_instruction(&low_s_signature(message), message)
}

#[tokio::test]
async fn verifies_single_signature_on_sbf_and_reports_compute_units() {
    let Some((result, compute_units)) = process(signed_instruction(SINGLE_MESSAGE)).await else {
        return;
    };

    assert_eq!(result, Ok(()));
    println!(
        "secp256r1 verify: 1 signature, {} message bytes, {} CUs",
        SINGLE_MESSAGE.len(),
        compute_units
    );
}

#[tokio::test]
async fn rejects_high_s_signature_on_sbf() {
    let (r, s) = low_s_signature(SINGLE_MESSAGE).split_scalars();
    let high_s = Signature::from_scalars(r, -s).unwrap();
    let ix = signature_instruction(&high_s, SINGLE_MESSAGE);

    let Some((result, _)) = process(ix).await else {
        return;
    };
    assert_eq!(
        result,
        instruction_error(InstructionError::InvalidInstructionData)
    );
}

#[tokio::test]
async fn rejects_out_of_range_s_on_sbf() {
    let mut ix = signed_instruction(SINGLE_MESSAGE);
    ix.data[S_OFFSET..MESSAGE_OFFSET].copy_from_slice(&SECP256R1_ORDER);

    let Some((result, _)) = process(ix).await else {
        return;
    };
    assert_eq!(
        result,
        instruction_error(InstructionError::InvalidInstructionData)
    );
}

#[tokio::test]
#[ignore = "the elliptic-curve check is not implemented until the SIMD-0565 syscalls are available"]
async fn rejects_tampered_message_on_sbf() {
    let mut ix = signed_instruction(SINGLE_MESSAGE);
    ix.data[MESSAGE_OFFSET] ^= 1;

    let Some((result, _)) = process(ix).await else {
        return;
    };
    assert_eq!(
        result,
        instruction_error(InstructionError::InvalidInstructionData)
    );
}

#[tokio::test]
#[ignore = "the elliptic-curve check is not implemented until the SIMD-0565 syscalls are available"]
async fn rejects_tampered_public_key_on_sbf() {
    let mut ix = signed_instruction(SINGLE_MESSAGE);
    ix.data[PUBLIC_KEY_OFFSET + 1] ^= 1;

    let Some((result, _)) = process(ix).await else {
        return;
    };
    assert_eq!(
        result,
        instruction_error(InstructionError::InvalidInstructionData)
    );
}

#[tokio::test]
async fn rejects_accounts_on_sbf() {
    let mut ix = signed_instruction(SINGLE_MESSAGE);
    ix.accounts = vec![AccountMeta::new_readonly(Address::new_unique(), false)];

    let Some((result, _)) = process(ix).await else {
        return;
    };
    assert_eq!(result, instruction_error(InstructionError::InvalidArgument));
}

#[tokio::test]
async fn rejects_short_instruction_on_sbf() {
    let ix = Instruction {
        program_id: ID,
        accounts: vec![],
        data: vec![0; MESSAGE_OFFSET - 1],
    };

    let Some((result, _)) = process(ix).await else {
        return;
    };
    assert_eq!(
        result,
        instruction_error(InstructionError::InvalidInstructionData)
    );
}
