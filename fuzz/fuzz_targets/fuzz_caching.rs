#![no_main]

use std::time::{Duration, Instant};

use credential_provider_core::{
    mock::MockCredentialProvider, CachingCredentialProvider, CredentialError,
    CredentialProvider, SecretString, UsernamePassword,
};
use libfuzzer_sys::fuzz_target;

/// Fuzz the `CachingCredentialProvider::get()` state machine.
///
/// Input layout (10+ bytes):
///   [0..2]  refresh_before_expiry in seconds (u16, clamped to ≥1)
///   [2]     expiry_kind: 0=None, 1=expired, 2=inside_window, 3=outside_window, 4=at_boundary
///   [3..7]  auxiliary offset seconds (u32, capped at 1 day)
///   [7]     first inner response: 0=Ok, else=Err
///   [8]     second inner response: 0=Ok, else=Err
///   [9]     extra calls after assertions (0–3)
///
/// Invariants checked:
///   • Rule 1: empty cache + inner Err → Err(Unavailable), never inner variant
///   • Rule 5: expired cache + inner Err → inner variant propagated, never Unavailable
///   • No panic for any structurally valid input
fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }

    // Bytes 0–1: refresh_before_expiry in seconds (1–65535)
    let refresh_secs = u16::from_le_bytes([data[0], data[1]]).max(1) as u64;
    let refresh_window = Duration::from_secs(refresh_secs);

    // Byte 2: expiry kind for credentials returned by inner
    //   0 → no expiry (None)    — always valid, Rule 6
    //   1 → already expired     — is_valid() == false, Rule 4/5
    //   2 → inside refresh window (valid, near expiry) — Rule 3/4
    //   3 → outside refresh window (long-lived)        — Rule 2
    //   4 → at exact refresh boundary                  — triggers refresh (E-CACHE-2)
    let expiry_kind = data[2] % 5;

    // Bytes 3–6: auxiliary offset seconds
    let aux = u32::from_le_bytes([data[3], data[4], data[5], data[6]]) as u64;
    let aux = aux.min(86_400); // cap at one day to avoid Instant overflow

    let expires_at: Option<Instant> = match expiry_kind {
        0 => None,
        1 => Some(Instant::now() - Duration::from_secs(1 + aux.min(3_600))),
        2 => {
            // Inside window: remaining < refresh_window so refresh triggers
            let remaining = refresh_secs.saturating_sub(1).max(1);
            Some(Instant::now() + Duration::from_secs(remaining))
        }
        3 => Some(Instant::now() + Duration::from_secs(refresh_secs + aux + 1)),
        4 => Some(Instant::now() + refresh_window), // at boundary → ≤ check triggers
        _ => unreachable!(),
    };

    // Byte 7: first inner response (0 = Ok, else = Err)
    let first_ok = data[7] == 0;
    // Byte 8: second inner response (0 = Ok, else = Err)
    let second_ok = data[8] == 0;
    // Byte 9: additional calls after assertions (0–3)
    let extra_calls = (data[9] % 4) as usize;

    let make_cred = |label: &'static str| -> UsernamePassword {
        UsernamePassword::new(label, SecretString::new("x".to_string()), expires_at)
    };

    let responses: Vec<Result<UsernamePassword, CredentialError>> = vec![
        if first_ok {
            Ok(make_cred("c1"))
        } else {
            Err(CredentialError::Backend("e1".into()))
        },
        if second_ok {
            Ok(make_cred("c2"))
        } else {
            Err(CredentialError::Backend("e2".into()))
        },
        Ok(make_cred("c3")), // fallback so extra calls never exhaust the sequence
    ];

    let mock = MockCredentialProvider::from_sequence(responses);
    let provider = CachingCredentialProvider::new(mock, refresh_window);

    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("tokio rt must build");

    // ── First call: cache is always empty ────────────────────────────────────

    let first = rt.block_on(provider.get());

    if !first_ok {
        // Rule 1: empty cache + inner error → Unavailable (not the inner variant).
        assert!(
            matches!(first, Err(CredentialError::Unavailable)),
            "empty-cache + inner error must yield Unavailable, got {:?}",
            first,
        );
        return;
    }

    assert!(
        first.is_ok(),
        "inner Ok on empty cache must succeed; got {:?}",
        first,
    );

    // ── Second call: exercises Rules 2–5 depending on expiry_kind ────────────

    let second = rt.block_on(provider.get());

    // Rule 5 invariant: expired credential + inner error must propagate the inner
    // error variant, NOT wrap it in Unavailable (which is only for empty-cache).
    if expiry_kind == 1 && !second_ok {
        if let Err(ref e) = second {
            assert!(
                !matches!(e, CredentialError::Unavailable),
                "expired-cache + inner error must propagate inner error (Rule 5), \
                 not Unavailable; got {:?}",
                second,
            );
        }
    }

    // ── Extra calls: verify the state machine does not panic ─────────────────
    for _ in 0..extra_calls {
        let _ = rt.block_on(provider.get());
    }
});
