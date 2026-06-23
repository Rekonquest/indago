//! # Indago Credential Store
//!
//! A per-case API-key vault, **encrypted at rest** with ChaCha20-Poly1305. It
//! answers [`IndagoMessage::GetCredential`] with a correlated
//! [`IndagoMessage::CredentialResult`], and stores secrets via
//! [`IndagoMessage::SetCredential`]. Secrets are never logged (names only).
//!
//! Lookup falls back from the requested case to the **nil case** (global), so a
//! key set once globally serves every case until a case-specific one overrides.
//! Keys can be seeded from the environment at startup (e.g. `INDAGO_HIBP_KEY`).
//!
//! Layout under the data root: `credentials/master.key` (32-byte AEAD key) and
//! `credentials/vault.json` (nonce + ciphertext per secret).

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use indago_bus::Bus;
use indago_protocol::{BusEnvelope, IndagoMessage};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast::error::RecvError;
use tracing::{error, info, warn};
use uuid::Uuid;

#[derive(Serialize, Deserialize, Clone)]
struct Record {
    case_id: String,
    name: String,
    nonce: String,
    ciphertext: String,
}

/// The encrypted vault. Holds the AEAD cipher, the on-disk path, and the
/// decrypted-on-demand records.
pub struct Vault {
    cipher: ChaCha20Poly1305,
    path: PathBuf,
    records: Vec<Record>,
}

impl Vault {
    /// Open (or create) the vault under `root/credentials`.
    pub fn open(root: impl AsRef<Path>) -> anyhow::Result<Self> {
        let dir = root.as_ref().join("credentials");
        fs::create_dir_all(&dir)?;
        let key = load_or_create_master(&dir)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|e| anyhow::anyhow!("credential cipher init: {e}"))?;
        let path = dir.join("vault.json");
        let records = if path.exists() {
            serde_json::from_str(&fs::read_to_string(&path)?)?
        } else {
            Vec::new()
        };
        Ok(Self {
            cipher,
            path,
            records,
        })
    }

    /// Store (or replace) a secret for `(case_id, name)`.
    pub fn set(&mut self, case_id: &str, name: &str, secret: &str) -> anyhow::Result<()> {
        let (nonce, ciphertext) = self.encrypt(secret)?;
        self.records
            .retain(|r| !(r.case_id == case_id && r.name == name));
        self.records.push(Record {
            case_id: case_id.to_string(),
            name: name.to_string(),
            nonce,
            ciphertext,
        });
        fs::write(&self.path, serde_json::to_string_pretty(&self.records)?)?;
        Ok(())
    }

    /// Fetch a secret for `(case_id, name)`, falling back to the nil (global)
    /// case. Returns `None` if absent or undecryptable.
    pub fn get(&self, case_id: &str, name: &str) -> Option<String> {
        let nil = Uuid::nil().to_string();
        let rec = self
            .records
            .iter()
            .find(|r| r.case_id == case_id && r.name == name)
            .or_else(|| self.records.iter().find(|r| r.case_id == nil && r.name == name))?;
        self.decrypt(&rec.nonce, &rec.ciphertext).ok()
    }

    fn encrypt(&self, plaintext: &str) -> anyhow::Result<(String, String)> {
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        let ct = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
            .map_err(|e| anyhow::anyhow!("encrypt: {e}"))?;
        Ok((hex(&nonce), hex(&ct)))
    }

    fn decrypt(&self, nonce_hex: &str, ct_hex: &str) -> anyhow::Result<String> {
        let nonce = hex_to_vec(nonce_hex)?;
        if nonce.len() != 12 {
            anyhow::bail!("bad nonce length");
        }
        let ct = hex_to_vec(ct_hex)?;
        let pt = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
            .map_err(|e| anyhow::anyhow!("decrypt: {e}"))?;
        Ok(String::from_utf8(pt)?)
    }
}

/// Start the credential-store subsystem, seeding well-known keys from the env.
pub fn start(bus: Bus, root: impl AsRef<Path>) -> anyhow::Result<()> {
    let mut vault = Vault::open(root)?;

    // Seed global credentials from the environment.
    for (env_var, name) in [("INDAGO_HIBP_KEY", "hibp"), ("INDAGO_SHODAN_KEY", "shodan")] {
        if let Ok(value) = std::env::var(env_var) {
            if !value.is_empty() {
                if let Err(e) = vault.set(&Uuid::nil().to_string(), name, &value) {
                    error!(error = %e, "credential-store: env seed failed");
                } else {
                    info!(%name, "credential-store: seeded credential from env");
                }
            }
        }
    }

    let mut rx = bus.subscribe();
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(IndagoMessage::SetCredential {
                    case_id,
                    name,
                    secret,
                    ..
                }) => {
                    if let Err(e) = vault.set(&case_id.to_string(), &name, &secret) {
                        error!(error = %e, "credential-store: set failed");
                    } else {
                        info!(%name, "credential-store: stored credential");
                    }
                }
                Ok(IndagoMessage::GetCredential {
                    request_id,
                    case_id,
                    name,
                    ..
                }) => {
                    let secret = vault.get(&case_id.to_string(), &name);
                    bus.send(IndagoMessage::CredentialResult {
                        request_id,
                        name,
                        secret,
                        envelope: BusEnvelope::fresh(),
                    });
                }
                Ok(_) => {}
                Err(RecvError::Lagged(n)) => warn!(skipped = n, "credential-store fell behind"),
                Err(RecvError::Closed) => break,
            }
        }
    });
    info!("credential-store: encrypted vault started");
    Ok(())
}

fn load_or_create_master(dir: &Path) -> anyhow::Result<[u8; 32]> {
    let key_path = dir.join("master.key");
    if key_path.exists() {
        fs::read(&key_path)?
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("credential-store: corrupt master key"))
    } else {
        let mut key = [0u8; 32];
        getrandom::getrandom(&mut key).map_err(|e| anyhow::anyhow!("getrandom: {e}"))?;
        fs::write(&key_path, key)?;
        Ok(key)
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{:02x}", b);
    }
    s
}

fn hex_to_vec(s: &str) -> anyhow::Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("odd hex length");
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow::anyhow!("hex: {e}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!("indago-cred-test-{}", Uuid::new_v4()))
    }

    #[test]
    fn set_get_roundtrip_and_nil_fallback() {
        let root = temp_root();
        let case = Uuid::new_v4().to_string();
        let nil = Uuid::nil().to_string();
        {
            let mut v = Vault::open(&root).unwrap();
            v.set(&nil, "hibp", "GLOBAL-KEY").unwrap();
            v.set(&case, "hibp", "CASE-KEY").unwrap();
            // case-specific wins
            assert_eq!(v.get(&case, "hibp").as_deref(), Some("CASE-KEY"));
            // unknown case falls back to global
            assert_eq!(
                v.get(&Uuid::new_v4().to_string(), "hibp").as_deref(),
                Some("GLOBAL-KEY")
            );
            // missing name
            assert_eq!(v.get(&case, "nope"), None);
        }
        // Persisted across reopen, still decryptable.
        let v = Vault::open(&root).unwrap();
        assert_eq!(v.get(&case, "hibp").as_deref(), Some("CASE-KEY"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ciphertext_is_not_plaintext() {
        let root = temp_root();
        let mut v = Vault::open(&root).unwrap();
        v.set(&Uuid::nil().to_string(), "k", "super-secret-value").unwrap();
        let on_disk = fs::read_to_string(root.join("credentials").join("vault.json")).unwrap();
        assert!(!on_disk.contains("super-secret-value"));
        let _ = fs::remove_dir_all(&root);
    }
}
