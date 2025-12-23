use async_trait::async_trait;
use blake2::digest::typenum;
use fastcrypto::{
    ed25519::{Ed25519PublicKey, Ed25519Signature},
    hash::{HashFunction, HashFunctionWrapper},
    traits::ToFromBytes,
};
use shared_crypto::intent::{Intent, IntentMessage};
use sui_types::crypto::{Signature, SignatureScheme, SuiKeyPair, SuiSignature};

use crate::generic_types::SuiAddress;
use crate::signer::Signer;

pub struct KeyPairContext {
    keypair: SuiKeyPair,
}

impl KeyPairContext {
    pub fn decode(value: &str) -> Self {
        Self {
            keypair: SuiKeyPair::decode(value).expect("invalid suiprivkey"),
        }
    }
}

#[async_trait]
impl Signer for KeyPairContext {
    type Error = anyhow::Error;

    async fn sign_personal_message(
        &mut self,
        message: Vec<u8>,
    ) -> anyhow::Result<Ed25519Signature> {
        let intent_msg = IntentMessage::new(Intent::personal_message(), &message);

        let signature = Signature::new_secure(&intent_msg, &self.keypair);

        let Signature::Ed25519SuiSignature(signature) = signature else {
            anyhow::bail!("IncorrectSignatureScheme");
        };

        Ok(Ed25519Signature::from_bytes(signature.signature_bytes())?)
    }

    fn get_public_key(&mut self) -> anyhow::Result<Ed25519PublicKey> {
        Ok(Ed25519PublicKey::from_bytes(
            self.keypair.public().as_ref(),
        )?)
    }

    fn get_sui_address(&mut self) -> anyhow::Result<SuiAddress> {
        let mut hasher: HashFunctionWrapper<blake2::Blake2b<typenum::U32>, 32> =
            HashFunctionWrapper::new();

        hasher.update([SignatureScheme::ED25519.flag()]);
        hasher.update(self.get_public_key()?);
        let g_arr = hasher.finalize();
        Ok(SuiAddress(g_arr.digest))
    }
}

#[cfg(test)]
mod test {

    use crate::{native_sui_sdk::signer::keypair_context::KeyPairContext, signer::Signer};

    #[tokio::test]
    async fn sign_personal_msg() {
        // fill the suiprivate_key
        let mut signer = KeyPairContext::decode("");

        let address = signer.get_sui_address().unwrap();

        let message = b"hello_kitty";
        let signature = signer
            .sign_personal_message(message.to_vec())
            .await
            .unwrap();

        assert_eq!(
            signature.to_string(),
            "PdP7zsMbe658qINgPt4EwN8qLA1+UJT4XepTK1gwSOQtQm8JeGYvBduDCc7y5kNwGcgf1uyU1B8D7q+MSV0eDQ=="
        );

        assert_eq!(
            address.to_string(),
            "0x6a74787182e12f920bc753f0bff20acf5897f878fcf63283cdc3f1e4982a4ce2"
        )
    }
}
