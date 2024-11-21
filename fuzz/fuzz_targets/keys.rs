#![no_main]

use libfuzzer_sys::fuzz_target;
use tari_crypto::ristretto::RistrettoSecretKey;
use tari_crypto::ristretto::RistrettoPublicKey;
use tari_crypto::tari_utilities::ByteArray;

fuzz_target!(|data: &[u8]| {

    if data.len() < 32 {
        return;
    }
    match RistrettoSecretKey::from_bytes(&data[0..32]) {
        Ok(r) => {
            // WIP: this should fail because we do a mod.
            // We should implement from_bytes_canonical
            //assert_eq!(&r.to_vec(), &data[0..32]);
        }
        Err(e) => {
            // This is unlikely to fail
            todo!()
        }
    }

    match RistrettoPublicKey::from_bytes(&data[0..32]) {
        Ok(r) => {
            assert_eq!(&r.to_vec(), &data[0..32]);
        }
        Err(e) => {
            // There are many ways this can fail
            // dbg!(&data[0..32]);
        }
    }
});
