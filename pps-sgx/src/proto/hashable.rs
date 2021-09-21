use sha2::digest::{Digest, Output};

use super::pps;

pub trait Hashable {
    fn hash<D: Digest>(&self) -> Output<D>;
}

impl Hashable for pps::SetupResponse {
    fn hash<D: Digest>(&self) -> Output<D> {
        D::new().chain(&self.public_key).finalize()
    }
}

impl Hashable for pps::ReceiveResponse {
    fn hash<D: Digest>(&self) -> Output<D> {
        let mut d = D::new();
        for item in &self.encrypted_row {
            d.update(&item)
        }
        d.finalize()
    }
}
