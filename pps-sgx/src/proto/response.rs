use std::fmt;
use std::time::Duration;

use anyhow::{bail, Context};
use tonic::metadata::MetadataValue;
use tonic::{Response, Status};

use super::hashable::Hashable;
use crate::crypto::{AttestationSignature, MockedEnclaveMasterKey, MockedEnclavePublicMasterKey};

pub trait SignResponse: Sized {
    type Error;
    fn sign(self, key: &MockedEnclaveMasterKey) -> Result<Self, Self::Error>;
}

impl<H> SignResponse for Response<H>
where
    H: Hashable,
{
    type Error = Status;

    fn sign(mut self, key: &MockedEnclaveMasterKey) -> Result<Self, Self::Error> {
        let signature = key
            .sign(self.get_ref())
            .map_err(|e| Status::internal(format!("sign response (local attestation): {}", e)))?;

        let signature = serde_json::to_string(&signature)
            .map_err(|e| Status::internal(format!("serialize signature: {}", e)))?;

        self.metadata_mut().insert(
            "attestation-signature",
            MetadataValue::from_str(&signature)
                .map_err(|e| Status::internal(format!("add attestation signature: {}", e)))?,
        );

        Ok(self)
    }
}

pub trait AttestResponse {
    type Error;
    fn attest(&self, key: &MockedEnclavePublicMasterKey) -> Result<(), Self::Error>;
}

impl<H> AttestResponse for Response<H>
where
    H: Hashable,
{
    type Error = anyhow::Error;

    fn attest(&self, key: &MockedEnclavePublicMasterKey) -> anyhow::Result<()> {
        let signature = self
            .metadata()
            .get("attestation-signature")
            .context("signature is missing")?
            .to_str()
            .context("signature isn't str")?;
        let signature: AttestationSignature =
            serde_json::from_str(signature).context("parse signature")?;
        let verified = key.verify(self.get_ref(), &signature);
        if !verified {
            bail!("signature doesn't match attestation key")
        }
        Ok(())
    }
}

pub trait SetMetricsResponse: Sized {
    type Error;
    fn set_took_time(self, took: Duration) -> Result<Self, Self::Error>;
}

impl<B> SetMetricsResponse for Response<B> {
    type Error = Status;

    fn set_took_time(mut self, took: Duration) -> Result<Self, Self::Error> {
        self.metadata_mut().insert(
            "took-time",
            MetadataValue::from_str(&format!("{:?}", took))
                .map_err(|e| Status::internal(format!("add `took-time` header: {}", e)))?,
        );

        Ok(self)
    }
}

pub trait GetMetricsResponse {
    type Error;
    fn get_took_time(&self) -> Result<TookTime, Self::Error>;
}

impl<B> GetMetricsResponse for Response<B> {
    type Error = anyhow::Error;

    fn get_took_time(&self) -> anyhow::Result<TookTime> {
        let took = self
            .metadata()
            .get("took-time")
            .map(|t| t.to_str())
            .transpose()
            .context("took-time isn't str")?;

        Ok(TookTime(took.map(|t| t.to_string())))
    }
}

pub struct TookTime(Option<String>);

impl fmt::Display for TookTime {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.0 {
            Some(t) => write!(f, "{}", t),
            None => write!(f, "unknown"),
        }
    }
}
