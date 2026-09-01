use thiserror::Error;

#[derive(Debug, Error)]
pub enum HarnessError {
    #[error("fault injector {0} failed to arm: {1}")]
    ArmFailed(String, String),

    #[error("fault injector {0} failed to disarm: {1}")]
    DisarmFailed(String, String),

    #[error("adapter {0} rejected message: {1}")]
    AdapterRejected(String, String),

    #[error("scenario config invalid: {0}")]
    InvalidScenario(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
