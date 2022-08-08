use serde::Serialize;

#[derive(Serialize)]
pub struct BranchWithProtection {
    pub name: String,
    // pub protected: bool,
    // pub protection: Protection,
    // pub protection_url: String,
    // is this the protection pattern?
    // #[serde(skip_serializing_for = "Option::is_none")]
    // pub pattern: Option<String>
    // pub required_approving_review_count: usize,
    pub commit: crate::repos::CommitsResponse,
}
