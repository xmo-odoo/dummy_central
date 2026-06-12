use serde::Serialize;

use crate::users::{SimpleUser, UserType};

#[derive(Serialize, Debug)]
pub struct Installation {
    pub id: i64,
    pub account: SimpleUser,
    pub app_id: i64,
    pub target_id: i64,
    pub target_type: UserType,
    pub app_slug: String,
    // ...
}
