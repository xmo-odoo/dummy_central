#![doc = include_str!("../README.md")]

pub mod branches;
pub mod git;
pub mod issues;
pub mod orgs;
pub mod pulls;
pub mod repos;
pub mod users;
pub mod webhooks;

#[derive(serde::Serialize, Default)]
pub struct RateLimit {
    pub rate: Core,
    pub resources: Resource,
}
#[derive(serde::Serialize, Default)]
pub struct Resource {
    pub core: Core,
}
#[derive(serde::Serialize, Default)]
pub struct Core {}
