use axum::{
    Json, Router,
    extract::{Path, State},
    routing::{delete, get, put},
};
use github_types::repos::{
    Collaborator, CreateRepositoryRuleset, RepositoryInvitation,
    RuleSetConditionsRefName, RulesetConditions, RulesetLinks, RulesetResponse,
    RulesetResponseShort, RulesetRuleResponse,
};
use http::StatusCode;
use serde::Serialize;
use tracing::instrument;

use crate::{
    github::{Error, GHError, St},
    model::{Read, Token, Write, repos::Ruleset},
};

#[rustfmt::skip]
pub fn routes() -> Router<St> {
    Router::new()
        .route("/collaborators", get(list_collaborators))
        .route("/collaborators/{login}", put(add_collaborator).delete(delete_collaborator))
        .route("/collaborators/{login}/permission", get(get_collaborator_permission))
        .route("/rulesets", get(list_rulesets).post(create_ruleset))
        .route("/rulesets/{ruleset_id}", /*get(get_ruleset).put(update_ruleset).*/delete(delete_ruleset))
        .route("/rules/branches/{branch}", get(list_branch_rules))
}

#[instrument(skip(tx))]
async fn list_collaborators(
    State(_): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<Collaborator>>, GHError<'static>> {
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        // FIXME: correct error?
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "list-collaborators",
        ));
    };
    Ok(Json(
        crate::model::repos::get_collaborators(&tx, repo_id)
            .into_iter()
            .map(|(uid, _)| Collaborator {
                login: crate::model::users::get_by_id(&tx, uid)
                    .login
                    .to_string(),
            })
            .collect(),
    ))
}

/// Invitation from from a UI perspective:
/// - when inviting to a personal repo, no role can be selected
/// - invitation is visible next to collaborators
/// - if invitation is rejected, it is removed from the list
/// - otherwise it's converted from pending invitation" to "collaborator"
/// - when inviting to an org repo, role selection is added
///   - role can be changed in list after invitation has been created (whether
///     accepted or not)
/// - invitations expire after 7 days (since 2020), in UI they remain present in
///   the list, but flagged as expired (and the invitation link doesn't work
///   anymore)
///
/// TODO:
/// - permission levels -- doc says only valid for organization-owned repository?
///   is it specific perms or explicit perms and individual repo is always push?
///
///   permissions are abnormal,
///
///   > pull, triage, push, maintain, admin and you can also specify a custom
///     repository role name
///
///   Passed as body content `{permission: ...}`.
/// - if inviting an org member and org has base role, permission must be higher
///   than base role otherwise request will fail
/// - can update an existing collaborator's permission level, just call endpoint
///   with new permission, response is 204
/// - rate limit of 50 invitations / repository / 24h, unless inviting org
///   member to org repo
///
/// Returns:
/// - 201 (created) when a new invitation is created
/// - 204 (no content) when an existing collaborator is re-added, an org member
///   is added as a collaborator, or an existing team member (whose team is a
///   collaborator) is added
/// - 403 (forbidden) ???
/// - 422 (validation failed) ???
#[instrument(skip(tx))]
async fn add_collaborator(
    State(_): State<St>,
    tx: Token<Write>,
    Path((owner, name, new_collaborator)): Path<(String, String, String)>,
) -> Result<(StatusCode, Json<RepositoryInvitation>), GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "add-a-repository-collaborator",
        ));
    };
    if new_collaborator == repo.owner.login {
        static DEETS: &[crate::github::GithubErrorDetails<'_>] =
            &[Error::details(
                "Repository",
                "",
                "custom",
                "Repository owner cannot be a collaborator",
            )];
        return Err(Error::unprocessable("Validation Failed", DEETS)
            .into_response(
                "reference",
                "repos",
                "add-a-repository-collaborator",
            ));
    }
    if !crate::model::repos::add_collaborator(&tx, repo.id, new_collaborator) {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "add-a-repository-collaborator",
        ));
    };
    tx.commit();

    // 204 when:
    // - an existing collaborator is added as a collaborator
    // - an organization member is added as an individual collaborator
    // - an existing team member (whose team is also a repository collaborator)
    //   is added as an individual collaborator
    Ok((StatusCode::CREATED, Json(RepositoryInvitation { id: 1 })))
}

#[instrument(skip(tx))]
async fn delete_collaborator(
    State(_): State<St>,
    tx: Token<Write>,
    Path((owner, name, collaborator)): Path<(String, String, String)>,
) -> Result<StatusCode, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "delete-a-repository-collaborator",
        ));
    };
    if collaborator == repo.owner.login {
        static DEETS: &[crate::github::GithubErrorDetails<'_>] =
            &[Error::details(
                "Repository",
                "",
                "custom",
                "Repository owner cannot be uncollaborated",
            )];
        return Err(Error::unprocessable("Validation Failed", DEETS)
            .into_response(
                "reference",
                "repos",
                "delete-a-repository-collaborator",
            ));
    }
    if !crate::model::repos::remove_collaborator(&tx, repo.id, &collaborator) {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "delete-a-repository-collaborator",
        ));
    };
    tx.commit();
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum LegacyRole {
    Admin,
    Write,
    Read,
    None,
}
#[derive(Serialize, Debug)]
#[serde(rename_all = "snake_case")]
enum RoleName {
    Admin,
    Maintain,
    Write,
    Triage,
    Read,
    None,
}

#[derive(Serialize, Debug)]
struct Permission {
    permission: LegacyRole,
    role_name: RoleName,
    user: github_types::users::SimpleUser,
}

/// https://docs.github.com/en/rest/collaborators/collaborators#get-repository-permissions-for-a-user
#[instrument(skip(st, tx))]
async fn get_collaborator_permission(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name, login)): Path<(String, String, String)>,
) -> Result<Json<Permission>, GHError<'static>> {
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "get-repository-collaborator-permission",
        ));
    };
    let Some(user) = crate::model::users::get_user(&tx, &login) else {
        return Err(Error::NOT_FOUND.into_response(
            "collaborators",
            "collaborators",
            "get-repository-collaborator-permission",
        ));
    };
    Ok(Json(
        crate::model::repos::get_collaborators(&tx, repo_id)
            .into_iter()
            .find_map(|(uid, role)| {
                (uid == user.id).then(|| {
                    use crate::model::repos::Role;
                    let (permission, role_name) = match role {
                        Role::Administrate => {
                            (LegacyRole::Admin, RoleName::Admin)
                        }
                        Role::Maintain => {
                            (LegacyRole::Write, RoleName::Maintain)
                        }
                        Role::Write => (LegacyRole::Write, RoleName::Write),
                        Role::Triage => (LegacyRole::Read, RoleName::Triage),
                        Role::Read => (LegacyRole::Read, RoleName::Read),
                    };
                    Permission {
                        permission,
                        role_name,
                        user: github_types::users::SimpleUser::for_login(
                            &st.root,
                            (&login).into(),
                        ),
                    }
                })
            })
            .unwrap_or_else(|| Permission {
                permission: LegacyRole::Read,
                role_name: RoleName::Read,
                user: github_types::users::SimpleUser::for_login(
                    &st.root,
                    login.into(),
                ),
            }),
    ))
}

fn ruleset_response_short(
    root: &str,
    owner: &str,
    name: &str,
    Ruleset {
        id,
        created_at,
        updated_at,
        name: ruleset_name,
        enforcement,
        target,
        ..
    }: Ruleset,
) -> RulesetResponseShort {
    RulesetResponseShort {
        id: *id,
        created_at,
        updated_at,
        name: ruleset_name,
        enforcement,
        target,
        links: RulesetLinks {
            self_: github_types::Link {
                href: format!("{}/repos/{owner}/{name}/rulesets/{}", root, *id),
            },
            html: github_types::Link {
                href: format!("{}/{owner}/{name}/rules/{}", root, *id),
            },
        },
        node_id: String::new(),
        source_type: github_types::repos::RulesetSourceType::Repository,
        source: format!("{owner}/{name}"),
    }
}

#[instrument(skip(st, tx))]
async fn create_ruleset(
    State(st): State<St>,
    tx: Token<Write>,
    Path((owner, name)): Path<(String, String)>,
    Json(ruleset): Json<CreateRepositoryRuleset>,
) -> Result<Json<RulesetResponse>, GHError<'static>> {
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "repos",
            "rules",
            "create-a-repository-ruleset",
        ));
    };

    if let Some(pattern) = ruleset
        .conditions
        .ref_name
        .include
        .iter()
        .chain(ruleset.conditions.ref_name.exclude.iter())
        .find_map(|pattern| match pattern.as_str() {
            "~ALL" => None,
            "~DEFAULT_BRANCH" => None,
            p if p.starts_with("refs/heads/")
                || p.starts_with("refs/tags/") =>
            {
                None
            }
            p => Some(p),
        })
    {
        return Err(Error::UnprocessableValue(
            "Validation Failed".into(),
            serde_json::Value::Array(vec![
                format!("Invalid target patterns: '{pattern}'").into(),
            ]),
        )
        .into_response("repos", "rules", "create-a-repository-ruleset"));
    }

    // TODO: actor stuff
    let ruleset = crate::model::repos::create_ruleset(&tx, repo_id, ruleset)
        .map(|id| crate::model::repos::read_ruleset(&tx, id))
        .map_err(|_| {
            const DETAILS: &[crate::github::GithubErrorDetails<'_>] =
                &[Error::details(
                    "Repository",
                    "",
                    "custom",
                    "Failed to create ruleset",
                )];
            Error::unprocessable("Validation Failed", DETAILS).into_response(
                "repos",
                "rules",
                "create-a-repository-ruleset",
            )
        })?;
    let (include, exclude) =
        crate::model::repos::read_ruleset_conditions(&tx, ruleset.id);
    let rules = crate::model::repos::read_ruleset_rules(&tx, ruleset.id);
    tx.commit();

    Ok(Json(RulesetResponse {
        _short: ruleset_response_short(&st.root, &owner, &name, ruleset),
        bypass_actors: vec![],
        conditions: RulesetConditions {
            ref_name: RuleSetConditionsRefName { include, exclude },
        },
        rules,
    }))
}

#[instrument(skip(st, tx))]
async fn list_rulesets(
    State(st): State<St>,
    tx: Token<Read>,
    Path((owner, name)): Path<(String, String)>,
) -> Result<Json<Vec<RulesetResponseShort>>, GHError<'static>> {
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "rulesets",
            "rulesets",
            "list-repository-rulesets",
        ));
    };
    let rulesets = crate::model::repos::read_rulesets(&tx, repo_id);
    Ok(Json(
        rulesets
            .into_iter()
            .map(|r| ruleset_response_short(&st.root, &owner, &name, r))
            .collect(),
    ))
}

#[instrument(skip(tx))]
async fn delete_ruleset(
    State(_): State<St>,
    tx: Token<Write>,
    Path((owner, name, ruleset_id)): Path<(String, String, i64)>,
) -> Result<StatusCode, GHError<'static>> {
    let Some(repo_id) = crate::model::repos::id_by_name(&tx, &owner, &name)
    else {
        return Err(Error::NOT_FOUND.into_response(
            "rulesets",
            "rulesets",
            "delete-repository-ruleset",
        ));
    };
    if !crate::model::repos::delete_ruleset(&tx, repo_id, ruleset_id) {
        return Err(Error::NOT_FOUND.into_response(
            "rulesets",
            "rulesets",
            "delete-repository-ruleset",
        ));
    };
    tx.commit();
    Ok(StatusCode::NO_CONTENT)
}

#[instrument(skip(tx))]
async fn list_branch_rules(
    State(_): State<St>,
    tx: Token<Read>,
    Path((owner, name, branch)): Path<(String, String, String)>,
) -> Result<Json<Vec<RulesetRuleResponse>>, GHError<'static>> {
    let Some(repo) = crate::model::repos::by_name(&tx, &owner, &name) else {
        return Err(Error::NOT_FOUND.into_response(
            "rulesets",
            "rulesets",
            "list-branch-rules",
        ));
    };

    let ruleset_source = format!("{owner}/{name}");
    Ok(Json(
        crate::model::repos::rulesets_for_branch(&tx, &repo, &branch)
            .flat_map(|ruleset| {
                let ruleset_id = ruleset.id;
                let ruleset_source = ruleset_source.clone();
                crate::model::repos::read_ruleset_rules(&tx, ruleset_id)
                    .into_iter()
                    .map(move |rule| RulesetRuleResponse {
                        ruleset_id: *ruleset_id,
                        ruleset_source_type:
                            github_types::repos::RulesetSourceType::Repository,
                        ruleset_source: ruleset_source.clone(),
                        rule,
                    })
            })
            .collect(),
    ))
}
