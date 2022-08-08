use async_graphql::{
    Context, EmptySubscription, Error, InputObject, Object, Schema,
    SimpleObject,
    connection::{Connection, Edge},
};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::{Extension, Router, extract::State, routing::post};
use github_types::webhooks;

use super::{Authorization, Pid, St, repos};
use crate::model::{
    Read, Token, Write,
    prs::{IssueId, PullRequest, PullRequestId},
    repos::RepositoryId,
    users::{User, find_current_user},
};

pub fn routes() -> Router<St> {
    Router::new()
        .route("/graphql", post(graphql))
        .layer(Extension(
            Schema::build(QueryRoot, MutationRoot, EmptySubscription).finish(),
        ))
}

async fn graphql(
    auth: Authorization,
    State(st): State<St>,
    Extension(schema): Extension<
        Schema<QueryRoot, MutationRoot, EmptySubscription>,
    >,
    request: GraphQLRequest,
) -> GraphQLResponse {
    schema
        .execute(request.into_inner().data(st).data(auth))
        .await
        .into()
}

struct QueryRoot;
#[Object]
impl QueryRoot {
    async fn repository(
        &self,
        // ctx: &Context<'_>,
        owner: String,
        name: String,
    ) -> Result<RepositoryId, Error> {
        let tx = Token::<Read>::get().await.unwrap();
        crate::model::repos::id_by_name(&tx, &owner, &name)
            .ok_or_else(|| Error::new("repository does not exist"))
    }
}
#[Object]
impl RepositoryId {
    async fn pull_request(
        &self,
        // ctx: &Context<'_>,
        number: usize,
    ) -> Result<PullRequestId, Error> {
        let tx = Token::<Read>::get().await.unwrap();

        crate::model::prs::find_by_number(&tx, *self, number)
            .ok_or_else(|| Error::new("PR not found"))
    }
    async fn name_with_owner(&self) -> String {
        let tx = Token::<Read>::get().await.unwrap();

        let repo = crate::model::repos::by_id(&tx, *self);
        format!("{}/{}", repo.owner.login, repo.name)
    }
}
#[Object]
impl PullRequestId {
    async fn closing_issues_references(
        &self,
        // ctx: &Context<'_>,
        // after: Option<String>,
        // before: Option<String>,
        // first: Option<usize>,
        #[graphql(name = "last")] _last: Option<usize>,
        // order_by: Option<IssueOrder>,
        // user_linked_only: bool,
    ) -> Connection<String, IssueId> {
        let tx = Token::<Read>::get().await.unwrap();

        // FIXME: use `connection::query` so it does the parsing of before/after to Cursor
        //        (requires a proper cursor type)
        let mut c = Connection::new(false, false);
        c.edges.extend(
            crate::model::prs::referenced(&tx, *self)
                .into_iter()
                // FIXME: proper cursor values
                .map(|id| Edge::new(String::new(), id)),
        );
        c
    }
}
#[Object]
impl IssueId {
    // TODO: closedByPullRequestsReferences?
    async fn number(&self) -> usize {
        let tx = Token::<Read>::get().await.unwrap();

        crate::model::prs::get_issue(&tx, *self).number
    }
    async fn repository(&self) -> RepositoryId {
        let tx = Token::<Read>::get().await.unwrap();

        crate::model::prs::get_issue(&tx, *self).repository.id
    }
}

struct MutationRoot;
#[Object]
impl MutationRoot {
    async fn mark_pull_request_ready_for_review(
        &self,
        ctx: &Context<'_>,
        input: MarkPullRequestReadyForReviewInput,
    ) -> Result<MutationData, Error> {
        let MarkPullRequestReadyForReviewInput {
            client_mutation_id,
            pull_request_id,
        } = input;
        let st = ctx.data_unchecked::<St>();
        let tx = Token::<Write>::get().await.unwrap();

        let Authorization(_, auth) = ctx.data_unchecked::<Authorization>();
        let Some(user) = find_current_user(&tx, auth) else {
            return Err(Error::new("Unknown user"));
        };

        let pr = get_pr(&tx, &user, &pull_request_id)?;
        if crate::model::prs::set_draft(&tx, pr.id, false) {
            repos::send_hook(
                &tx,
                pr.issue.repository,
                st,
                github_types::repos::HookEvent::PullRequest,
                &user,
                || {
                    webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                        action: webhooks::PullRequestAction::ReadyForReview,
                        number: pr.issue.number,
                        pull_request: repos::issues::pr_response(
                            &tx, st, pr.id,
                        ),
                    })
                },
            );
            tx.commit();
            Ok(MutationData { client_mutation_id })
        } else {
            Err(Error::new("unable to undraft"))
        }
    }
    async fn convert_pull_request_to_draft(
        &self,
        ctx: &Context<'_>,
        input: ConvertPullRequestToDraftInput,
    ) -> Result<MutationData, Error> {
        let ConvertPullRequestToDraftInput {
            client_mutation_id,
            pull_request_id,
        } = input;
        let st = ctx.data_unchecked::<St>();
        let tx = Token::<Write>::get().await.unwrap();

        let Authorization(_, auth) = ctx.data_unchecked::<Authorization>();
        let Some(user) = find_current_user(&tx, auth) else {
            return Err(Error::new("Unknown user"));
        };

        let pr = get_pr(&tx, &user, &pull_request_id)?;
        if crate::model::prs::set_draft(&tx, pr.id, true) {
            repos::send_hook(
                &tx,
                pr.issue.repository,
                st,
                github_types::repos::HookEvent::PullRequest,
                &user,
                || {
                    webhooks::WebhookEvent::PullRequest(webhooks::PullRequest {
                        action: webhooks::PullRequestAction::ConvertedToDraft,
                        number: pr.issue.number,
                        pull_request: repos::issues::pr_response(
                            &tx, st, pr.id,
                        ),
                    })
                },
            );
            tx.commit();
            Ok(MutationData { client_mutation_id })
        } else {
            Err(Error::new("unable to draftify"))
        }
    }
}
fn get_pr(
    tx: &Token<Write>,
    user: &User<'static>,
    pull_request_id: &str,
) -> Result<PullRequest, Error> {
    let pid: Pid = serde_json::from_str(pull_request_id)
        .map_err(|_| Error::new("unable to resolve pull request id"))?;
    let pr = crate::model::prs::find_by_id(tx, pid.0)
        .ok_or_else(|| Error::new("PR not found"))?;
    if !crate::model::prs::can_write(tx, user.id, pr.id) {
        return Err(Error::new("No write access"));
    }
    Ok(pr)
}

#[derive(InputObject)]
struct DraftMutationInput {
    client_mutation_id: Option<String>,
    pull_request_id: String,
}
type ConvertPullRequestToDraftInput = DraftMutationInput;
type MarkPullRequestReadyForReviewInput = DraftMutationInput;
#[derive(SimpleObject)]
struct MutationData {
    client_mutation_id: Option<String>,
}
