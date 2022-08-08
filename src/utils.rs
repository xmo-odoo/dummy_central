use std::convert::Infallible;
use warp::*;

pub fn data<T: Clone + Send>(
    t: T,
) -> impl Filter<Extract = (T,), Error = Infallible> + Clone {
    any().map(move || t.clone())
}
