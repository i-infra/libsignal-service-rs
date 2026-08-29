//! Everything needed to support [Signal Groups v2](https://signal.org/blog/new-groups/)
mod credentials;
mod manager;
mod model;
mod operations;
pub mod utils;

pub use credentials::{
    create_credential_request_context, receive_credential,
    ProfileKeyCredentialCache, SignalServiceProfileWithCredential,
};
pub use manager::{
    decrypt_group, CredentialsCache, CredentialsCacheError, GroupsManager,
    InMemoryCredentialsCache,
};
pub use model::{
    AccessControl, AccessRequired, Group, GroupChange, GroupChanges,
    GroupMemberCandidate, Member, PendingMember, RequestingMember, Role, Timer,
};
pub use operations::{GroupDecodingError, GroupOperations};
