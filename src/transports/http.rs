use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::errors::Result;
use crate::transports::{BatchTransport, Transport};
use crate::types::{Call, MethodCall, Params, Request, RequestId, Response, Version};

#[derive(Clone)]
pub struct DigestAuthCredentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone)]
enum HttpCredentials {
    DigestAuthCredentials(DigestAuthCredentials),
    BearerAuthToken(String),
    None,
}

/// HTTP transport
#[derive(Clone)]
pub struct HttpTransport {
    id: Arc<AtomicUsize>,
    url: String,
    credentials: HttpCredentials,
    client: reqwest::Client,
}

impl HttpTransport {
    fn new_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .build()
            .expect("ClientBuilder config is valid; qed")
    }

    /// Create a new HTTP transport with given `url`.
    pub fn new<U: Into<String>>(url: U) -> Self {
        Self {
            id: Default::default(),
            url: url.into(),
            credentials: HttpCredentials::None,
            client: Self::new_client(),
        }
    }

    /// Create a new HTTP transport with given `url` and bearer `token`.
    pub fn new_with_bearer_auth<U: Into<String>, T: Into<String>>(url: U, token: T) -> Self {
        Self {
            id: Default::default(),
            url: url.into(),
            credentials: HttpCredentials::BearerAuthToken(token.into()),
            client: Self::new_client(),
        }
    }

    #[cfg(feature = "http-digest-auth")]
    /// Create a new HTTP transport with given `url` and bearer `token`.
    pub fn new_with_digest_auth<U: Into<String>, UN: Into<String>, P: Into<String>>(
        url: U,
        username: UN,
        password: P
    ) -> Self {
        Self {
            id: Default::default(),
            url: url.into(),
            credentials: HttpCredentials::DigestAuthCredentials(DigestAuthCredentials {
                username: username.into(),
                password: password.into(),
            }),
            client: Self::new_client(),
        }
    }

    // Create a new HTTP transport with the given `url` and digest authentication credentials
    // `DigestAuthCredentials`.

    async fn send_request(&self, request: &Request) -> Result<Response> {
        Ok(match &self.credentials {
            #[cfg(feature = "http-digest-auth")]
            HttpCredentials::DigestAuthCredentials(credentials) => {
                let encoded_request = serde_json::to_vec(request).unwrap();

                let auth_request_response = self.client.get(&self.url).send().await?;
                let mut challenge = match auth_request_response.headers().get("WWW-Authenticate") {
                    Some(challenge) => {
                        digest_auth::parse(challenge.to_str().expect("invalid challenge"))
                            .expect("invalid challenge")
                    }

                    None => panic!("server doesn't require digest authentication"),
                };

                let url_path = reqwest::Url::parse(&self.url).expect("bad url");
                let url_path = url_path.path();

                let auth_context = digest_auth::AuthContext::new_post(
                    &credentials.username,
                    &credentials.password,
                    url_path,
                    Some(&encoded_request)
                );

                let authorize_header = challenge.respond(&auth_context).unwrap().to_string();

                self.client
                    .post(&self.url)
                    .header("Authorization", authorize_header)
                    .body(encoded_request)
                    .send()
                    .await?
                    .json()
                    .await?
            }

            HttpCredentials::BearerAuthToken(token) => {
                self.client
                    .post(&self.url)
                    .bearer_auth(token)
                    .json(request)
                    .send()
                    .await?
                    .json()
                    .await?
            }

            HttpCredentials::None => {
                self.client
                    .post(&self.url)
                    .json(request)
                    .send()
                    .await?
                    .json()
                    .await?
            }
        })
    }
}

#[async_trait::async_trait]
impl Transport for HttpTransport {
    fn prepare<M: Into<String>>(&self, method: M, params: Params) -> (RequestId, Call) {
        let id = self.id.fetch_add(1, Ordering::AcqRel);
        let call = Call::MethodCall(MethodCall {
            jsonrpc: Some(Version::V2),
            id,
            method: method.into(),
            params,
        });
        (id, call)
    }

    async fn execute(&self, _id: RequestId, request: &Request) -> Result<Response> {
        self.send_request(request).await
    }
}

#[async_trait::async_trait]
impl BatchTransport for HttpTransport {}
