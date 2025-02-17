use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use mirror_error::MirrorError;
use reqwest::StatusCode;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::str;
use urlencoding::encode;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    pub token: Option<String>,
    #[serde(rename = "access_token")]
    pub access_token: Option<String>,
    #[serde(rename = "expires_in")]
    pub expires_in: Option<i64>,
    #[serde(rename = "issued_at")]
    pub issued_at: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub auths: HashMap<String, Provider>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Provider {
    pub auth: String,
    pub email: Option<String>,
}

#[derive(Clone)]
pub struct ImplTokenInterface {}

#[async_trait]
pub trait TokenInterface {
    async fn get_credentials(&self, file: Option<String>) -> Result<String, MirrorError>;
    async fn get_auth_json(&self, url: String, auth: String) -> Result<String, MirrorError>;
    // this allows us to inject file read errors for testing
    async fn read_file<P: AsRef<Path> + Send>(&self, file: P) -> Result<String, MirrorError>;
}

#[async_trait]
impl TokenInterface for ImplTokenInterface {
    // read the credentials from set path (see podman credential reference)
    async fn get_credentials(&self, file: Option<String>) -> Result<String, MirrorError> {
        let mut auth_file_chain = file
            .map(PathBuf::from)
            .into_iter()
            // podman overriden default path
            .chain(env::var_os("REGISTRY_AUTH_FILE").map(PathBuf::from))
            // podman credential default path
            .chain(
                env::var_os("XDG_RUNTIME_DIR")
                    .map(|s| PathBuf::from(s).join("containers/auth.json")),
            )
            // docker credential default path
            .chain(env::var_os("HOME").map(|s| PathBuf::from(s).join(".docker/config.json")));
        if let Some(f) = auth_file_chain.find(|f| f.exists()) {
            log::debug!("loading credentials from {}", f.display());
            self.read_file(&f).await
        } else {
            Err(MirrorError::new("[get_credentials] could not locate creds"))
        }
    }

    /// async api call with basic auth
    async fn get_auth_json(&self, url: String, auth: String) -> Result<String, MirrorError> {
        let client = reqwest::Client::new();
        let res = client
            .get(&url)
            .header("Authorization", format!("Basic {}", auth))
            .header("User-Agent", "rust-mirror-auth")
            .send()
            .await
            .map_err(|e| MirrorError::new(format!("[get_auth_json] api call {} {}", url, e)))?;

        if res.status() != StatusCode::OK {
            return Err(MirrorError::new(format!(
                "[get_auth_json] api call {} {}",
                url,
                res.status()
            )));
        }
        res.text().await.map_err(|e| {
            MirrorError::new(format!(
                "[get_auth_json] reading body {}",
                e.to_string().to_lowercase()
            ))
        })
    }

    async fn read_file<P: AsRef<Path> + Send>(&self, file: P) -> Result<String, MirrorError> {
        fs::read_to_string(file)
            .map_err(|e| MirrorError::new(format!("[read_file] {}", e.to_string().to_lowercase())))
    }
}

/// process all relative functions in this module to actually get the token
pub async fn get_token<T: TokenInterface>(
    t_impl: T,
    name: String,
    namespace: String,
    enabled: bool,
) -> Result<String, MirrorError> {
    if !enabled {
        return Ok("".to_string());
    }
    // get creds from $XDG_RUNTIME_DIR
    let creds = t_impl.get_credentials(None).await?;
    // parse the json data
    let auth = parse_json_creds(creds.clone(), name.clone())?;
    // decode to base64
    let res_bytes = general_purpose::STANDARD.decode(&auth).map_err(|e| {
        MirrorError::new(format!(
            "[get_token] base64 decode {}",
            e.to_string().to_lowercase()
        ))
    })?;
    let s = str::from_utf8(&res_bytes).map_err(|e| {
        MirrorError::new(format!(
            "[get_token] get auth json {}",
            e.to_string().to_lowercase()
        ))
    })?;

    // get user from json
    let (user, _) = s.split_once(':').unwrap();
    let token_url = match name.as_str() {
                "registry.redhat.io" => format!(
                "https://sso.redhat.com/auth/realms/rhcc/protocol/redhat-docker-v2/auth?service=docker-registry&client_id=curl&scope={}",encode("repository:rhel:pull")
                ),
                "quay.io" => {
                    format!("https://quay.io/v2/auth?account={}&service={}&scope={}",
                        encode(user),
                        "quay%2Eio",
                        encode("repository:openshift-release-dev/ocp-v4.0-art-dev:pull"))
                }
                "registry.ci.openshift.org" => {
                    format!(
                        "https://registry.ci.openshift.org/openshift/token?&account={}&scope={}",
                        encode(user),
                        encode("repository:ocp/release:pull"))
                }
                &_ => {
                    // used for quay.io on prem
                    let scope_pull_push = format!("repository:{}:pull,push",namespace);
                    let scope_pull = format!("repository:{}:pull",namespace);
                    format!("https://{}/v2/auth?account={}&scope={}&scope={}&service={}",
                        name,
                        encode(user),
                        encode(&scope_pull_push),
                        encode(&scope_pull),
                        encode(&name))
                }
            };

    // call the realm url to get a token with the creds
    let res = t_impl.get_auth_json(token_url, auth.to_string()).await?;
    // if all goes well we should have a valid token
    parse_json_token(res)
}

/// parse the json credentials to a struct
pub fn parse_json_creds(data: String, mode: String) -> Result<String, MirrorError> {
    // parse the string of data into serde_json::Root.
    let creds: Root = serde_json::from_str(&data).map_err(|e| {
        MirrorError::new(format!(
            "[parse_json_creds] {}",
            e.to_string().to_lowercase()
        ))
    })?;
    creds
        .auths
        .get(&mode)
        .map(|p| p.auth.clone())
        .ok_or(MirrorError::new(format!(
            "[parse_json_creds] could not find key for {}",
            mode
        )))
}

/// parse the json from the api call
pub fn parse_json_token(data: String) -> Result<String, MirrorError> {
    // parse the string of data into serde_json::Token.
    let root: Token = serde_json::from_str(&data).map_err(|e| {
        MirrorError::new(format!(
            "[parse_json_token] {}",
            e.to_string().to_lowercase()
        ))
    })?;
    root.token.or(root.access_token).ok_or(MirrorError::new(
        "[parse_json_token] could not parse access_token or token fields",
    ))
}

#[cfg(test)]
mod tests {
    // this brings everything from parent's scope
    use super::*;
    use custom_logger::*;
    use serial_test::serial;

    macro_rules! aw {
        ($e:expr) => {
            tokio_test::block_on($e)
        };
    }

    #[derive(Clone)]
    struct Fake {}

    #[async_trait]
    impl TokenInterface for Fake {
        async fn get_credentials(&self, _file: Option<String>) -> Result<String, MirrorError> {
            let json_data = r#"{ 
                  "auths":{
                    "registry.redhat.io": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "quay.io": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "registry.ci.openshift.org": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "other": {
                      "auth":"aGVsbG86d29ybGQK"
                    },
                    "broken" : {
                        "auth" : "broken"
                    }
                  }
                }"#;
            Ok(json_data.to_string())
        }
        async fn get_auth_json(&self, _url: String, _auth: String) -> Result<String, MirrorError> {
            let result = r#"{
                    "token": "test",
                    "access_token": "aebcdef1234567890",
                    "expires_in":300,
                    "issued_at":"2023-10-20T13:23:31Z"
                }"#;
            Ok(result.to_string())
        }
        async fn read_file<P: AsRef<Path> + Send>(&self, _file: P) -> Result<String, MirrorError> {
            Ok("ok".to_string())
        }
    }

    fn setup_mock() -> Fake {
        Fake {}
    }

    #[test]
    #[serial]
    fn test_get_token_pass() {
        let _ = Logging::new().with_level(LevelFilter::Trace).init();

        let fake = setup_mock();
        let res = aw!(get_token(
            fake.clone(),
            "registry.redhat.io".to_string(),
            "".to_string(),
            true
        ));
        assert!(res.is_ok());

        let res_q = aw!(get_token(
            fake.clone(),
            "quay.io".to_string(),
            "".to_string(),
            true
        ));
        assert!(res_q.is_ok());

        let res_r = aw!(get_token(
            fake.clone(),
            "registry.ci.openshift.org".to_string(),
            "".to_string(),
            true
        ));
        assert!(res_r.is_ok());

        let res_o = aw!(get_token(
            fake.clone(),
            "other".to_string(),
            "".to_string(),
            true
        ));
        assert!(res_o.is_ok());

        let res_o = aw!(get_token(
            fake.clone(),
            "broken".to_string(),
            "".to_string(),
            true
        ));
        assert!(res_o.is_err());

        let res_o = aw!(get_token(
            fake.clone(),
            "none".to_string(),
            "".to_string(),
            false
        ));
        assert!(res_o.is_ok());
    }

    #[test]
    fn parse_json_creds_fail() {
        let data = "{".to_string();
        let res = parse_json_creds(data, "other".to_string());
        assert!(res.is_err());
    }

    #[test]
    fn parse_json_token_fail() {
        let data = "{".to_string();
        let res = parse_json_token(data);
        assert!(res.is_err());
    }

    #[test]
    fn parse_json_token_invalid_token_fail() {
        let data = r#"{
                    "none": "aebcdef1234567890",
                    "expires_in":300,
                    "issued_at":"2023-10-20T13:23:31Z"
                }"#;
        let res = parse_json_token(data.to_string());
        assert!(res.is_err());
    }

    #[test]
    fn parse_json_token_pass() {
        let data = r#"{
                    "access_token": "aebcdef1234567890",
                    "expires_in":300,
                    "issued_at":"2023-10-20T13:23:31Z"
                }"#;
        let res = parse_json_token(data.to_string());
        assert!(res.is_ok());
    }

    #[test]
    fn get_auth_json_pass() {
        let mut server = mockito::Server::new();
        let url = server.url();

        let t_impl = ImplTokenInterface {};
        // Create a mock server
        server
            .mock("GET", "/v2/auth")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                "{
                    \"token\": \"test\",
                    \"access_token\": \"aebcdef1234567890\",
                    \"expires_in\":300,
                    \"issued_at\":\"2023-10-20T13:23:31Z\"
                }",
            )
            .create();

        server
            .mock("GET", "/v2/error")
            .with_status(500)
            .with_header("content-type", "application/json")
            .create();

        let res = aw!(t_impl.get_auth_json(format!("{}/v2/auth", url), "auth".to_string()));
        assert!(res.is_ok());

        let res = aw!(t_impl.get_auth_json(format!("{}/v2/error", url), "auth".to_string()));
        assert!(res.is_err());
    }

    #[test]
    fn get_credentials_file_pass() {
        let _ = Logging::new().with_level(LevelFilter::Trace).init();
        let t_impl = ImplTokenInterface {};
        let res = aw!(t_impl.get_credentials(Some("tests/containers/auth.json".to_string())));
        assert!(res.is_ok());
    }

    #[test]
    #[serial]
    fn get_credentials_file_fail() {
        let _ = Logging::new().with_level(LevelFilter::Trace).init();
        let t_impl = ImplTokenInterface {};
        let res_f = aw!(t_impl.get_credentials(Some("nada".to_string())));
        assert!(res_f.is_err());
    }

    #[test]
    #[serial]
    fn get_credentials_xdg_pass() {
        let _ = Logging::new().with_level(LevelFilter::Trace).init();
        let orig = env::var_os("XDG_RUNTIME_DIR");
        env::set_var("XDG_RUNTIME_DIR", "tests");
        let t_impl = ImplTokenInterface {};
        let res_f = aw!(t_impl.get_credentials(None));
        env::set_var("XDG_RUNTIME_DIR", orig.unwrap_or_default());
        assert!(res_f.is_ok());
    }
}
