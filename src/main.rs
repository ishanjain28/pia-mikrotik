use reqwest::{Certificate, Client, ClientBuilder};
use serde::{Deserialize, Serialize};
use std::io;
use thiserror::Error;
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Debug, Error)]
pub enum PError {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    IoError(#[from] io::Error),
}

#[tokio::main]
async fn main() -> Result<(), PError> {
    let token = get_token().await?;

    println!("{:?}", token);

    // TODO(ishan): In future, give an option to specify exit node.
    // for now, we assume de-frankfurt, would prefer SG but some issues in the path to SG right now
    let response = register_wireguard_pub_key(&token.token).await?;

    println!("{:?}", response);

    Ok(())
}

async fn read_certificate() -> Result<Certificate, PError> {
    let mut buf = vec![];
    let mut file = File::open("ca.rsa.4096.crt").await?;

    file.read_to_end(&mut buf).await?;

    Ok(Certificate::from_pem(&buf)?)
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegisterWireguardPubKeyResponse {
    pub status: String,
    #[serde(rename = "server_key")]
    pub server_key: String,
    #[serde(rename = "server_port")]
    pub server_port: i64,
    #[serde(rename = "server_ip")]
    pub server_ip: String,
    #[serde(rename = "server_vip")]
    pub server_vip: String,
    #[serde(rename = "peer_ip")]
    pub peer_ip: String,
    #[serde(rename = "peer_pubkey")]
    pub peer_pubkey: String,
    #[serde(rename = "dns_servers")]
    pub dns_servers: Vec<String>,
}

async fn register_wireguard_pub_key(
    token: &str,
) -> Result<RegisterWireguardPubKeyResponse, PError> {
    let pubkey = std::env::var("PUBKEY").unwrap();
    let certificate = read_certificate().await?;

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .add_root_certificate(certificate)
        .build()
        .unwrap();

    let response = client
        .get(format!(
            "https://de-frankfurt.privacy.network:1337/addKey?pt={}&pubkey={}",
            urlencoding::encode(token),
            urlencoding::encode(&pubkey)
        ))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send()
        .await?;

    Ok(response.json().await?)
}

#[derive(Debug, Deserialize)]
pub struct GetTokenOutput {
    #[allow(unused)]
    status: String,
    token: String,
}

async fn get_token() -> Result<GetTokenOutput, PError> {
    let username = std::env::var("PIA_USER").unwrap();
    let password = Some(std::env::var("PIA_PASS").unwrap());

    let client = Client::new();

    let response = client
        .get("https://www.privateinternetaccess.com/gtoken/generateToken")
        .basic_auth(username, password)
        .send();

    Ok(response.await?.json::<GetTokenOutput>().await?)
}
