use ipnetwork::{IpNetwork, Ipv4Network};
use mikrotik::{
    interface::wireguard::{AddWireguardPeerInput, AllowedAddresses},
    ip::address,
};
use ping::ping;
use reqwest::{Certificate, Client, ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    io,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    time::Duration,
};
use thiserror::Error;
use tokio::{fs::File, io::AsyncReadExt};

#[derive(Debug, Error)]
pub enum PError {
    #[error(transparent)]
    PiaError(#[from] PiaError),

    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    MikrotikError(#[from] mikrotik::ClientError),

    #[error(transparent)]
    TomlError(#[from] toml::de::Error),
}

#[derive(Debug, Error, Deserialize, Serialize)]
pub struct PiaError {
    status: String,
    message: String,
}

impl Display for PiaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "status = {} message = {}",
            self.status, self.message,
        ))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    router_url: String,
    router_password: String,
    pia_user: String,
    pia_pass: String,
    pia_exit_node_url: String,
    router_pubkey: String,
    interface: String,
}

#[tokio::main]
async fn main() -> Result<(), PError> {
    let config: Config = {
        let mut f = File::open("./config.toml").await?;

        let mut contents = String::new();
        f.read_to_string(&mut contents).await?;

        toml::from_str(&contents)?
    };

    loop {
        // 3. Check if the tunnel dies on it's own after some time and we if need to do something to
        //    keep it active.
        let wg_details = match activate_tunnel(&config).await {
            Ok(v) => v,
            Err(e) => {
                println!("error in activating tunnel: {:?}", e);

                tokio::time::sleep(Duration::from_secs(60)).await;
                continue;
            }
        };

        println!("added address and peer");

        while ping(
            wg_details.server_vip.parse().unwrap(),
            Some(Duration::from_secs(30)),
            Some(0),
            None,
            Some(255),
            None,
        )
        .is_ok()
        {
            println!("vpn server ip is reachabable");
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    }
}

async fn activate_tunnel(config: &Config) -> Result<RegisterWireguardPubKeyResponse, PError> {
    let token = get_token(config).await?;

    // TODO(ishan): In future, give an option to specify exit node.
    // for now, we assume de-frankfurt, would prefer SG but some issues in the path to SG right now
    let response = register_wireguard_pub_key(config, &token.token).await?;

    add_address(config, &response).await?;

    add_peer(config, &response).await?;

    Ok(response)
}

async fn add_peer(config: &Config, ip: &RegisterWireguardPubKeyResponse) -> Result<(), PError> {
    let mut mclient = mikrotik::Client::new(
        Url::from_str(&config.router_url).unwrap(),
        config.interface.to_string(),
        config.router_password.to_string(),
        true,
    )?;

    let peers = mikrotik::interface::wireguard::list_peers(&mut mclient)
        .await?
        .into_iter()
        .filter(|peer| peer.interface == config.interface);

    mikrotik::interface::wireguard::add_peer(
        &mut mclient,
        AddWireguardPeerInput {
            allowed_address: AllowedAddresses(vec![IpNetwork::V4(
                Ipv4Network::new(Ipv4Addr::new(0, 0, 0, 0), 0).unwrap(),
            )]),
            comment: Some("Managed by pia-mikrotik".to_string()),
            disabled: false,
            endpoint_address: Some(IpAddr::from_str(&ip.server_ip).unwrap()),
            endpoint_port: ip.server_port,
            interface: config.interface.to_string(),
            persistent_keepalive: Some(25),
            preshared_key: None,
            public_key: ip.server_key.clone(),
        },
    )
    .await
    .expect("error in adding peer");

    for peer in peers {
        mikrotik::interface::wireguard::remove_peer(&mut mclient, &peer.id)
            .await
            .expect("error in removing peer");
    }

    Ok(())
}

async fn add_address(config: &Config, ip: &RegisterWireguardPubKeyResponse) -> Result<(), PError> {
    // 1. List all addresses in `config.interface` interface, remove everything except for the address we just
    //    received in response.
    // 2. List all peers attached to `config.interface` interface, remove all peers except for the peer details
    //    we just received in response.

    let mut mclient = mikrotik::Client::new(
        Url::from_str(&config.router_url).unwrap(),
        config.interface.to_string(),
        config.router_password.to_string(),
        true,
    )?;

    // This represents all the addresses on `config.interface` interface.
    // All but `ip.peer_ip` address have to be removed
    let mut addresses: HashMap<String, String> = address::list(&mut mclient)
        .await?
        .into_iter()
        .filter(|addr| addr.interface == config.interface)
        .map(|addr| (addr.address, addr.id))
        .collect();

    if addresses.contains_key(&ip.peer_ip) {
        addresses.remove(&ip.peer_ip);
    } else {
        mikrotik::ip::address::add(
            &mut mclient,
            address::AddAddressInput {
                address: ip.peer_ip.clone(),
                comment: Some("Managed by pia-mikrotik".to_string()),
                disabled: false,
                interface: config.interface.to_string(),
                network: None,
            },
        )
        .await?;
    }
    for (_, id) in addresses.into_iter() {
        mikrotik::ip::address::remove(&mut mclient, &id).await?;
    }

    Ok(())
}

async fn read_certificate() -> Result<Certificate, PError> {
    let mut buf = vec![];
    let mut file = File::open("ca.rsa.4096.crt").await?;

    file.read_to_end(&mut buf).await?;

    Ok(Certificate::from_pem(&buf)?)
}

#[derive(Default, Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegisterWireguardPubKeyResponse {
    pub status: String,
    pub server_key: String,
    pub server_port: u16,
    pub server_ip: String,
    pub server_vip: String,
    pub peer_ip: String,
    pub peer_pubkey: String,
    pub dns_servers: Vec<String>,
}

async fn register_wireguard_pub_key(
    config: &Config,
    token: &str,
) -> Result<RegisterWireguardPubKeyResponse, PError> {
    let certificate = read_certificate().await?;

    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .add_root_certificate(certificate)
        .build()
        .unwrap();

    let response = client
        .get(format!(
            "{}/addKey?pt={}&pubkey={}",
            config.pia_exit_node_url,
            urlencoding::encode(token),
            urlencoding::encode(&config.router_pubkey)
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

async fn get_token(config: &Config) -> Result<GetTokenOutput, PError> {
    let client = Client::new();

    let response = client
        .get("https://www.privateinternetaccess.com/gtoken/generateToken")
        .basic_auth(&config.pia_user, Some(&config.pia_pass))
        .send();

    let response = response.await?;

    if response.status().is_success() {
        Ok(response.json::<GetTokenOutput>().await?)
    } else {
        Err(PError::PiaError(response.json::<PiaError>().await?))
    }
}
