use ipnetwork::{IpNetwork, Ipv4Network};
use mikrotik::{
    interface::wireguard::{AddWireguardPeerInput, AllowedAddresses, WireguardPeer},
    ip::address,
};
use reqwest::{Certificate, Client, ClientBuilder, Url};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};
use thiserror::Error;
use tokio::{fs::File, io::AsyncReadExt};

// TODO(ishan): Interface name should not hardcoded to be `pia` and should be user configurable

#[derive(Debug, Error)]
pub enum PError {
    #[error(transparent)]
    ReqwestError(#[from] reqwest::Error),

    #[error(transparent)]
    IoError(#[from] io::Error),

    #[error(transparent)]
    MikrotikError(#[from] mikrotik::ClientError),
}

#[tokio::main]
async fn main() -> Result<(), PError> {
    let token = get_token().await?;

    // TODO(ishan): In future, give an option to specify exit node.
    // for now, we assume de-frankfurt, would prefer SG but some issues in the path to SG right now
    let response = register_wireguard_pub_key(&token.token).await?;

    // TODO(ishan):
    // 1. List all addresses in `pia` interface, remove everything except for the address we just
    //    received in response. DONE
    // 2. List all peers attached to `pia` interface, remove all peers except for the peer details
    //    we just received in response. DONE
    // 3. Check if the tunnel dies on it's own after some time and we if need to do something to
    //    keep it active.

    println!("{:?}", response);

    add_address(&response).await?;

    add_peer(&response).await?;

    Ok(())
}

async fn add_peer(ip: &RegisterWireguardPubKeyResponse) -> Result<(), PError> {
    let mut mclient = mikrotik::Client::new(
        Url::from_str("https://10.0.99.1").unwrap(),
        "pia".to_string(),
        "qwertyuiop".to_string(),
        true,
    )?;

    let peers = mikrotik::interface::wireguard::list_peers(&mut mclient)
        .await?
        .into_iter()
        .filter(|peer| peer.interface == "pia");

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
            interface: "pia".to_string(),
            persistent_keepalive: Some(25),
            preshared_key: None,
            public_key: ip.server_key.clone(),
        },
    )
    .await?;

    for peer in peers {
        mikrotik::interface::wireguard::remove_peer(&mut mclient, &peer.id).await?;
    }

    Ok(())
}

async fn add_address(ip: &RegisterWireguardPubKeyResponse) -> Result<(), PError> {
    let mut mclient = mikrotik::Client::new(
        Url::from_str("https://10.0.99.1").unwrap(),
        "pia".to_string(),
        "qwertyuiop".to_string(),
        true,
    )?;

    // This represents all the addresses on `pia` interface.
    // All but `ip.peer_ip` address have to be removed
    let mut addresses: HashMap<String, String> = address::list(&mut mclient)
        .await?
        .into_iter()
        .filter(|addr| addr.interface == "pia")
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
                interface: "pia".to_string(),
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
            "https://sg.privacy.network:1337/addKey?pt={}&pubkey={}",
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
