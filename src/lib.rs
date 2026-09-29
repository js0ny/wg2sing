use http::uri::Authority;
use ini::{Ini, Properties};

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct WireGuardEndpoint {
    #[serde(rename = "type")]
    endpoint_type: String,
    tag: String,
    system: bool,
    address: Vec<String>,
    private_key: String,
    peers: Vec<SingBoxPeer>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SingBoxPeer {
    address: String,
    port: u16,
    public_key: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pre_shared_key: Option<String>,

    allowed_ips: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    persistent_keepalive_interval: Option<u16>,
}

fn required<'a>(properties: &'a Properties, key: &str, section: &str) -> Result<&'a str, String> {
    properties
        .get(key)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("missing {key} in [{section}]"))
}

fn addresses(properties: &Properties, key: &str, section: &str) -> Result<Vec<String>, String> {
    let values: Vec<String> = properties
        .get_all(key)
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect();
    if values.is_empty() {
        return Err(format!("missing {key} in [{section}]"));
    }
    Ok(values)
}

fn peer(properties: &Properties) -> Result<SingBoxPeer, String> {
    let endpoint = required(properties, "Endpoint", "Peer")?;
    let authority: Authority = endpoint
        .parse()
        .map_err(|_| format!("invalid Endpoint: {endpoint}"))?;
    if endpoint.contains('@') {
        return Err(format!("invalid Endpoint: {endpoint}"));
    }
    let address = authority
        .host()
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or_else(|| authority.host());
    if address.is_empty() {
        return Err(format!("invalid Endpoint: {endpoint}"));
    }
    let port = authority
        .port_u16()
        .filter(|port| *port != 0)
        .ok_or_else(|| format!("invalid Endpoint port: {endpoint}"))?;

    let persistent_keepalive_interval = properties
        .get("PersistentKeepalive")
        .map(|value| {
            value
                .trim()
                .parse()
                .map_err(|_| format!("invalid PersistentKeepalive: {value}"))
        })
        .transpose()?;

    Ok(SingBoxPeer {
        address: address.to_owned(),
        port,
        public_key: required(properties, "PublicKey", "Peer")?.to_owned(),
        pre_shared_key: properties
            .get("PresharedKey")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned),
        allowed_ips: addresses(properties, "AllowedIPs", "Peer")?,
        persistent_keepalive_interval,
    })
}

pub fn convert(config: &Ini, tag: String, system: bool) -> Result<WireGuardEndpoint, String> {
    let interface = config
        .section(Some("Interface"))
        .ok_or("missing [Interface] section")?;
    let peers = config
        .section_all(Some("Peer"))
        .map(peer)
        .collect::<Result<Vec<_>, _>>()?;

    Ok(WireGuardEndpoint {
        endpoint_type: "wireguard".to_owned(),
        tag,
        system,
        address: addresses(interface, "Address", "Interface")?,
        private_key: required(interface, "PrivateKey", "Interface")?.to_owned(),
        peers,
    })
}

pub fn format_output(
    endpoint: &WireGuardEndpoint,
    wrap_endpoints: bool,
) -> Result<String, serde_json::Error> {
    if wrap_endpoints {
        serde_json::to_string_pretty(&serde_json::json!({ "endpoints": [endpoint] }))
    } else {
        serde_json::to_string_pretty(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const EXAMPLE_CONFIG: &str = "[Interface]\nPrivateKey = private\nAddress = 10.2.0.2/32\n\
                                  [Peer]\nPublicKey = public\nAllowedIPs = 0.0.0.0/0, ::/0\n\
                                  Endpoint = example.org:51820\nPersistentKeepalive = 25\n";

    #[test]
    fn wraps_endpoint_when_requested() {
        let config = Ini::load_from_str(EXAMPLE_CONFIG).unwrap();
        let endpoint = convert(&config, "sing-test".to_owned(), false).unwrap();
        let bare: serde_json::Value =
            serde_json::from_str(&format_output(&endpoint, false).unwrap()).unwrap();
        let wrapped: serde_json::Value =
            serde_json::from_str(&format_output(&endpoint, true).unwrap()).unwrap();

        assert_eq!(bare["type"], "wireguard");
        assert_eq!(wrapped, json!({ "endpoints": [bare] }));
    }

    #[test]
    fn converts_example() {
        let config = Ini::load_from_str(EXAMPLE_CONFIG).unwrap();
        let endpoint = convert(&config, "sing-test".to_owned(), true).unwrap();
        let output = serde_json::to_value(endpoint).unwrap();

        assert_eq!(output["type"], "wireguard");
        assert_eq!(output["tag"], "sing-test");
        assert_eq!(output["system"], true);
        assert_eq!(output["address"], json!(["10.2.0.2/32"]));
        assert_eq!(output["private_key"], "private");
        assert_eq!(output["peers"][0]["public_key"], "public");
        assert_eq!(
            output["peers"][0]["allowed_ips"],
            json!(["0.0.0.0/0", "::/0"])
        );
        assert_eq!(output["peers"][0]["persistent_keepalive_interval"], 25);
    }

    #[test]
    fn converts_multiple_peers_and_ipv6_endpoint() {
        let config = Ini::load_from_str(
            "[Interface]\nPrivateKey = private\nAddress = 10.0.0.2/32, fd00::2/128\n\
             [Peer]\nPublicKey = first\nAllowedIPs = 10.0.0.0/8\nEndpoint = example.org:51820\n\
             PresharedKey = shared\n\
             [Peer]\nPublicKey = second\nAllowedIPs = ::/0\nEndpoint = [2001:db8::1]:443\n",
        )
        .unwrap();
        let output =
            serde_json::to_value(convert(&config, "wg".to_owned(), false).unwrap()).unwrap();

        assert_eq!(output["address"], json!(["10.0.0.2/32", "fd00::2/128"]));
        assert_eq!(output["system"], false);
        assert_eq!(output["peers"][0]["address"], "example.org");
        assert_eq!(output["peers"][0]["pre_shared_key"], "shared");
        assert_eq!(output["peers"][1]["address"], "2001:db8::1");
        assert_eq!(output["peers"][1]["port"], 443);
        assert_eq!(output["peers"][1]["allowed_ips"], json!(["::/0"]));
        assert_eq!(output["peers"][1].get("pre_shared_key"), None);
        assert_eq!(
            output["peers"][1].get("persistent_keepalive_interval"),
            None
        );
    }

    #[test]
    fn rejects_invalid_peer() {
        let config = Ini::load_from_str(
            "[Interface]\nPrivateKey = private\nAddress = 10.0.0.2/32\n\
             [Peer]\nPublicKey = first\nAllowedIPs = 0.0.0.0/0\nEndpoint = example.org:invalid\n",
        )
        .unwrap();
        assert!(convert(&config, "wg".to_owned(), false).is_err());
    }

    #[test]
    fn rejects_endpoint_without_port_or_with_userinfo() {
        for endpoint in ["example.org", "user@example.org:51820", "example.org:0"] {
            let config = Ini::load_from_str(&format!(
                "[Interface]\nPrivateKey = private\nAddress = 10.0.0.2/32\n\
                 [Peer]\nPublicKey = first\nAllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}\n"
            ))
            .unwrap();
            assert!(convert(&config, "wg".to_owned(), false).is_err());
        }
    }
}
