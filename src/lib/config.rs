use ini::Ini;
use std::{io::Write, net::Ipv4Addr};
use termcolor::{BufferWriter, Color, ColorChoice, ColorSpec, StandardStream, WriteColor};

#[derive(Debug)]
pub struct GateServerConfig {
    pub ip: Ipv4Addr,
    pub port: u16,
}

impl GateServerConfig {
    pub fn new() -> Self {
        GateServerConfig {
            ip: Ipv4Addr::new(127, 0, 0, 1),
            port: 1973,
        }
    }
}

pub struct ClientConfig {
    pub num_max_connections: u16,
}

impl ClientConfig {
    pub fn new() -> Self {
        ClientConfig {
            num_max_connections: 20,
        }
    }
}

pub struct ProxyServerConfig {
    pub port: u16,
}

impl ProxyServerConfig {
    pub fn new() -> Self {
        ProxyServerConfig { port: 6000 }
    }
}

#[derive(Default)]
pub struct Config {
    config: Ini,
    gateserver_config: Option<GateServerConfig>,
    client_config: Option<ClientConfig>,
    proxy_server_config: Option<ProxyServerConfig>,
}

impl Config {
    pub fn new() -> Self {
        Config {
            config: Ini::new(),
            gateserver_config: None,
            client_config: None,
            proxy_server_config: None,
        }
    }

    fn print_begin(&self) {
        let bufwtr = BufferWriter::stderr(ColorChoice::Always);
        let mut buffer = bufwtr.buffer();

        buffer
            .set_color(ColorSpec::new().set_fg(Some(Color::Blue)))
            .unwrap();
        writeln!(&mut buffer, "Loading config...").unwrap();
        bufwtr.print(&buffer).unwrap();
        buffer.reset().unwrap();
    }

    pub fn load_config(&mut self, config_file: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.print_begin();

        self.config = Ini::load_from_file(config_file)?;

        self.load_gateserver_config()?;
        self.load_client_config()?;
        self.load_proxy_server_config()?;

        Ok(())
    }

    fn load_gateserver_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut gate_config = GateServerConfig::new();

        match self.config.section(Some("GateServer")) {
            Some(conf) => {
                if let Some(ip) = conf.get("IP") {
                    gate_config.ip = ip.parse::<Ipv4Addr>().unwrap();
                }

                if let Some(port) = conf.get("Port") {
                    gate_config.port = port.parse::<u16>().unwrap();
                }
            }

            None => {
                panic!("No GateServer config found")
            }
        }

        self.gateserver_config = Some(gate_config);

        Ok(())
    }

    fn load_client_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut client_config = ClientConfig::new();

        match self.config.section(Some("Client")) {
            Some(conf) => {
                if let Some(max_connections) = conf.get("MaxConnections") {
                    client_config.num_max_connections = max_connections.parse::<u16>().unwrap();
                }
            }

            None => {
                panic!("No Client config found")
            }
        }

        self.client_config = Some(client_config);

        Ok(())
    }

    fn load_proxy_server_config(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut proxy_config = ProxyServerConfig::new();

        match self.config.section(Some("ProxyServer")) {
            Some(conf) => {
                if let Some(port) = conf.get("Port") {
                    proxy_config.port = port.parse::<u16>().unwrap();
                }
            }

            None => {
                panic!("No ProxyServer config found")
            }
        }

        self.proxy_server_config = Some(proxy_config);

        Ok(())
    }

    pub fn take_gateserver_config(&mut self) -> Option<GateServerConfig> {
        let config = self.gateserver_config.take();
        config
    }

    pub fn take_client_config(&mut self) -> Option<ClientConfig> {
        let config = self.client_config.take();
        config
    }

    pub fn take_proxy_config(&mut self) -> Option<ProxyServerConfig> {
        let config = self.proxy_server_config.take();
        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_correctly_loads_a_config() {
        let mut conf = Config::new();
        conf.load_config("./tests/artifacts/config_test.ini")
            .unwrap();

        let gs_config = conf.take_gateserver_config().unwrap();
        let client_config = conf.take_client_config().unwrap();
        let proxy_config = conf.take_proxy_config().unwrap();

        assert_eq!(gs_config.ip, Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(gs_config.port, 1973);
        assert_eq!(client_config.num_max_connections, 400);
        assert_eq!(proxy_config.port, 6000);
    }
}
