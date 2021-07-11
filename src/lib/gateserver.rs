use std::net::{Ipv4Addr};
use tokio::net::TcpStream;

use super::config::GateServerConfig;

pub struct GateServerConnector {
  ip: Ipv4Addr,
  port: u16,
  connection: Option<TcpStream>,
}

impl GateServerConnector {
  pub fn new(config: &GateServerConfig) -> Self {
    GateServerConnector {
      ip: config.ip,
      port: config.port,
      connection: None,
    }
  }

  pub async fn connect(&mut self) -> Result<(), Box<dyn std::error::Error>> {
    let socket_addr = format!("{}:{}", self.ip.to_string(), self.port.to_string());
    let stream = TcpStream::connect(socket_addr).await?;

    self.connection = Some(stream);
    Ok(())
  }

  pub fn has_connection(&self) -> bool {
    match &self.connection {
      Some(_) => true,
      None => false
    }
  }
}


#[cfg(test)]
mod tests {
  use tokio::net::TcpListener;

use super::*;

  #[tokio::test]
  async fn it_successfully_establishes_a_connection_with_the_gateserver() {
      let gateserver = TcpListener::bind("127.0.0.1:1973").await.unwrap();

      let mut gate_config = GateServerConfig::new();
      gate_config.ip = Ipv4Addr::new(127, 0, 0, 1);
      gate_config.port = 1973;

      let mut connector = GateServerConnector::new(&gate_config);

      connector.connect().await.unwrap();

      assert_eq!(connector.has_connection(), true);
  }
}