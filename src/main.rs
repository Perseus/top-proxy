use lib::config::Config;
use lib::gateserver::GateServerConnector;
use std::sync::Arc;

mod lib;

const CONFIG_FILE: &str = "config.cfg";


#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let mut config = Config::new();
  
  
  match config.load_config(CONFIG_FILE) {
    Ok(_) => {}
    Err(err) => {
      panic!("Error while reading config - {:?}", err);
    }
  };

  let gateserver_config = Arc::new(config.take_gateserver_config().unwrap());
  let client_config = Arc::new(config.take_client_config().unwrap()); 

  tokio::spawn( async move {
    let mut gateserver = GateServerConnector::new(gateserver_config.as_ref());
    gateserver.connect().await.unwrap();
  });

  Ok(())
}
