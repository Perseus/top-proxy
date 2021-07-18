use std::collections::HashMap;
use std::net::{SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use anyhow::anyhow;
use tokio::net::tcp::OwnedWriteHalf;
use tokio::net::TcpListener;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::error::Error;

use crate::lib::packet::Packet;

use super::client_adapter::ClientAdapter;
use super::config::{ClientConfig, GateServerConfig, ProxyServerConfig};
use super::gateserver_connector::GateServerConnector;

type ConnectionMap = Arc<Mutex<HashMap<SocketAddr, SocketAddr>>>;
pub struct ProxyServer {
    server: TcpListener,
    conn_map: ConnectionMap,
}

#[derive(Debug)]
enum ClientGateConnectionErrors {
    FailedToConnectGate,
    FailedToConnectClient,
    GateForcedDisconnect,
    ClientDisconnectionFailed,
}

#[derive(PartialEq)]
enum ConnectionTrackingMessageType {
    AddConnection,
    RemoveConnection,
}

struct ConnectionTrackingMessage {
    action_type: ConnectionTrackingMessageType,
    connection: (SocketAddr, SocketAddr),
}

impl ProxyServer {
    pub async fn new(config: ProxyServerConfig) -> Self {
        let bind_addr = format!("127.0.0.1:{}", config.port);

        let server = TcpListener::bind(bind_addr).await.unwrap();

        Self {
            server,
            conn_map: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /**
        The Proxy Server acts as a middleman between the GateServer and a Client
            * It relays packets between the two, while also performing any additional functions like
            * filtering unwanted/unrecognized packet types
            * enforcing packet size limits
            * sanitizing packet data

        Open a TCP listener on a port -> ProxyServer instance listening on it

        Whenever a connection is initiated by a client ->
            * We try to create a connection to the GateServer
                * If this fails, we close the client connection immediately
            * Once the GS connection is successful, we retrieve some metadata about the client connection
                and store it in the ClientAdapter instance
            * We create four MPSC channels (which basically act as SPSC channels)
                * One to send data to the ProxyServer whenever the client sends some data for the GateServer
                * One to send data to the ProxyServer whenever the gateserver sends some data for a client
                * One to relay data onto the GateServer from the ProxyServer whenever the client sends some
                * One to relay data onto a Client from the ProxyServer whenever the GateServer sends some

        Technical impl:
            * For every client connection
                * We create a tokio task that establishes a new connection to the GateServer
                    * This task will be responsible for parsing and passing on packets coming in from the GS to the ProxyServer
                    * We also spawn a separate task that takes the write half of this TcpStream, listens to the relevant channel
                        and writes data to the GateServer when needed
                * We create another task that will be given ownership of the client connection
                    * This task will be responsible for parsing and passing on packets coming in from the Client to the ProxyServer
                * We also spawn a separate task that takes the write half of this TcpStream, listens to the relevant channel
                        and writes data to the client when needed
    **/

    pub async fn boot(
        &mut self,
        gate_config: Arc<GateServerConfig>,
        client_config: Arc<ClientConfig>,
    ) -> anyhow::Result<()> {
        let sender = self.start_connection_tracker_thread().await;

        while let Ok((socket, socket_addr)) = self.server.accept().await {
            let thread_sender = sender.clone();

            let (client_recv_packet_writer, client_recv_packet_reader) =
                mpsc::channel::<Packet>(10);
            let (client_send_packet_writer, client_send_packet_reader) =
                mpsc::channel::<Packet>(10);

            let (gate_recv_packet_writer, gate_recv_packet_reader) = mpsc::channel::<Packet>(10);
            let (gate_send_packet_writer, gate_send_packet_reader) = mpsc::channel::<Packet>(10);

            let mut client = ClientAdapter::new(socket);
            let mut gateserver_connector = GateServerConnector::new(&gate_config);

            // start with a gateserver connection. if this doesn't happen, we cant let the client connect

            let gateserver_handle = tokio::spawn(async move {
                match gateserver_connector.connect().await {
                    Ok(_) => {
                        gateserver_connector
                            .start_listening_for_packets_to_send(gate_send_packet_reader)
                            .map_err(|_| ClientGateConnectionErrors::FailedToConnectGate)?;

                        gateserver_connector
                            .start_reading_packets(gate_recv_packet_writer)
                            .map_err(|_| ClientGateConnectionErrors::FailedToConnectGate)?;

                        Ok(())
                    }
                    Err(_) => Err(ClientGateConnectionErrors::FailedToConnectGate),
                }
            })
            .await;

            if gateserver_handle.is_err() {
                client.close().await?;
                continue;
            }

            let client_handle: Result<Result<(), ClientGateConnectionErrors>, JoinError> =
                tokio::spawn(async move {
                    client
                        .start_listening_for_packets_to_send(client_send_packet_reader)
                        .map_err(|_| ClientGateConnectionErrors::FailedToConnectClient)?;

                    client
                        .start_reading_packets(client_recv_packet_writer)
                        .map_err(|_| ClientGateConnectionErrors::FailedToConnectClient)?;

                    Ok(())
                })
                .await;

            if client_handle.is_err() {
                // TODO: handle client and gateserver closing if client handle fails
            }

            let _ = thread_sender
                .send(ConnectionTrackingMessage {
                    action_type: ConnectionTrackingMessageType::AddConnection,
                    connection: (
                        socket_addr,
                        SocketAddr::from_str(
                            format!("{}:{}", &gate_config.ip, &gate_config.port).as_str(),
                        )
                        .unwrap(),
                    ),
                })
                .await;

            self.start_middleman_tasks(
                (client_recv_packet_reader, client_send_packet_writer),
                (gate_recv_packet_reader, gate_send_packet_writer),
            );
        }
        Ok(())
    }

    fn start_middleman_tasks(
        &mut self,
        client_channels: (Receiver<Packet>, Sender<Packet>),
        gate_channels: (Receiver<Packet>, Sender<Packet>),
    ) {
        let (mut client_recv, client_send) = client_channels;
        let (mut gate_recv, gate_send) = gate_channels;

        tokio::spawn(async move {
            while let Some(packet) = client_recv.recv().await {
                let packet = Self::run_packet_through_middlewares(packet);

                println!("Sending packet from client to gate {:?}", packet);
                let _ = gate_send.send(packet).await;
            }
        });

        tokio::spawn(async move {
            while let Some(packet) = gate_recv.recv().await {
                let packet = Self::run_packet_through_middlewares(packet);
                println!("Sending packet from gate to client {:?}", packet);
                let _ = client_send.send(packet).await;
            }
        });
    }

    fn run_packet_through_middlewares(packet: Packet) -> Packet {
        packet
    }

    async fn start_connection_tracker_thread(&self) -> Sender<ConnectionTrackingMessage> {
        let (write_half, mut read_half) = mpsc::channel::<ConnectionTrackingMessage>(10);
        let cloned_map = self.conn_map.clone();

        tokio::spawn(async move {
            while let Some(val) = read_half.recv().await {
                match val.action_type {
                    ConnectionTrackingMessageType::AddConnection => {
                        if let Ok(mut map) = cloned_map.lock() {
                            println!(
                                "Incoming connection {} {}",
                                val.connection.0, val.connection.1
                            );
                            map.insert(val.connection.0, val.connection.1);
                        }
                    }

                    ConnectionTrackingMessageType::RemoveConnection => {}
                }
            }
        });
        write_half
    }

    fn start_gateserver_communication_task(
        &mut self,
        packet_writer: Sender<Packet>,
        packet_reader: Receiver<Packet>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn start_client_communication_task(
        &mut self,
        packet_writer: Sender<Packet>,
        packet_reader: Receiver<Packet>,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore]
    async fn it_binds_a_gateserver_and_client_connection() {
        assert_eq!(0, 1);
    }
}
