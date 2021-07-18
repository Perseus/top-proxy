use bytes::{Buf, BufMut, BytesMut};
use std::{
    borrow::Borrow,
    io::{self, Cursor},
    net::Ipv4Addr,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    sync::mpsc::{Receiver, Sender},
};

use super::{
    config::GateServerConfig,
    packet::{FrameError, Packet},
};
use anyhow::anyhow;

const MAX_BUFFER_CAPACITY: usize = 8192;

pub struct GateServerConnector {
    ip: Ipv4Addr,
    port: u16,
    conn_reader: Option<OwnedReadHalf>,
    conn_writer: Option<OwnedWriteHalf>,
    buffer: BytesMut,
}

impl GateServerConnector {
    pub fn new(config: &GateServerConfig) -> Self {
        GateServerConnector {
            ip: config.ip,
            port: config.port,
            conn_reader: None,
            conn_writer: None,
            buffer: BytesMut::with_capacity(4096),
        }
    }

    pub async fn connect(&mut self) -> anyhow::Result<()> {
        let socket_addr = format!("{}:{}", self.ip.to_string(), self.port.to_string());
        let stream = TcpStream::connect(socket_addr).await?;
        let (reader, writer) = stream.into_split();

        self.conn_reader = Some(reader);
        self.conn_writer = Some(writer);

        Ok(())
    }

    pub fn start_reading_packets(&mut self, channel: Sender<Packet>) -> anyhow::Result<()> {
        if self.conn_reader.is_none() {
            return Err(anyhow!("No GateServer connection found"));
        }

        let mut reader = self.conn_reader.take().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::with_capacity(4096);

            loop {
                if !buffer.has_remaining_mut() {
                    let mut cursor = Cursor::new(&buffer[..]);
                    match Packet::check_frame(&mut cursor) {
                        Ok(len) => {
                            cursor.set_position(0);
                            if let Ok(packet) = Packet::parse_frame(&mut buffer, len) {
                                channel.send(packet).await;
                            }
                            buffer.advance(len);
                        }
                        Err(err) => {
                            if buffer.capacity() > MAX_BUFFER_CAPACITY {
                                buffer.clear();
                            } else {
                                buffer.reserve(4096);
                            }
                        }
                    }
                }

                match reader.read_buf(&mut buffer).await {
                    Ok(0) => {
                        println!("Gateserver connection closed");
                        break;
                    }

                    Ok(n) => {
                        let mut cursor = Cursor::new(&buffer[..]);

                        println!("Got {} from gate {:?}", n, buffer);
                        match Packet::check_frame(&mut cursor) {
                            Ok(len) => {
                                cursor.set_position(0);
                                let packet = Packet::parse_frame(&mut buffer, len).unwrap();
                                println!("Got packet FROM gate {:?}", packet);
                                channel.send(packet).await;

                                buffer.advance(len);
                            }

                            Err(err) => {
                                if err == FrameError::Invalid {
                                    buffer.clear();
                                    println!("Clearing buffer");
                                }
                            }
                        }
                    }

                    Err(ref e) => {
                        if e.kind() == io::ErrorKind::WouldBlock {
                            continue;
                        }
                    }
                }
            }
        });

        Ok(())
    }

    pub fn start_listening_for_packets_to_send(
        &mut self,
        mut channel: Receiver<Packet>,
    ) -> anyhow::Result<()> {
        if self.conn_writer.is_none() {
            return Err(anyhow!("No GateServer connection found"));
        }

        let mut writer = self.conn_writer.take().unwrap();

        tokio::spawn(async move {
            while let Some(packet) = channel.recv().await {
                let mut bytes = packet.get_as_bytes();
                writer.write_all_buf(&mut bytes).await;
            }
        });

        Ok(())
    }

    pub fn has_connection(&self) -> bool {
        self.conn_reader.is_some()
    }
}
