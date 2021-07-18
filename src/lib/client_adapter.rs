use std::{
    io::Cursor,
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
};

use bytes::{Buf, BufMut, BytesMut};
use std::io;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::mpsc::{Receiver, Sender},
};

use anyhow::anyhow;

use crate::lib::packet::FrameError;

use super::packet::{Command, Packet, PacketWriter};

const MAX_BUFFER_CAPACITY: usize = 8192;

#[derive(Debug)]
pub struct ClientAdapter {
    client_ip: Option<SocketAddr>,
    buffer: BytesMut,

    socket_reader: Option<OwnedReadHalf>,
    socket_writer: Option<OwnedWriteHalf>,
}

impl ClientAdapter {
    pub fn new(socket: TcpStream) -> Self {
        let client_ip: Option<SocketAddr> = match socket.peer_addr() {
            Ok(addr) => Some(addr),
            Err(_) => None,
        };

        let (socket_reader, socket_writer) = socket.into_split();

        Self {
            socket_reader: Some(socket_reader),
            socket_writer: Some(socket_writer),
            client_ip,
            buffer: BytesMut::with_capacity(4096),
        }
    }

    pub fn start_listening_for_packets_to_send(
        &mut self,
        mut channel: Receiver<Packet>,
    ) -> anyhow::Result<()> {
        if self.socket_writer.is_none() {
            return Err(anyhow!("No Client connection writer found"));
        }

        let mut writer = self.socket_writer.take().unwrap();

        tokio::spawn(async move {
            while let Some(packet) = channel.recv().await {
                let mut bytes = packet.get_as_bytes();
                writer.write_all_buf(&mut bytes).await;
            }
        });

        Ok(())
    }

    pub fn start_reading_packets(&mut self, channel: Sender<Packet>) -> anyhow::Result<()> {
        if self.socket_reader.is_none() {
            return Err(anyhow!("No Client connection reader found"));
        }

        let mut reader = self.socket_reader.take().unwrap();

        tokio::spawn(async move {
            let mut buffer = BytesMut::with_capacity(4096);

            loop {
                if !buffer.has_remaining_mut() {
                    let mut cursor = Cursor::new(&buffer[..]);
                    match Packet::check_frame(&mut cursor) {
                        Ok(len) => {
                            cursor.set_position(0);
                            if let Ok(packet) = Packet::parse_frame(&mut buffer, len) {
                                if channel.send(packet).await.is_err() {}
                            }

                            buffer.advance(len);
                        }
                        Err(_) => {
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
                        println!("Client connection closed");
                        break;
                    }

                    Ok(n) => {
                        let mut cursor = Cursor::new(&buffer[..]);

                        match Packet::check_frame(&mut cursor) {
                            Ok(len) => {
                                cursor.set_position(0);
                                let packet = Packet::parse_frame(&mut buffer, len).unwrap();
                                println!("Got packet FROM client {:?}", packet);

                                if channel.send(packet).await.is_ok() {}
                                buffer.advance(len);
                            }

                            Err(err) => {
                                if err == FrameError::Invalid {
                                    println!("Clearing buffer");
                                    buffer.clear();
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

    pub fn get_client_ip(&self) -> Option<SocketAddr> {
        self.client_ip
    }

    // TODO: impl
    pub async fn close(self) -> anyhow::Result<()> {
        Ok(())
    }
}
