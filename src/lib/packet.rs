use byteorder::{BigEndian, ByteOrder, LittleEndian, ReadBytesExt};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use num_enum::IntoPrimitive;
use num_enum::TryFromPrimitive;
use std::iter::FromIterator;
use std::{io::Read, mem::size_of};

#[derive(PartialEq, Debug, TryFromPrimitive, Clone, IntoPrimitive)]
#[repr(u16)]
pub enum Command {
    None,
    BridgeChatLogs = 1514,
}

const DEFAULT_HEADER: u32 = 2147483648;

pub trait PacketReader {
    fn read_cmd(&mut self) -> Option<Command>;
    fn read_char(&mut self) -> Option<u8>;
    fn read_short(&mut self) -> Option<u16>;
    fn read_long(&mut self) -> Option<u32>;
    fn read_long_long(&mut self) -> Option<u64>;
    fn read_sequence(&mut self) -> Option<&[u8]>;
    fn read_string(&mut self) -> Option<String>;
    fn read_float(&mut self) -> Option<f32>;
    fn reverse_read_char(&mut self) -> Option<u8>;
    fn reverse_read_short(&mut self) -> Option<u16>;
    fn reverse_read_long(&mut self) -> Option<u32>;
}

pub trait PacketWriter {
    fn write_buffer(&mut self, buffer: Vec<u8>) -> Result<(), Box<dyn std::error::Error>>;
    fn write_cmd(&mut self, cmd: Command) -> Result<(), Box<dyn std::error::Error>>;
    fn write_char(&mut self, char: u8) -> Result<(), Box<dyn std::error::Error>>;
    fn write_short(&mut self, data: u16) -> Result<(), Box<dyn std::error::Error>>;
    fn write_long(&mut self, data: u32) -> Result<(), Box<dyn std::error::Error>>;
    fn write_long_long(&mut self, data: u64) -> Result<(), Box<dyn std::error::Error>>;
    fn write_sequence(
        &mut self,
        sequence: &[u8],
        len: u16,
    ) -> Result<(), Box<dyn std::error::Error>>;
    fn write_string(&mut self, string: &str) -> Result<(), Box<dyn std::error::Error>>;
    fn write_float(&mut self, data: f32) -> Result<(), Box<dyn std::error::Error>>;
    fn build_packet(&mut self) -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Debug, Clone)]
pub struct Packet {
    data: BytesMut,
    cmd: Command,
    size: u16,
    offset: u8,
    header: u32,
    reverse_offset: u8,
}

impl Packet {
    pub fn new() -> Self {
        // the offset is 4 since 4 bytes of the header are already consumed to identify the entire packet frame
        Packet {
            data: BytesMut::with_capacity(64),
            cmd: Command::None,
            size: 0,
            offset: 4,
            header: DEFAULT_HEADER,
            reverse_offset: 0,
        }
    }

    pub fn from_bytes(data: BytesMut) -> Self {
        let mut packet = Packet {
            data,
            cmd: Command::None,
            size: 0,
            offset: 0,
            header: 0,
            reverse_offset: 0,
        };

        if let Some(size) = packet.read_short() {
            packet.size = size;

            if let Some(header) = packet.read_long() {
                packet.header = header;

                if let Some(cmd) = packet.read_cmd() {
                    packet.cmd = cmd;
                }
            }
        }

        packet
    }

    pub fn get_remaining_packet_len(&self) -> usize {
        let offset = self.offset as usize;
        let remaining_packet_len = self.data.len() - offset;

        remaining_packet_len
    }

    fn get_total_packet_len(&self) -> usize {
        self.data.len()
    }

    fn increment_offset<T>(&mut self) {
        self.offset += size_of::<T>() as u8;
    }

    fn increment_reverse_offset<T>(&mut self) {
        self.reverse_offset += size_of::<T>() as u8;
    }

    fn has_enough_bytes_for_data<T>(&mut self) -> bool {
        let packet_len = self.get_remaining_packet_len();
        if packet_len < size_of::<T>() {
            return false;
        }

        true
    }

    pub fn duplicate(&self) -> Self {
        let mut packet = self.clone();
        packet.offset = 8; // size, header data and command have already been read
        packet.reverse_offset = 0;

        packet
    }
}

impl PacketReader for Packet {
    /// Returns a <Command> enum, reading the first 2 bytes of a packet (after the header)
    fn read_cmd(&mut self) -> Option<Command> {
        if self.cmd != Command::None || self.offset > 6 {
            return Some(self.cmd.clone());
        }

        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<u16>() {
            return None;
        }

        let data_len_to_read = size_of::<u16>();
        if let Some(mut command_data) = self.data.get(offset..offset + data_len_to_read) {
            let primitive_command = command_data.read_u16::<BigEndian>().ok()?;
            let command = Command::try_from_primitive(primitive_command).ok()?;

            self.increment_offset::<u16>();
            self.cmd = command.clone();

            return Some(command);
        } else {
            println!("no cmd found");
        }

        None
    }

    fn read_char(&mut self) -> Option<u8> {
        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<u8>() {
            return None;
        }

        let data_len_to_read = size_of::<u8>();
        let mut data = self.data.get(offset..offset + data_len_to_read)?;
        let data_to_return = data.read_u8().ok()?;

        self.increment_offset::<u8>();

        Some(data_to_return)
    }

    fn read_short(&mut self) -> Option<u16> {
        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<u16>() {
            return None;
        }

        let data_len_to_read = size_of::<u16>();
        let mut data = self.data.get(offset..offset + data_len_to_read)?;
        let data_to_return = data.read_u16::<BigEndian>().ok()?;
        self.increment_offset::<u16>();

        Some(data_to_return)
    }

    fn read_long(&mut self) -> Option<u32> {
        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<u32>() {
            return None;
        }

        let data_len_to_read = size_of::<u32>();
        let mut data = self.data.get(offset..offset + data_len_to_read)?;
        let data_to_return = data.read_u32::<BigEndian>().ok()?;
        self.increment_offset::<u32>();

        Some(data_to_return)
    }

    fn read_long_long(&mut self) -> Option<u64> {
        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<u64>() {
            return None;
        }

        let data_len_to_read = size_of::<u64>();
        let mut data = self.data.get(offset..offset + data_len_to_read)?;
        let data_to_return = data.read_u64::<BigEndian>().ok()?;
        self.increment_offset::<u64>();

        Some(data_to_return)
    }

    fn read_float(&mut self) -> Option<f32> {
        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<f32>() {
            return None;
        }

        let data_len_to_read = size_of::<f32>();
        let mut data = self.data.get(offset..offset + data_len_to_read)?;
        let data_to_return = data.read_f32::<BigEndian>().ok()?;
        self.increment_offset::<f32>();

        Some(data_to_return)
    }

    fn read_sequence(&mut self) -> Option<&[u8]> {
        let offset = self.offset as usize;
        if !self.has_enough_bytes_for_data::<u16>() {
            return None;
        }

        let seq_len_data_len = size_of::<u16>();
        let sequence_length = self
            .data
            .get(offset..offset + seq_len_data_len)?
            .read_u16::<BigEndian>()
            .ok()? as usize;

        println!("sequence length -> {}", sequence_length);
        if self.get_remaining_packet_len() < sequence_length {
            return None;
        }

        let sequence_start_offset = offset + seq_len_data_len;

        // last byte is a null character for the sequence, we can ignore it
        let sequence = self
            .data
            .get(sequence_start_offset..sequence_start_offset + sequence_length - 1)?;
        self.offset += (seq_len_data_len + sequence_length) as u8;
        Some(sequence)
    }

    fn read_string(&mut self) -> Option<String> {
        let sequence = self.read_sequence()?;
        let buf: Vec<u8> = Vec::from(sequence);
        let string = String::from_utf8(buf).ok()?;

        Some(string)
    }

    /// Reads a character from the trailing end of a packet
    //
    /// Increments a "reverse" offset which tracks the data that has been previously returned from the end
    fn reverse_read_char(&mut self) -> Option<u8> {
        if self.get_total_packet_len() < self.reverse_offset as usize + size_of::<u8>() {
            return None;
        }

        self.increment_reverse_offset::<u8>();

        let start_index = self.get_total_packet_len() - self.reverse_offset as usize;
        let end_index = start_index + size_of::<u8>();

        let mut data = self.data.get(start_index..end_index)?;
        let data_to_return = data.read_u8().ok()?;

        Some(data_to_return)
    }

    /// Reads a short from the trailing end of a packet
    //
    /// Increments a "reverse" offset which tracks the data that has been previously returned from the end
    fn reverse_read_short(&mut self) -> Option<u16> {
        let data_size = size_of::<u16>();

        if self.get_total_packet_len() < (self.reverse_offset as usize + data_size) {
            return None;
        }

        self.increment_reverse_offset::<u16>();

        let start_index = self.get_total_packet_len() - self.reverse_offset as usize;
        let end_index = start_index + data_size;

        let mut data = self.data.get(start_index..end_index)?;
        let data_to_return = data.read_u16::<BigEndian>().ok()?;

        Some(data_to_return)
    }

    /// Reads a long from the trailing end of a packet
    //
    /// Increments a "reverse" offset which tracks the data that has been previously returned from the end
    fn reverse_read_long(&mut self) -> Option<u32> {
        let data_size = size_of::<u32>();

        if self.get_total_packet_len() < (self.reverse_offset as usize + data_size) {
            return None;
        }

        self.increment_reverse_offset::<u32>();

        let start_index = self.get_total_packet_len() - self.reverse_offset as usize;
        let end_index = start_index + data_size;

        let mut data = self.data.get(start_index..end_index)?;
        let data_to_return = data.read_u32::<BigEndian>().ok()?;

        Some(data_to_return)
    }
}

impl PacketWriter for Packet {
    fn write_buffer(&mut self, mut buffer: Vec<u8>) -> Result<(), Box<dyn std::error::Error>> {
        println!("buffer len is - {}, buffer is - {:?}", buffer.len(), buffer);

        for _ in 0..buffer.len() {
            if let Some(el) = buffer.pop() {
                self.data.put_u8(el);
                self.size += 1;
            }
        }

        Ok(())
    }

    fn write_cmd(&mut self, cmd: Command) -> Result<(), Box<dyn std::error::Error>> {
        let command: u16 = cmd.into();
        let mut buf: Vec<u8> = vec![0; 2];

        LittleEndian::write_u16(&mut buf[..], command);

        self.write_buffer(buf)?;
        self.cmd = Command::try_from_primitive(command)?;

        Ok(())
    }

    fn write_char(&mut self, char: u8) -> Result<(), Box<dyn std::error::Error>> {
        self.write_buffer(vec![char])?;

        Ok(())
    }

    fn write_short(&mut self, data: u16) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0; 2];

        LittleEndian::write_u16(&mut buf[..], data);

        self.write_buffer(buf)?;

        Ok(())
    }

    fn write_long(&mut self, data: u32) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0; 4];

        LittleEndian::write_u32(&mut buf[..], data);
        self.write_buffer(buf)?;

        Ok(())
    }

    fn write_long_long(&mut self, data: u64) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0; 8];

        LittleEndian::write_u64(&mut buf[..], data);
        self.write_buffer(buf)?;

        Ok(())
    }

    fn write_float(&mut self, data: f32) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = vec![0; 4];

        LittleEndian::write_f32(&mut buf[..], data);
        self.write_buffer(buf)?;

        Ok(())
    }

    fn write_sequence(
        &mut self,
        sequence: &[u8],
        len: u16,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut buf = Vec::with_capacity(len as usize);

        println!("len - {}", len);
        self.write_short(len + 1)?;

        buf.push('\0' as u8);

        for i in 0..len as usize {
            if let Some(char) = sequence.get((len as usize) - i - 1) {
                buf.push(*char);
            }
        }

        self.write_buffer(buf)?;

        Ok(())
    }

    fn write_string(&mut self, string: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.write_sequence(string.as_bytes(), string.len() as u16)?;

        Ok(())
    }

    fn build_packet(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let size = (self.data.len() + 4 + 2) as u16; // total data + header + length of the size data itself

        let size_buf = size.to_le_bytes().to_vec();
        let header_buf = self.header.to_le_bytes().to_vec();

        let full_buf = [size_buf, header_buf].concat();

        let mut byte_buffer = BytesMut::from_iter(full_buf);
        let empty_buffer = BytesMut::new();

        let existing_data = std::mem::replace(&mut self.data, empty_buffer);
        byte_buffer.unsplit(existing_data);

        self.data = byte_buffer;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use core::num;
    use std::iter::FromIterator;

    use bytes::BufMut;

    use super::*;

    fn get_test_packet_one() -> BytesMut {
        let data = BytesMut::from_iter(vec![
            0, 40, 128, 0, 0, 0, 5, 234, 0, 7, 107, 105, 108, 108, 116, 49, 0, 0, 6, 76, 111, 99,
            97, 108, 0, 0, 2, 97, 0, 99, 0, 0, 13, 67, 1, 57, 41, 112, 0, 1,
        ]);
        data
    }

    #[test]
    fn it_creates_a_packet_from_bytes() {
        let data = get_test_packet_one();
        let bytes_clone = data.clone();
        let packet = Packet::from_bytes(data);

        assert_eq!(packet.data, bytes_clone);
        assert_eq!(packet.size, 40);
    }

    #[test]
    fn it_reads_a_command_correctly() {
        let data = get_test_packet_one();
        let mut packet = Packet::from_bytes(data);

        let command = packet.read_cmd().unwrap();
        assert_eq!(command, Command::BridgeChatLogs);
    }

    #[test]
    fn it_reads_strings_correctly() {
        let data = get_test_packet_one();
        let mut packet = Packet::from_bytes(data);

        let _ = packet.read_cmd().unwrap();
        let char_name = packet.read_string().unwrap();
        let chat_channel = packet.read_string().unwrap();
        let chat_content = packet.read_string().unwrap();

        assert_eq!(char_name, "killt1");
        assert_eq!(chat_channel, "Local");
        assert_eq!(chat_content, "a");
    }

    #[test]
    fn it_reads_reverse_data_correctly() {
        let data = get_test_packet_one();
        let mut packet = Packet::from_bytes(data);

        let last_char = packet.reverse_read_char().unwrap();
        assert_eq!(last_char, 1);

        let last_short = packet.reverse_read_short().unwrap();
        assert_eq!(last_short, 28672);
    }

    #[test]
    fn it_creates_an_empty_packet() {
        let packet = Packet::new();
        assert_eq!(packet.data, BytesMut::new());
    }

    #[test]
    fn it_builds_a_packet_correctly() {
        let mut w_packet = Packet::new();

        w_packet.write_cmd(Command::BridgeChatLogs).unwrap();
        w_packet.write_short(10).unwrap();
        w_packet.write_long(200).unwrap();
        w_packet.write_string("Hello").unwrap();
        w_packet.write_char('A' as u8).unwrap();
        w_packet.build_packet().unwrap();

        let mut r_packet = w_packet.duplicate();
        assert_eq!(r_packet.read_cmd().unwrap(), Command::BridgeChatLogs);
        assert_eq!(r_packet.read_short().unwrap(), 10);
        assert_eq!(r_packet.read_long().unwrap(), 200);
        assert_eq!(r_packet.read_string().unwrap(), "Hello");
        assert_eq!(r_packet.read_char().unwrap(), 'A' as u8);
    }
}
