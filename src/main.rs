// Uncomment this block to pass the first stage
use std::net::UdpSocket;
use structs::*;

mod structs;
fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let incoming_msg = DnsMessage::from_bytes(&buf[..size]);
                let num_questions = incoming_msg.header.questions;
                let mut reply_header = DnsHeader::default();
                reply_header = DnsHeader {
                    id: incoming_msg.header.id,
                    questions: num_questions,
                    ..reply_header
                };
                let reply_message = DnsMessage {
                    header: reply_header,
                    questions: incoming_msg.questions, // use the same incoming questions
                };
                udp_socket
                    .send_to(reply_message.to_bytes().as_slice(), source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
