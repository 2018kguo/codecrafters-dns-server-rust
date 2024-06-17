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
                let rescode = match incoming_msg.header.opcode {
                    0 => 0,
                    _ => 4,
                };
                reply_header = DnsHeader {
                    id: incoming_msg.header.id,
                    questions: num_questions,
                    answers: 1, 
                    opcode: incoming_msg.header.opcode,
                    recursion_desired: incoming_msg.header.recursion_desired,
                    rescode,
                    response: true,
                    authoritative_answer: false,
                    truncated_message: false,
                    recursion_available: false,
                    z: false,
                    ..reply_header
                };
                let answer_domain = if incoming_msg.questions.len() > 0 {
                    &incoming_msg.questions[0].qname
                } else {
                    "codecrafters.io"
                };
                let answer = DnsAnswer {
                    name: answer_domain.to_string(),
                    qtype: 1,
                    qclass: 1,
                    ttl: 60,
                    rdlength: 4,
                    rdata: vec![8,8, 8, 8],
                };
                let reply_message = DnsMessage {
                    header: reply_header,
                    questions: incoming_msg.questions, // use the same incoming questions
                    answers: vec![answer],
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
