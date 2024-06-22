// Uncomment this block to pass the first stage
use std::net::UdpSocket;
use structs::*;

mod structs;
fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 1024]; // not implementing proper message buffering for now
    let args = std::env::args().collect::<Vec<String>>();

    let resolver_arg_index = args.iter().position(|arg| arg == "--resolver");
    let resolver_address = match resolver_arg_index {
        Some(index) => Some(args.get(index + 1).expect("Missing resolver address")),
        None => None,
    };

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
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
                    answers: num_questions,
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
                let mut answers = Vec::new();
                if resolver_address.is_none() {
                    let answer_domain = if !incoming_msg.questions.is_empty() {
                        &incoming_msg.questions[0].qname
                    } else {
                        "codecrafters.io"
                    };

                    for _ in 0..num_questions {
                        let answer = make_answer(answer_domain);
                        answers.push(answer);
                    }
                } else {
                    let resolver_address = resolver_address.as_ref().unwrap();
                    //let unwrapped_resolver_socket = resolver_socket.as_ref().unwrap();
                    // the resolver will only respond to one question at a time so we need to iterate over all questions
                    let question_header = DnsHeader {
                        id: incoming_msg.header.id, // preserve the packet id that we originally received
                        questions: 1,
                        answers: 0,
                        opcode: incoming_msg.header.opcode,
                        recursion_desired: incoming_msg.header.recursion_desired,
                        rescode: 0,
                        response: false,
                        authoritative_answer: false,
                        truncated_message: false,
                        recursion_available: false,
                        z: false,
                        ..DnsHeader::default()
                    };
                    for question in incoming_msg.questions.iter() {
                        let cloned_question = question.clone();
                        let forwarded_message = DnsMessage {
                            header: question_header.clone(),
                            questions: vec![cloned_question],
                            answers: Vec::new(),
                        };
                        let mut resolver_buf = [0; 1024];
                        // forward the question to the resolver
                        // and wait for the response
                        udp_socket
                            .send_to(forwarded_message.to_bytes().as_slice(), resolver_address)
                            .expect("Failed to send to resolver");
                        let (resolver_size, _) = udp_socket
                            .recv_from(&mut resolver_buf)
                            .expect("Failed to receive from resolver");
                        let resolver_msg = DnsMessage::from_bytes(&resolver_buf[..resolver_size]);
                        // extract the answers from the resolver response
                        // and add them to the response we will send back to the client
                        for answer in resolver_msg.answers.iter() {
                            answers.push(answer.clone());
                        }
                    }
                }
                let reply_message = DnsMessage {
                    header: reply_header,
                    questions: incoming_msg.questions, // use the same incoming questions
                    answers,
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

fn make_answer(domain: &str) -> DnsAnswer {
    DnsAnswer {
        name: domain.to_string(),
        qtype: 1,
        qclass: 1,
        ttl: 60,
        rdlength: 4,
        rdata: vec![8, 8, 8, 8],
    }
}
