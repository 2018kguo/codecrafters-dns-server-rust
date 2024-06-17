#![allow(dead_code)]

#[derive(Debug, Clone)]
pub struct DnsHeader {
    pub id: u16,
    pub response: bool,
    pub recursion_desired: bool,
    pub truncated_message: bool,
    pub authoritative_answer: bool,
    pub opcode: u8,
    pub rescode: u8,
    pub checking_disabled: bool,
    pub authed_data: bool,
    pub z: bool,
    pub recursion_available: bool,
    pub questions: u16,
    pub answers: u16,
    pub authoritative_entries: u16,
    pub resource_entries: u16,
}

impl Default for DnsHeader {
    fn default() -> Self {
        DnsHeader {
            id: 1234,
            recursion_desired: false,
            truncated_message: false,
            authoritative_answer: false,
            opcode: 0,
            response: true,
            rescode: 0,
            checking_disabled: false,
            authed_data: false,
            z: false,
            recursion_available: false,
            questions: 0,
            answers: 0,
            authoritative_entries: 0,
            resource_entries: 0,
        }
    }
}

impl DnsHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        let first_flag_bytes = (self.response as u8) << 7
            | (self.opcode & 0b1111) << 3
            | (self.authoritative_answer as u8) << 2
            | (self.truncated_message as u8) << 1
            | self.recursion_desired as u8;
        bytes.push(first_flag_bytes);
        let second_flag_bytes = (self.checking_disabled as u8) << 7
            | (self.authed_data as u8) << 5
            | (self.z as u8) << 4
            | (self.recursion_available as u8) << 3
            | self.rescode;
        bytes.push(second_flag_bytes);
        bytes.extend_from_slice(&self.questions.to_be_bytes());
        bytes.extend_from_slice(&self.answers.to_be_bytes());
        bytes.extend_from_slice(&self.authoritative_entries.to_be_bytes());
        bytes.extend_from_slice(&self.resource_entries.to_be_bytes());
        assert!(bytes.len() == 12, "DnsHeader is not 12 bytes long");
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> DnsHeader {
        assert!(bytes.len() == 12, "DnsHeader is not 12 bytes long");
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let first_flag_bytes = bytes[2];
        let response = first_flag_bytes & 0b1000_0000 != 0;
        let opcode = (first_flag_bytes & 0b0111_1000) >> 3;
        let authoritative_answer = first_flag_bytes & 0b0000_0100 != 0;
        let truncated_message = first_flag_bytes & 0b0000_0010 != 0;
        let recursion_desired = first_flag_bytes & 0b0000_0001 != 0;
        let second_flag_bytes = bytes[3];
        let checking_disabled = second_flag_bytes & 0b1000_0000 != 0;
        let authed_data = second_flag_bytes & 0b0100_0000 != 0;
        let z = second_flag_bytes & 0b0010_0000 != 0;
        let recursion_available = second_flag_bytes & 0b0001_0000 != 0;
        let rescode = second_flag_bytes & 0b0000_1111;
        let questions = u16::from_be_bytes([bytes[4], bytes[5]]);
        let answers = u16::from_be_bytes([bytes[6], bytes[7]]);
        let authoritative_entries = u16::from_be_bytes([bytes[8], bytes[9]]);
        let resource_entries = u16::from_be_bytes([bytes[10], bytes[11]]);
        DnsHeader {
            id,
            response,
            recursion_desired,
            truncated_message,
            authoritative_answer,
            opcode,
            rescode,
            checking_disabled,
            authed_data,
            z,
            recursion_available,
            questions,
            answers,
            authoritative_entries,
            resource_entries,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsQuestion {
    pub qname: String, // the domain name that is being queried
    pub qtype: u16,    // 2 bytes, the type of record being queried (A, MX, CNAME, etc.)
    pub qclass: u16,   // the class of the query (usually IN for internet)
}

impl DnsQuestion {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut qname_bytes = Vec::new();
        // labels are encoded as a byte for the length of the label followed by the label itself
        for label in self.qname.split('.') {
            qname_bytes.push(label.len() as u8);
            qname_bytes.extend_from_slice(label.as_bytes());
        }
        qname_bytes.push(0); // null byte to terminate the domain name
        bytes.extend_from_slice(&qname_bytes);
        bytes.extend_from_slice(&self.qtype.to_be_bytes());
        bytes.extend_from_slice(&self.qclass.to_be_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> DnsQuestion {
        let mut qname = String::new();
        let mut i = 0;
        loop {
            let label_len = bytes[i] as usize;
            if label_len == 0 {
                break;
            }
            if i != 0 {
                qname.push('.');
            }
            qname.push_str(
                std::str::from_utf8(&bytes[i + 1..i + 1 + label_len])
                    .expect("Invalid UTF-8 in domain name"),
            );
            i += label_len + 1;
        }
        assert!(bytes[i] == 0, "Domain name is not null-terminated");
        i += 1; // skip the null byte
        let qtype = u16::from_be_bytes([bytes[i], bytes[i + 1]]);
        assert!(1 <= qtype && qtype <= 16, "Invalid qtype");
        let qclass = u16::from_be_bytes([bytes[i + 2], bytes[i + 3]]);
        assert!(qclass == 1, "Invalid qclass");
        DnsQuestion {
            qname,
            qtype,
            qclass,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
}

impl DnsMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.header.to_bytes());
        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> DnsMessage {
        let header = DnsHeader::from_bytes(&bytes[..12]);
        let num_questions = header.questions as usize;
        let mut questions = Vec::new();
        let mut i = 12;
        for _ in 0..num_questions {
            let question = DnsQuestion::from_bytes(&bytes[i..]);
            questions.push(question.clone());
            i += question.to_bytes().len();
        }
        DnsMessage { header, questions }
    }
}
