use hickory_proto::rr::{Name, RecordType};

pub fn make_cache_key(name: &Name, qtype: RecordType) -> String {
    let formatted_name = name.to_ascii().trim_end_matches(".").to_lowercase();
    format!("{}|{}", formatted_name, u16::from(qtype))
}