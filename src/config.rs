use std::{env, fs::File, io::Read};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct MailConfig {
    pub hostname: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
pub struct Group {
    pub username: String,
    pub password: String,
    pub imap: MailConfig,
    pub smtp: MailConfig,
    pub hostnames: Vec<String>,
    pub interface: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub groups: Vec<Group>,
    pub interval: u64,
}

pub const DEFAULT_CONFIG: &str = r#"{
    "groups": [
      {
        "username": "xxx@outlook.com",
        "password": "yyy",
        "imap": {
          "hostname": "outlook.office365.com",
          "port": 993
        },
        "smtp": {
          "hostname": "smtp.office365.com",
          "port": 587
        },
        "hostnames": ["abc"],
        "interface": ["en0"]
      }
    ],
    "interval": 180
}
"#;

pub fn get_config() -> Config {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];

    let mut file = File::open(path).expect("Config file is not existed!");

    let mut contents = String::new();

    let _ = file.read_to_string(&mut contents);

    let config: Config = serde_json::from_str(&contents).expect("Parse error");

    config
}
