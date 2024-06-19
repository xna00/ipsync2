use log::warn;
use serde::{Deserialize, Serialize};

use crate::config::Group;
#[derive(Serialize, Deserialize)]
pub struct E {
    pub name: String,
    pub address: String,
}

pub fn get_local_ips(group: &Group) -> Vec<E> {
    let ifas: Vec<E> = netif::up()
        .unwrap()
        .filter(|ifa| {
            group.interface.contains(&ifa.name().to_string())
                && (ifa.address().is_ipv4() || ifa.scope_id().unwrap() == 0)
        })
        .map(|ifa| E {
            name: ifa.name().to_string(),
            address: ifa.address().to_string(),
        })
        .collect();
    ifas
}

pub fn parse_ips(ips_str: &str) -> Vec<E> {
    let ips: Vec<E> = match serde_json::from_str(ips_str) {
        Ok(ips) => ips,
        Err(e) => {
            warn!("{:?}", e);
            vec![E {
                name: "unknown".to_string(),
                address: ips_str.to_string(),
            }]
        }
    };
    ips
}
