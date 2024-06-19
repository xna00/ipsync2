use std::{
    collections::{HashMap, HashSet},
    env,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    path::Path,
    thread::sleep,
    time::Duration,
};

use config::{get_config, DEFAULT_CONFIG};
use env_logger::Builder;
use ip::get_local_ips;
use log::{error, info, warn};
use mail::{delete_email, get_remote_ips, send_mail};
use regex::Regex;

mod config;
mod ip;
mod mail;

extern crate log;

fn daemonize() -> io::Result<()> {
    let _ = match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(()),
        pid => {
            info!("Child process: {}", pid);
            std::process::exit(0)
        }
    };

    unsafe { libc::setsid() };

    env::set_current_dir("/")
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to change directory"))?;

    // Redirect standard file descriptors to /dev/null
    let null_fd = File::open(Path::new("/dev/null"))
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Failed to open /dev/null"))?;
    unsafe {
        libc::dup2(null_fd.as_raw_fd(), libc::STDIN_FILENO);
        libc::dup2(null_fd.as_raw_fd(), libc::STDOUT_FILENO);
        libc::dup2(null_fd.as_raw_fd(), libc::STDERR_FILENO);
    }

    Ok(())
}
fn main() {
    println!("Hello, world!");

    if let Some(i) = env::args().nth(1) {
        if i == "init" {
            let mut file = File::create("./config.json").expect("Can't create file");
            file.write_all(DEFAULT_CONFIG.as_bytes())
                .expect("Can't write file");
            return;
        }
    }
    let log_file = env::var("PREFIX").unwrap_or("".to_string()) + "/var/log/ipsync.log";
    let target = Box::new(File::create(log_file).expect("Can't create file"));

    Builder::new()
        .filter_level(log::LevelFilter::max())
        .target(env_logger::Target::Pipe(target))
        .init();

    log::info!("Start log...");

    let binding = env::var("PREFIX").unwrap_or("".to_string()) + "/var/run/ipsync.pid";
    let pid_file = Path::new(&binding);

    // Check if the daemon is already running
    if let Ok(contents) = File::open(pid_file).and_then(|mut f| {
        let mut s = String::new();
        f.read_to_string(&mut s).map(|_| s)
    }) {
        let pid: i32 = contents.trim().parse().unwrap_or(0);
        if pid > 0 && unsafe { libc::kill(pid, 0) } != -1 {
            warn!("Daemon is already running.");
            if (unsafe { libc::kill(pid, libc::SIGTERM) } == -1) {
                println!("Stop fail");
                return;
            } else {
                println!("Stop success");
            }
        }
    }
    daemonize().expect("Failed to daemonize");
    let pid = unsafe { libc::getpid() };
    let mut file = File::create(pid_file).expect("Failed to create PID file");
    writeln!(file, "{}", pid).expect("Failed to write PID file");
    loop {
        let config = get_config();
        let path = "/etc/hosts";

        let mut file = File::open(path).expect("Config file is not existed!");

        let mut contents = String::new();

        let _ = file.read_to_string(&mut contents);

        info!("{}", contents);
        let ip_re = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b|\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9]{1,4}\b").unwrap();
        let a: Vec<_> = contents
            .split("\n")
            .map(|line| line.trim())
            .filter(|line| !line.is_empty())
            .map(|line| {
                let mut ret = Regex::new(r"\s+")
                    .unwrap()
                    .split(line)
                    .collect::<Vec<&str>>();
                ret.reverse();
                ret
            })
            .filter(|v| v.len() == 2 && ip_re.is_match(v[1]))
            .map(|v| (v[0], v[1]))
            .collect();
        info!("{:?}", a);

        let mut ip_map: HashMap<String, HashSet<String>> = HashMap::new();

        for group in &config.groups {
            let remote_ip_val = get_remote_ips(&group);
            let local_ip_val = get_local_ips(group);
            let mut send = false;

            let t = match remote_ip_val {
                Ok(v) => v,
                Err(e) => {
                    error!("{:?}", e);
                    HashMap::new()
                }
            };
            for (k, v) in t.iter() {
                let a = v.iter().cloned().collect::<HashSet<String>>();
                match ip_map.get_mut(k) {
                    Some(v) => {
                        v.extend(a);
                    }
                    None => {
                        ip_map.insert(k.clone(), a);
                    }
                }
            }
            for hostname in group.hostnames.iter() {
                let empty = HashSet::new();
                let r: &HashSet<String> = t.get(hostname).unwrap_or(&empty);
                if !(local_ip_val.iter().all(|ip| r.contains(&ip.address))
                    && r.iter()
                        .all(|ip| local_ip_val.iter().any(|ip2| ip2.address == *ip)))
                {
                    // println!("{:?}", hostname);
                    send = true;
                }
            }
            info!("{}", serde_json::to_string(&local_ip_val).unwrap());
            if send {
                for t in group.hostnames.iter() {
                    let _ = delete_email(group, t);
                    send_mail(
                        group,
                        format!("ip:[{}]", t).to_string(),
                        serde_json::to_string(&local_ip_val).unwrap(),
                    );
                }
            }
        }

        let _ = config
            .groups
            .iter()
            .flat_map(|group| group.hostnames.clone())
            .for_each(|hostname| {
                let _ = ip_map.insert(hostname, HashSet::from(["127.0.0.1".to_string()]));
            });
        let new_keys: HashSet<_> = a
            .iter()
            .map(|v| v.0)
            .filter(|k| !ip_map.contains_key(*k))
            .collect();

        for k in new_keys {
            let ips = a.iter().filter(|v| v.0 == k).map(|v| v.1.to_string());
            let _ = ip_map.insert(k.to_string(), HashSet::from_iter(ips));
        }

        info!("{:?}", ip_map);

        let hosts = ip_map
            .iter()
            .map(|(k, v)| {
                let mut ret = v
                    .iter()
                    .map(|v| format!("{} {}", v, k).to_string())
                    .collect::<Vec<String>>();
                ret.sort_by(|a, b| b.len().cmp(&a.len()));
                ret
            })
            .flatten()
            .collect::<Vec<String>>()
            .join("\n");
        info!("{}", hosts);

        let file = File::create(path);
        match file {
            Ok(mut file) => {
                info!("Write to /etc/hosts");
                let _ = file.write_all(hosts.as_bytes());
            }
            Err(e) => {
                error!("{:?}", e);
            }
        };

        sleep(Duration::from_secs(config.interval));
    }
}
