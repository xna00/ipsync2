use std::{
    collections::{HashMap, HashSet},
    str::from_utf8,
};

use crate::ip::parse_ips;
use lettre::{
    message::header::ContentType,
    transport::smtp::{authentication::Credentials, client::TlsParameters},
    Message, SmtpTransport, Transport,
};
use log::{error, info};

use crate::config::Group;

pub fn get_remote_ips(group: &Group) -> imap::error::Result<HashMap<String, HashSet<String>>> {
    let mut ret: HashMap<String, HashSet<String>> = HashMap::new();
    let domain = &group.imap.hostname[..];
    let tls = native_tls::TlsConnector::builder().build().unwrap();

    // we pass in the domain twice to check that the server's TLS
    // certificate is valid for the domain we're connecting to.
    let client = imap::connect((domain, group.imap.port), domain, &tls).unwrap();

    // the client we have here is unauthenticated.
    // to do anything useful with the e-mails, we need to log in
    let mut imap_session = client
        .login(&group.username, &group.password)
        .map_err(|e| e.0)?;

    // we want to fetch the first email in the INBOX mailbox
    imap_session.select("INBOX")?;

    let ips = imap_session.search("SUBJECT ip:")?;
    // for entry in ips  {

    // }
    let t = Vec::from_iter(ips.iter().map(|x| x.to_string())).join(",");
    // println!("{:?}", ips);

    let messages = imap_session.fetch(t, "(BODY[TEXT] BODY[HEADER.FIELDS (SUBJECT)])")?;
    // println!("{:?}", messages);
    for message in &messages {
        let header = message.header().expect("message did not have a header");
        let header = from_utf8(header).expect("").trim().to_string();
        let body = message.text().expect("message did not have a body!");
        let body = std::str::from_utf8(body)
            .expect("message was not valid utf-8")
            .trim()
            .replace("=\r\n", "");
        let t = header.find("[").unwrap();
        let h = &header[(t + 1)..(header.len() - 1)].to_string();
        let ips = parse_ips(&body);
        if !ret.contains_key(h) {
            ret.insert(h.to_string(), HashSet::new());
        }
        ret.get_mut(h)
            .unwrap()
            .extend(ips.iter().map(|x| x.address.to_string()));
        // println!("{}", &header[(t + 1)..(header.len() - 1)]);
        // println!("{:?}, {:?}", header.trim(), body);
    }

    let _ = imap_session.logout();
    Ok(ret)
    // ret
}

pub fn delete_email(group: &Group, hostname: &String) -> imap::error::Result<()> {
    let domain = &group.imap.hostname[..];
    let tls = native_tls::TlsConnector::builder().build().unwrap();

    let client = imap::connect((domain, group.imap.port), domain, &tls).unwrap();

    let mut imap_session = client
        .login(&group.username, &group.password)
        .map_err(|e| e.0)?;

    imap_session.select("INBOX")?;
    let sequence_set = imap_session.search(format!("SUBJECT ip:[{}]", hostname))?;
    // println!("{:?}", sequence_set);
    let t = Vec::from_iter(sequence_set.iter().map(|x| x.to_string())).join(",");
    imap_session.mv(t, "Deleted")
}

pub fn send_mail(group: &Group, subject: String, msg: String) {
    // println!("{:?}", msg);
    let email = Message::builder()
        .from(format!("IpSync <{}>", group.username).parse().unwrap())
        .to(format!("IpSync <{}>", group.username).parse().unwrap())
        .subject(subject)
        .header(ContentType::TEXT_PLAIN)
        .body(msg)
        .unwrap();

    let creds = Credentials::new(group.username.clone(), group.password.clone());

    // Open a remote connection to gmail
    let mailer = SmtpTransport::relay(&group.smtp.hostname)
        .unwrap()
        .port(587)
        .tls(lettre::transport::smtp::client::Tls::Required(
            TlsParameters::new_native(group.smtp.hostname.clone()).unwrap(),
        ))
        .credentials(creds)
        .build();

    // Send the email
    match mailer.send(&email) {
        Ok(_) => info!("Email sent successfully!"),
        Err(e) => error!("Could not send email: {e:?}"),
    }
}
