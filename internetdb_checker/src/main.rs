use reqwest;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use trust_dns_resolver::TokioAsyncResolver;
use uuid::Uuid;
use bs58;

#[derive(Deserialize, Serialize, Clone, Debug)]
struct InternetDBResponse {
    cpes: Option<Vec<String>>,
    hostnames: Option<Vec<String>>,
    ip: String,
    ports: Option<Vec<u16>>,
    tags: Option<Vec<String>>,
    vulns: Option<Vec<String>>,
}

impl InternetDBResponse {
    fn display(&self, uuid: &str) {
        println!("UUID: {}", uuid);
        println!("IP Address: {}", self.ip);
        // Further implementation...
    }
}

async fn fetch_and_update_db(conn: &Connection, ip: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let response: InternetDBResponse = reqwest::get(&url).await?.json().await?;
    let uuid = Uuid::new_v4();
    let uuid_b58 = bs58::encode(uuid.as_bytes()).into_string();

    conn.execute(
        "INSERT INTO internetdb (uuid, ip, cpes, hostnames, ports, tags, vulns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(ip) DO UPDATE SET
         cpes=excluded.cpes,
         hostnames=excluded.hostnames,
         ports=excluded.ports,
         tags=excluded.tags,
         vulns=excluded.vulns",
        params![
            &uuid_b58,
            &response.ip,
            &serde_json::to_string(&response.cpes)?,
            &serde_json::to_string(&response.hostnames)?,
            &serde_json::to_string(&response.ports)?,
            &serde_json::to_string(&response.tags)?,
            &serde_json::to_string(&response.vulns)?,
        ],
    )?;

    Ok(uuid_b58)
}

async fn process_address(conn: &Connection, address: &str) -> Result<(), Box<dyn Error>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?;
    match resolver.lookup_ip(address).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                let uuid_b58 = fetch_and_update_db(conn, &ip.to_string()).await?;
                println!("Processed IP: {} with UUID: {}", ip, uuid_b58);
            }
        },
        Err(_) => {
            let uuid_b58 = fetch_and_update_db(conn, address).await?;
            println!("Processed address: {} with UUID: {}", address, uuid_b58);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} [--refresh] <IP Address/FQDN>...", args[0]);
        return Err("Invalid arguments".into());
    }

    let conn = Connection::open("internetdb.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS internetdb (
            uuid TEXT PRIMARY KEY,
            ip TEXT UNIQUE,
            cpes TEXT,
            hostnames TEXT,
            ports TEXT,
            tags TEXT,
            vulns TEXT
        )",
        [],
    )?;

    let refresh_flag = args[1] == "--refresh";
    let addresses = if refresh_flag { &args[2..] } else { &args[1..] };

    for address in addresses {
        process_address(&conn, address).await?;
    }

    Ok(())
}
