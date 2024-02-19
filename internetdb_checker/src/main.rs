use reqwest;
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;
use trust_dns_resolver::TokioAsyncResolver;

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
    fn display(&self) {
        println!("IP Address: {}", self.ip);
        println!("CPEs: {}", self.cpes.as_ref().map_or_else(|| "None".to_string(), |c| c.join(", ")));
        println!("Hostnames: {}", self.hostnames.as_ref().map_or_else(|| "None".to_string(), |h| h.join(", ")));
        println!("Ports: {}", self.ports.as_ref().map_or_else(|| "None".to_string(), |p| p.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
        println!("Tags: {}", self.tags.as_ref().map_or_else(|| "None".to_string(), |t| t.join(", ")));
        println!("Vulnerabilities: {}", self.vulns.as_ref().map_or_else(|| "None".to_string(), |v| v.join(", ")));
    }
}

async fn fetch_and_update_db(conn: &Connection, ip: &str) -> Result<(), Box<dyn Error>> {
    let url = format!("https://internetdb.shodan.io/{}", ip);
    let response: InternetDBResponse = reqwest::get(url).await?.json().await?;
    
    conn.execute(
        "INSERT OR REPLACE INTO internetdb (ip, cpes, hostnames, ports, tags, vulns)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            &response.ip,
            &serde_json::to_string(&response.cpes)?,
            &serde_json::to_string(&response.hostnames)?,
            &serde_json::to_string(&response.ports)?,
            &serde_json::to_string(&response.tags)?,
            &serde_json::to_string(&response.vulns)?,
        ],
    )?;
    
    response.display();
    Ok(())
}

async fn process_address(conn: &Connection, address: &str) -> Result<(), Box<dyn Error>> {
    let resolver = TokioAsyncResolver::tokio_from_system_conf()?; // Correction applied here
    match resolver.lookup_ip(address).await {
        Ok(lookup) => {
            for ip in lookup.iter() {
                fetch_and_update_db(conn, &ip.to_string()).await?;
            }
        },
        Err(_) => {
            fetch_and_update_db(conn, address).await?;
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

    let refresh_flag = args[1] == "--refresh";
    let addresses = if refresh_flag { &args[2..] } else { &args[1..] };

    let conn = Connection::open("internetdb.db")?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS internetdb (
            ip TEXT PRIMARY KEY,
            cpes TEXT,
            hostnames TEXT,
            ports TEXT,
            tags TEXT,
            vulns TEXT
        )",
        params![],
    )?;

    for address in addresses {
        println!("Queued: {}", address);
        process_address(&conn, address).await?;
    }

    Ok(())
}
