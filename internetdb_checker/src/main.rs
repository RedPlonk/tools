use reqwest;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::env;
use std::error::Error;

#[derive(Deserialize, Serialize, Clone)]
struct InternetDBResponse {
    cpes: Option<Vec<String>>,
    hostnames: Option<Vec<String>>,
    ip: Option<String>,
    ports: Option<Vec<u16>>,
    tags: Option<Vec<String>>,
    vulns: Option<Vec<String>>,
}

impl InternetDBResponse {
    fn display(&self) {
        println!("IP Address: {}", self.ip.as_ref().unwrap_or(&"Unknown IP".to_string()));
        println!("CPEs: {}", self.cpes.as_ref().map_or(String::new(), |c| c.join(", ")));
        println!("Hostnames: {}", self.hostnames.as_ref().map_or(String::new(), |h| h.join(", ")));
        println!("Ports: {}", self.ports.as_ref().map_or(String::new(), |p| p.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(", ")));
        println!("Tags: {}", self.tags.as_ref().map_or(String::new(), |t| t.join(", ")));
        println!("Vulnerabilities: {}", self.vulns.as_ref().map_or(String::new(), |v| v.join(", ")));
    }
}

async fn fetch_and_update_db(conn: &Connection, ip_address: &str) -> Result<(), Box<dyn Error>> {
    let url = format!("https://internetdb.shodan.io/{}", ip_address);
    let response: InternetDBResponse = reqwest::get(&url).await?.json().await?;
    
    if let Some(ip) = &response.ip {
        conn.execute(
            "INSERT OR REPLACE INTO internetdb (ip, cpes, hostnames, ports, tags, vulns)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                ip,
                &serde_json::to_string(&response.cpes.as_ref().unwrap_or(&vec![]))?,
                &serde_json::to_string(&response.hostnames.as_ref().unwrap_or(&vec![]))?,
                &serde_json::to_string(&response.ports.as_ref().unwrap_or(&vec![]))?,
                &serde_json::to_string(&response.tags.as_ref().unwrap_or(&vec![]))?,
                &serde_json::to_string(&response.vulns.as_ref().unwrap_or(&vec![]))?,
            ],
        )?;
    }
    
    response.display();
    Ok(())
}

fn lookup_ip_address(conn: &Connection, ip_address: &str) -> Result<Option<InternetDBResponse>, Box<dyn Error>> {
    let mut stmt = conn.prepare("SELECT ip, cpes, hostnames, ports, tags, vulns FROM internetdb WHERE ip = ?1")?;
    let mut rows = stmt.query(params![ip_address])?;

    if let Some(row) = rows.next()? {
        let response = InternetDBResponse {
            ip: row.get(0)?,
            cpes: serde_json::from_str(&row.get::<_, String>(1)?)?,
            hostnames: serde_json::from_str(&row.get::<_, String>(2)?)?,
            ports: serde_json::from_str(&row.get::<_, String>(3)?)?,
            tags: serde_json::from_str(&row.get::<_, String>(4)?)?,
            vulns: serde_json::from_str(&row.get::<_, String>(5)?)?,
        };
        Ok(Some(response))
    } else {
        Ok(None)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.len() > 3 || (args.len() == 3 && args[1] != "--refresh") {
        eprintln!("Usage: {} [--refresh] <IP Address>", args[0]);
        std::process::exit(1);
    }

    let ip_address = if args.contains(&"--refresh".to_string()) { &args[2] } else { &args[1] };
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
        [],
    )?;

    if args.contains(&"--refresh".to_string()) {
        fetch_and_update_db(&conn, ip_address).await?;
    } else {
        match lookup_ip_address(&conn, ip_address) {
            Ok(Some(response)) => {
                println!("Cached data found:");
                response.display();
            },
            Ok(None) => {
                println!("No cached data found. Fetching new data...");
                fetch_and_update_db(&conn, ip_address).await?;
            },
            Err(e) => return Err(e),
        }
    }

    Ok(())
}

