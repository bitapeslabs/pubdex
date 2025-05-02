use crate::db::get_chain_tip;
use actix_web::{get, web, App, HttpServer};
use colored::Colorize;
// This struct represents state

#[get("/")]
async fn index() -> String {
    match get_chain_tip() {
        Ok(result) => result.to_string(),
        Err(e) => format!("{}: {}", "An error ocurred", e),
    }
}

pub async fn start_api_server() -> Result<(), std::io::Error> {
    let server = HttpServer::new(|| App::new().service(index)).bind(("127.0.0.1", 8080))?;

    println!(
        "{}",
        "API server started successfully on 127.0.0.1:8080"
            .green()
            .bold()
    );

    server.run().await
}
