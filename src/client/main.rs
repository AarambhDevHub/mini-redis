//! Mini Redis Client CLI

use clap::Parser;
use mini_redis::protocol::{Command, Response};
use mini_redis::{Result, TcpClient};
use std::io::{self, Write};
use tracing::error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Server address to connect to
    #[arg(short, long, default_value = "127.0.0.1:6379")]
    server: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().with_target(false).init();

    let args = Args::parse();

    println!("Mini Redis Client");
    println!("Connecting to {}...", args.server);

    let mut client = match TcpClient::connect(&args.server).await {
        Ok(client) => {
            println!("Connected successfully!");
            client
        }
        Err(e) => {
            eprintln!("Failed to connect: {}", e);
            return Err(e);
        }
    };

    // Interactive REPL
    loop {
        print!("mini-redis> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(0) => break, // EOF
            Ok(_) => {
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }

                if input.eq_ignore_ascii_case("quit") || input.eq_ignore_ascii_case("exit") {
                    break;
                }

                match parse_user_input(input) {
                    Ok(command) => match client.execute(command).await {
                        Ok(response) => print_response(response),
                        Err(e) => eprintln!("Error: {}", e),
                    },
                    Err(e) => eprintln!("Parse error: {}", e),
                }
            }
            Err(e) => {
                error!("Failed to read input: {}", e);
                break;
            }
        }
    }

    println!("Goodbye!");
    Ok(())
}

fn parse_user_input(input: &str) -> Result<Command> {
    let args = parse_command_line(input)?;

    if args.is_empty() {
        return Err(mini_redis::Error::Parse("Empty command".to_string()));
    }

    let cmd = args[0].to_uppercase();
    match cmd.as_str() {
        "SET" => {
            if args.len() != 3 {
                return Err(mini_redis::Error::Parse("Usage: SET key value".to_string()));
            }
            Ok(Command::Set {
                key: args[1].clone(),
                value: args[2].clone(),
            })
        }
        "GET" => {
            if args.len() != 2 {
                return Err(mini_redis::Error::Parse("Usage: GET key".to_string()));
            }
            Ok(Command::Get {
                key: args[1].clone(),
            })
        }
        "DEL" => {
            if args.len() != 2 {
                return Err(mini_redis::Error::Parse("Usage: DEL key".to_string()));
            }
            Ok(Command::Del {
                key: args[1].clone(),
            })
        }
        "PING" => Ok(Command::Ping),
        "INFO" => Ok(Command::Info),
        _ => Err(mini_redis::Error::Parse(format!(
            "Unknown command: {}",
            cmd
        ))),
    }
}

/// Parse command line with proper quote handling
fn parse_command_line(input: &str) -> Result<Vec<String>> {
    let mut args = Vec::new();
    let mut current_arg = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            '"' if !in_quotes => {
                in_quotes = true;
            }
            '"' if in_quotes => {
                in_quotes = false;
            }
            ' ' | '\t' if !in_quotes => {
                if !current_arg.is_empty() {
                    args.push(current_arg.clone());
                    current_arg.clear();
                }
            }
            _ => {
                current_arg.push(ch);
            }
        }
    }

    if !current_arg.is_empty() {
        args.push(current_arg);
    }

    if in_quotes {
        return Err(mini_redis::Error::Parse("Unclosed quotes".to_string()));
    }

    Ok(args)
}

fn print_response(response: Response) {
    match response {
        Response::Ok => println!("OK"),
        Response::Value(val) => println!("\"{}\"", val),
        Response::Nil => println!("(nil)"),
        Response::Integer(num) => println!("(integer) {}", num),
        Response::Error(err) => println!("(error) {}", err),
        Response::Pong => println!("PONG"),
        Response::Info(info) => println!("{}", info),
    }
}
