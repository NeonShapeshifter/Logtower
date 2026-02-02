use clap::Parser;
use evtx::EvtxParser;
use evtx::ParserSettings;
use std::path::PathBuf;
use std::io::{self, Write};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the EVTX file
    #[arg(value_name = "FILE")]
    file: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let fp = args.file;

    if !fp.exists() {
        eprintln!("File not found: {:?}", fp);
        std::process::exit(1);
    }

    // Default settings with multithreading enabled
    let settings = ParserSettings::default().num_threads(0); // 0 = auto-detect

    let mut parser = EvtxParser::from_path(fp)
        .map_err(|e| anyhow::anyhow!("Failed to open EVTX file: {}", e))?
        .with_configuration(settings);

    let stdout = io::stdout();
    let mut handle = stdout.lock();

    // Iterate over records. The parser handles threading internally for parsing,
    // but the iterator yields results sequentially if needed, or we can consume in parallel.
    // The evtx crate's `records_json()` output is already quite fast.
    // It returns Result<Obj<String>>.
    
    for record_result in parser.records_json() {
        match record_result {
            Ok(record) => {
                // record.data is a String (pretty printed by default in some versions or depending on features)
                // To be safe and ensure single-line JSONL, we parse and re-serialize.
                // This is a bit inefficient but guarantees the contract.
                // Alternatively, we could check if evtx crate has a setting for compact JSON.
                // It does not seem to expose it easily in the iterator.
                
                if let Ok(json_val) = serde_json::from_str::<serde_json::Value>(&record.data) {
                    if let Ok(minified) = serde_json::to_string(&json_val) {
                        writeln!(handle, "{}", minified)?;
                    }
                }
            }
            Err(e) => {
                eprintln!("Error parsing record: {}", e);
            }
        }
    }

    Ok(())
}