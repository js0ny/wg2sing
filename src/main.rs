use clap::{ArgAction, Parser, builder::NonEmptyStringValueParser};
use ini::Ini;
use std::error::Error;
use std::path::PathBuf;
use wg2sing::{convert, format_output};

#[derive(Parser)]
struct Cli {
    #[arg(value_name = "PATH_TO_WG_INI", help = "WireGuard INI configuration")]
    path: PathBuf,
    #[arg(long, action = ArgAction::Set, require_equals = true, default_value_t = false, help = "Use system networking")]
    system: bool,
    #[arg(long, require_equals = true, value_parser = NonEmptyStringValueParser::new(), help = "Endpoint tag (defaults to the file stem)")]
    tag: Option<String>,
    #[arg(long = "wrap", help = "Wrap the endpoint in an endpoints array")]
    wrap_endpoints: bool,
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let config = Ini::load_from_file(&cli.path)?;
    let tag = cli.tag.unwrap_or_else(|| {
        cli.path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .filter(|stem| !stem.is_empty())
            .unwrap_or("wireguard")
            .to_owned()
    });
    let endpoint = convert(&config, tag, cli.system)?;
    println!("{}", format_output(&endpoint, cli.wrap_endpoints)?);
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn parses_cli_options_in_any_order() {
        let cli = Cli::try_parse_from([
            "wg2sing",
            "--tag=my-tunnel",
            "example.ini",
            "--system=true",
            "--wrap",
        ])
        .unwrap();
        assert_eq!(cli.path, Path::new("example.ini"));
        assert_eq!(cli.tag.as_deref(), Some("my-tunnel"));
        assert!(cli.system);
        assert!(cli.wrap_endpoints);

        let cli = Cli::try_parse_from(["wg2sing", "--system=false", "example.ini"]).unwrap();
        assert!(!cli.system);
        assert!(cli.tag.is_none());
        assert!(!cli.wrap_endpoints);
    }

    #[test]
    fn rejects_invalid_cli_options() {
        for args in [
            vec!["wg2sing", "--system=yes", "example.ini"],
            vec!["wg2sing", "--tag=", "example.ini"],
            vec!["wg2sing", "--unknown", "example.ini"],
            vec!["wg2sing", "--tag=a", "--tag=b", "example.ini"],
            vec!["wg2sing", "--system=true", "--system=false", "example.ini"],
            vec!["wg2sing", "--wrap", "--wrap", "example.ini"],
            vec!["wg2sing", "example.ini", "extra.ini"],
            vec!["wg2sing"],
        ] {
            assert!(Cli::try_parse_from(args).is_err());
        }
    }
}
