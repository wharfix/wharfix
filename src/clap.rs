use clap::{arg, command, crate_authors, Command};

pub fn build_cli() -> Command {
    command!()
        .author(crate_authors!("\n"))
        .arg(
            arg!(--path <PATH> "Path to directory of static docker image specs.")
                .required_unless_present_any(["repo", "dbconnfile", "derivation_output"]),
        )
        .arg(
            arg!(--repo <REPO> "URL to git repository.")
                .required_unless_present_any([
                "path",
                "dbconnfile",
                "derivation_output",
            ]),
        )
        .arg(
            arg!(--derivation_output <DERIVATIONOUTPUT> "Output which servable derivations need to produce to be valid.")
                .required_unless_present_any([
                    "path",
                    "dbconnfile",
                    "repo",
                ]),
        )
        .arg(
            arg!(--target <TARGET> "Target path in which to checkout repos.")
                .default_value("/tmp/wharfix")
                .required(false)
        )
        .arg(
            arg!(--blob_cache_dir <BLOBCACHEDIR> "Directory in which to store persitent symlinks to docker layer blobs.")
                .required(false)
        )
        .arg(
            arg!(--substituters <SUBSTITUTERS> "Comma-separated list of nix substituters to pass directly to nix-build as 'substituters'.")
                .required(false)
        )
        .arg(
            arg!(--index_file_path <INDEXFILEPATH> "Path to repository index file.")
                .default_value("default.nix")
                .required(false)
        )
        .arg(
            arg!(--index_file_is_buildable "Set if the provided index-file is a valid nix entrypoint by itself (i.e. don't use internal drv-wrapper).")
                .required(false)
        )
        .arg(
            arg!(--ssh_private_key <SSHPRIVATEKEY> "Path to optional ssh private key file.")
                .required(false)
        )
        .arg(
            arg!(--add_nix_gcroots "Whether to add nix gcroots for blobs cached in blob cache dir.")
                .required(false)
                .requires("blob_cache_dir")
        )
        .arg(
            arg!(--address <ADDRESS> "Listen address to open on <port>.")
                .required(false)
                .default_value("0.0.0.0")
        )
        .arg(
            arg!(--port <PORT> "Listen port to open on <address>.")
                .required(true)
                .default_value("8088")
        )
        .arg(
            arg!(--dbconnfile <DBCONNFILE> "Path to file from which to read db connection details.")
                .required_unless_present_any([
                    "path",
                    "repo",
                    "derivation_output",
                ]),
        )
}

/*
    let args = clap::App::new("wharfix")
    .arg(clap::Arg::with_name("path")
        .long("path")
        .help("Path to directory of static docker image specs")
        .takes_value(true)
        .required_unless_one(&["repo", "dbconnfile", "derivationoutput"]))

    .arg(clap::Arg::with_name("repo")
        .long("repo")
        .help("URL to git repository")
        .takes_value(true)
        .required_unless_one(&["path", "dbconnfile", "derivationoutput"]))
    .arg(clap::Arg::with_name("derivationoutput")
        .long("derivation-output")
        .help("Output which servable derivations need to produce to be valid")
        .takes_value(true)
        .required_unless_one(&["path", "repo", "dbconnfile"]))
    .arg(clap::Arg::with_name("target")
        .long("target")
        .help("Target path in which to checkout repos")
        .default_value("/tmp/wharfix")
        .required(false))

    .arg(clap::Arg::with_name("blobcachedir")
        .long("blob-cache-dir")
        .help("Directory in which to store persitent symlinks to docker layer blobs")
        .takes_value(true)
        .required(false))
    .arg(clap::Arg::with_name("substituters")
        .long("substituters")
        .help("Comma-separated list of nix substituters to pass directly to nix-build as 'substituters'")
        .takes_value(true)
        .required(false))

    .arg(clap::Arg::with_name("indexfilepath")
        .long("index-file-path")
        .help("Path to repository index file")
        .default_value("default.nix")
        .takes_value(true)
        .required(false))

    .arg(clap::Arg::with_name("indexfileisbuildable")
        .long("index-file-is-buildable")
        .help("Set if the provided index-file is a valid nix entrypoint by itself (i.e. don't use internal drv-wrapper)")
        .takes_value(false)
        .required(false))

    .arg(clap::Arg::with_name("sshprivatekey")
        .long("ssh-private-key")
        .help("Path to optional ssh private key file")
        .takes_value(true)
        .required(false))

    .arg(clap::Arg::with_name("addnixgcroots")
        .long("add-nix-gcroots")
        .help("Whether to add nix gcroots for blobs cached in blob cache dir")
        .takes_value(false)
        .required(false)
        .requires("blobcachedir"))

    .arg(clap::Arg::with_name("address")
        .long("address")
        .help("Listen address to open on <port>")
        .default_value("0.0.0.0")
        .required(false))

    .arg(clap::Arg::with_name("port")
        .long("port")
        .help("Listen port to open on <address>")
        .default_value("8088")
        .required(true));

    TODO: THIS PART
    #[cfg(feature = "mysql")]
    let args = args.arg(clap::Arg::with_name("dbconnfile")
        .long("dbconnfile")
        .help("Path to file from which to read db connection details")
        .takes_value(true)
        .required_unless_one(&["path", "repo", "derivationoutput"]));
*/
