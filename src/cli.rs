use clap::{arg, command, crate_authors, Command};

pub fn build_cli() -> Command {
    let cmd = command!()
        .author(crate_authors!("\n"))
        .arg(
            arg!(--path <PATH> "Path to directory of static docker image specs.")
                .required_unless_present_any(["repo", "derivationoutput"]),
        )
        .arg(
            arg!(--repo <REPO> "URL to git repository.")
                .required_unless_present_any([
                "path",
                "derivationoutput",
            ]),
        )
        .arg(
            arg!(derivationoutput: <DERIVATIONOUTPUT> "Output which servable derivations need to produce to be valid.")
                .long("derivation-output")
                .required(false)
                .required_unless_present_any([
                    "path",
                    "repo",
                ]),
        )
        .arg(
            arg!(--target <TARGET> "Target path in which to checkout repos.")
                .default_value("/tmp/wharfix")
                .required(false)
        )
        .arg(
            arg!(blobcachedir: <BLOBCACHEDIR> "Directory in which to store persitent symlinks to docker layer blobs.")
                .long("blob-cache-dir")
                .required(false)
        )
        .arg(
            arg!(--substituters <SUBSTITUTERS> "Comma-separated list of nix substituters to pass directly to nix-build as 'substituters'.")
                .required(false)
        )
        .arg(
            arg!(indexfilepath: <INDEXFILEPATH> "Path to repository index file.")
                .long("index-file-path")
                .default_value("default.nix")
                .required(false)
        )
        .arg(
            arg!(indexfileisbuildable: "Set if the provided index-file is a valid nix entrypoint by itself (i.e. don't use internal drv-wrapper).")
                .action(clap::ArgAction::SetTrue)
                .long("index-file-is-buildable")
                .required(false)
        )
        .arg(
            arg!(sshprivatekey:<SSHPRIVATEKEY> "Path to optional ssh private key file.")
                .long("ssh-private-key")
                .required(false)
        )
        .arg(
            arg!(addnixgcroots: "Whether to add nix gcroots for blobs cached in blob cache dir.")
                .long("add-nix-gcroots")
                .action(clap::ArgAction::SetTrue)
                .required(false)
                .requires("blobcachedir")
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
        );

        #[cfg(feature = "mysql")]
        let cmd = cmd.arg(
            arg!(--dbconnfile <DBCONNFILE> "Path to file from which to read db connection details.")
                .required_unless_present_any([
                    "path",
                    "repo",
                    "derivationoutput",
                ]),
        );
        cmd
}
