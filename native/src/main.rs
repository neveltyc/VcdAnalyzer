// Thin CLI wrapper over the vcdidx library core (for debugging the
// builder outside Python): manifest on stdin, stats JSON on
// stdout, errors on stderr with exit code 2.

use std::io::Read;

fn main() {
    let mut manifest = String::new();
    if std::io::stdin().read_to_string(&mut manifest).is_err() {
        eprintln!("vcdidx: cannot read manifest from stdin");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: vcdidx <vcd> <sidecar>");
        std::process::exit(2);
    }
    match vcdidx::build_from_manifest(&manifest, &args[1], &args[2]) {
        Ok(stats) => println!("{}", stats),
        Err(e) => {
            eprintln!("vcdidx: {}", e);
            std::process::exit(2);
        }
    }
}
