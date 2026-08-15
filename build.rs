fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/");
    let fds = protox::compile(
        ["proto/polo.proto", "proto/remotemessage.proto"],
        ["proto/"],
    )?;
    prost_build::Config::new().compile_fds(fds)?;
    Ok(())
}
