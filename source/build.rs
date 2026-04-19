fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(
        &["proto/tfplugin5.proto", "proto/tfplugin6.proto"],
        &["proto"],
    )?;
    tonic_build::configure()
        .build_server(false)
        .compile_fds(fds)?;
    Ok(())
}
