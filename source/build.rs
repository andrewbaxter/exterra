fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(
        &[
            "terraform-plugin-go/tfprotov5/internal/tfplugin5/tfplugin5.proto",
            "terraform-plugin-go/tfprotov6/internal/tfplugin6/tfplugin6.proto",
        ],
        &[
            "terraform-plugin-go/tfprotov5/internal",
            "terraform-plugin-go/tfprotov6/internal",
        ],
    )?;
    tonic_build::configure()
        .build_server(false)
        .compile_fds(fds)?;
    Ok(())
}
