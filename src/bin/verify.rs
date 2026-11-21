mod verification;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::WARN.into()),
        )
        .init();

    std::process::exit(verification::run(&std::env::args().collect::<Vec<_>>()));
}
