#![warn(clippy::pedantic, clippy::nursery, clippy::all, clippy::cargo)]
#![allow(clippy::multiple_crate_versions, clippy::module_name_repetitions)]

use anyhow::Result;
use arti_client::{TorClient, TorClientConfig};
use axum::{routing::get, Router};
use futures::StreamExt;
use hyper::{body::Incoming, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use native_tls::Identity;
use safelog::sensitive;
use tokio_native_tls::TlsAcceptor;
use tor_cell::relaycell::msg::Connected;
use tor_hsservice::{config::OnionServiceConfigBuilder, StreamRequest};
use tor_proto::stream::IncomingStreamRequest;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;
use tower_service::Service;

#[tokio::main]
async fn main() {
	// Make sure you read doc/OnionService.md to extract your Onion service hostname

	// Arti uses the `tracing` crate for logging. Install a handler for this, to
	// print Arti's logs. (You'll need to set RUST_LOG=info as an environment
	// variable to actually see much; also try =debug for more detailed logging.)
	tracing_subscriber::fmt::init();

	// Initialize web server data, if you need to
	//let handler = Arc::new(WebHandler { shutdown: CancellationToken::new() });

	// The client config includes things like where to store persistent Tor network
	// state. The defaults provided are the same as the Arti standalone
	// application, and save data to a conventional place depending on operating
	// system (for example, ~/.local/share/arti on Linux platforms)
	let config = TorClientConfig::default();

	// We now let the Arti client start and bootstrap a connection to the network.
	// (This takes a while to gather the necessary consensus state, etc.)
	let client = TorClient::with_runtime(TokioNativeTlsRuntime::current().unwrap());
	let client = client.config(config).create_bootstrapped().await.unwrap();

	let svc_cfg = OnionServiceConfigBuilder::default().nickname("allium-ampeloprasum".parse().unwrap()).build().unwrap();
	let (service, request_stream) = client.launch_onion_service(svc_cfg).unwrap();

	let service_name = service.onion_name().unwrap().to_string();
	eprintln!("service name: {service_name}");

	let c = include_bytes!("../self_signed_certs/cert.pem");
	let k = include_bytes!("../self_signed_certs/key.pem");
	let cert = Identity::from_pkcs8(c, k).unwrap();
	let tls_acceptor = TlsAcceptor::from(native_tls::TlsAcceptor::builder(cert).build().unwrap());

	eprintln!("created tls acceptor");

	let stream_requests = tor_hsservice::handle_rend_requests(request_stream);

	tokio::pin!(stream_requests);
	eprintln!("ready to serve connections");

	let app = Router::new().route("/", get(|| async { "Hello, World!" }));

	while let Some(stream_request) = stream_requests.next().await {
		// incoming connection
		//let handler = handler.clone();
		let tls_acceptor = tls_acceptor.clone();
		let app = app.clone();

		eprintln!("received connection");

		tokio::spawn(async move {
			let request = stream_request.request().clone();

			eprintln!("handling connection");
			let result = handle_stream_request(stream_request, tls_acceptor.clone(), app.clone()).await;

			match result {
				Ok(()) => {}
				Err(err) => {
					eprintln!("error serving connection {:?}: {}", sensitive(request), err);
				}
			}
		});
	}

	drop(service);
	eprintln!("onion service exited cleanly");
}

async fn handle_stream_request(stream_request: StreamRequest, tls_acceptor: TlsAcceptor, app: Router) -> Result<()> {
	match stream_request.request() {
		IncomingStreamRequest::Begin(begin) if begin.port() == 80 || begin.port() == 443 => {
			eprintln!("begin request");
			let onion_service_stream = stream_request.accept(Connected::new_empty()).await.unwrap();

			eprintln!("onion_service stream");

			//let onion_service_stream = TlsPrepStream { stream:
			// Arc::new(TokioMutex::new(onion_service_stream)) };
			let tls_onion_service_stream = tls_acceptor.accept(onion_service_stream).await.unwrap();

			eprintln!("tls_onion_service_stream");

			let stream = TokioIo::new(tls_onion_service_stream);

			// Hyper also has its own `Service` trait and doesn't use tower. We can use
			// `hyper::service::service_fn` to create a hyper `Service` that calls our app
			// through `tower::Service::call`.
			let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| {
				// We have to clone `tower_service` because hyper's `Service` uses `&self`
				// whereas tower's `Service` requires `&mut self`.
				//
				// We don't need to call `poll_ready` since `Router` is always ready.
				app.clone().call(request)
			});

			let ret = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new()).serve_connection_with_upgrades(stream, hyper_service).await;

			if let Err(err) = ret {
				eprintln!("error serving connection: {err}");
			}
		}
		_ => {
			eprintln!("rejecting request: {:?}", stream_request.request());
			stream_request.shutdown_circuit()?;
		}
	}

	Ok(())
}
