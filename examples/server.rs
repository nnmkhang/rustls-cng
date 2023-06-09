use std::{
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use rustls::{
    server::{AllowAnyAuthenticatedClient, ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
    Certificate, RootCertStore, ServerConfig, ServerConnection, Stream,
};

use rustls_cng::{
    signer::CngSigningKey,
    cert::{CertChainEngineType, CertAiaRetrievalType},
    store::{CertStore, CertStoreType},
};

const PORT: u16 = 8000;


#[derive(Parser)]
#[clap(name = "rustls-server-sample")]
struct AppParams {
    #[clap(
        action,
        short = 'c',
        long = "ca-cert",
        help = "CA cert name to verify the peer certificate",
        default_value = "peer"
    )]
    ca_cert: String,

    #[clap(
        action,
        short = 's',
        long = "server-cert",
        help = "server cert name to find certificate",
        default_value = "server"
    )]
    server_cert: String,

    #[clap(
        action,
        short = 'k',
        long = "keystore",
        help = "Use external PFX keystore"
    )]
    keystore: Option<PathBuf>,

    #[clap(
        action,
        short = 'p',
        long = "password",
        help = "Keystore password",
        default_value = "changeit"
    )]
    password: String,

    #[clap(
        action,
        long = "cache-server-cert",
        help = "cache server certificae",
        default_value = "false"
    )]
    cache_server_cert: String,

    #[clap(
        action,
        long = "local-machine",
        help = "use local machine instead of current user",
        default_value = "false"
    )]
    use_local_machine: String,

    #[clap(
        action,
        long = "store-name",
        help = "override my",
        default_value = "my"
    )]
    store_name: String,

    #[clap(
        action,
        long = "thumbprint",
        help = "sha1 (20) or sha1_sha256 (52) ascii hex characters",
        default_value = ""
    )]
    thumbprint: String,
}

pub struct ServerCertResolver(CertStore);


impl ResolvesServerCert for ServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        println!("Client hello server name: {:?}", client_hello.server_name());
        let name = client_hello.server_name()?;

        // look up certificate by subject
        let contexts = self.0.find_by_subject_str(name).ok()?;

        let context = contexts.into_iter().find_map(|ctx| {
            if ctx.has_private_key() && ctx.is_time_valid() {
                return Some(ctx);
            }

            None
        })?;

        // attempt to acquire a private key and construct CngSigningKey
//        let (context, key) = contexts.into_iter().find_map(|ctx| {
//        let (context, key) = {
//            let key = ctx.acquire_key().ok()?;
//            CngSigningKey::new(key).ok().map(|key| (ctx, key))
//        })?;

        let key = context.acquire_key().ok()?;
        let signing_key = CngSigningKey::new(key).ok()?;

        println!("Key alg group: {:?}", signing_key.key().algorithm_group());
        println!("Key alg: {:?}", signing_key.key().algorithm());

        // attempt to acquire a full certificate chain
//        let chain = context.as_chain_der().ok()?;
        let chain_engine_type;
        if self.0.is_local_machine() {
            chain_engine_type = CertChainEngineType::LocalMachine;
        } else {
            chain_engine_type = CertChainEngineType::CurrentUser;
        }

        let chain = context.as_chain_der_ex(
                        chain_engine_type,
                        CertAiaRetrievalType::CacheOnly,
                        false,                              // include_root
                        Some(self.0.clone())
                     ).ok()?;
        let certs = chain.into_iter().map(Certificate).collect();

        // return CertifiedKey instance
        Some(Arc::new(CertifiedKey {
            cert: certs,
            key: Arc::new(signing_key),
            ocsp: None,
            sct_list: None,
        }))
    }
}

pub struct CacheServerCertResolver(Arc<CertifiedKey>);
impl ResolvesServerCert for CacheServerCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        println!("Client hello server name: {:?}", client_hello.server_name());

        Some(Arc::clone(&self.0))
    }
}

fn get_chain(store: &CertStore, name: &str) -> anyhow::Result<(Vec<Certificate>, CngSigningKey)> {
    let contexts = store.find_by_subject_str(name)?;
    let context = contexts.into_iter().find_map(|ctx| {
        if ctx.has_private_key() && ctx.is_time_valid() {
            return Some(ctx);
        }

        None
    }).ok_or_else(|| anyhow::Error::msg("No client cert"))?;

//    let context = contexts
//        .first()
//        .ok_or_else(|| anyhow::Error::msg("No client cert"))?;
    let key = context.acquire_key()?;
    let signing_key = CngSigningKey::new(key)?;
    let chain = context
        .as_chain_der()?
        .into_iter()
        .map(Certificate)
        .collect();
    Ok((chain, signing_key))
}


// fn make_cache_cng_config(ca_name: &str, server_name: &str) -> Arc<rustls::ServerConfig> {
fn make_cache_cng_config(store_type: CertStoreType, store_name: &str,
                         ca_name: &str, server_name: &str) -> rustls::ServerConfig {
    println!("in make_cache_cng");

    let store = CertStore::open(store_type, store_name).unwrap();
    let ca_cert_context = store.find_by_subject_str(ca_name).unwrap();
    let ca_cert = ca_cert_context.first().unwrap();

    let mut root_store = RootCertStore::empty();
    root_store.add(&Certificate(ca_cert.as_der().to_vec())).unwrap();

    let (chain, signing_key) = get_chain(&store, server_name).unwrap();

    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions().unwrap()
        .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(root_store)))
        .with_cert_resolver(Arc::new(CacheServerCertResolver(
            Arc::new(CertifiedKey {
                cert: chain,
                key: Arc::new(signing_key),
                ocsp: None,
                sct_list: None,
            }))));

        config
}

fn make_thumbprint_cng_config(store_type: CertStoreType, store_name: &str,
                              hex_thumbprint: &str) -> rustls::ServerConfig {
    println!("in make_thumbprint_cng");

    let store = CertStore::open_for_sha1_find(store_type, store_name).unwrap();
    let thumbprint = hex::decode(hex_thumbprint).unwrap();
    let context = store.find_last_renewed(&thumbprint).unwrap();

    let key = context.acquire_key().unwrap();
    let signing_key = CngSigningKey::new(key).unwrap();

    let chain_engine_type = match store_type {
        CertStoreType::LocalMachine => CertChainEngineType::LocalMachine,
        _ => CertChainEngineType::CurrentUser,
    };
    
    let chain = context
        .as_chain_der_ex(
            chain_engine_type,
            CertAiaRetrievalType::Network,
            false,              // include_root
            None).unwrap()      // additional_store
        .into_iter()
        .map(Certificate)
        .collect();


    let config = ServerConfig::builder()
        .with_safe_default_cipher_suites()
        .with_safe_default_kx_groups()
        .with_safe_default_protocol_versions().unwrap()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(CacheServerCertResolver(
            Arc::new(CertifiedKey {
                cert: chain,
                key: Arc::new(signing_key),
                ocsp: None,
                sct_list: None,
            }))));

        config
}

fn handle_connection(mut stream: TcpStream, config: Arc<ServerConfig>) -> anyhow::Result<()> {
    println!("Accepted incoming connection from {}", stream.peer_addr()?);
    let mut connection = ServerConnection::new(config)?;
    let mut tls_stream = Stream::new(&mut connection, &mut stream);

    // perform handshake early to get and dump some protocol information
    if tls_stream.conn.is_handshaking() {
        tls_stream.conn.complete_io(tls_stream.sock)?;
    }

    println!("Protocol version: {:?}", tls_stream.conn.protocol_version());
    println!(
        "Cipher suite: {:?}",
        tls_stream.conn.negotiated_cipher_suite()
    );
    println!("SNI host name: {:?}", tls_stream.conn.server_name());
    println!(
        "Peer certificates: {:?}",
        tls_stream.conn.peer_certificates().map(|c| c.len())
    );

    let mut buf = Vec::new();
    tls_stream.read_to_end(&mut buf)?;
    println!("{}", String::from_utf8_lossy(&buf));
    tls_stream.sock.shutdown(Shutdown::Read)?;
    tls_stream.write_all(b"pong")?;
    tls_stream.sock.shutdown(Shutdown::Write)?;

    Ok(())
}

fn accept(server: TcpListener, config: Arc<ServerConfig>) -> anyhow::Result<()> {
    for stream in server.incoming().flatten() {
        let config = config.clone();
        std::thread::spawn(|| {
            let _ = handle_connection(stream, config);
        });
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let params: AppParams = AppParams::parse();

    let store_type;
    if params.use_local_machine != "false" {
        store_type = CertStoreType::LocalMachine;
    } else {
        store_type = CertStoreType::CurrentUser;
    }

    let server_config;

    if params.thumbprint.len() != 0 {
        server_config = make_thumbprint_cng_config(
            store_type, &params.store_name, &params.thumbprint);
    } else if params.cache_server_cert == "true" {
        server_config = make_cache_cng_config(store_type, &params.store_name, &params.ca_cert, &params.server_cert);
    } else {
        println!("in SNI resolver config");

        let store = if let Some(ref keystore) = params.keystore {
            let data = std::fs::read(keystore)?;
            CertStore::from_pkcs12(&data, &params.password)?
        } else {
            CertStore::open(store_type, &params.store_name)?
        };

        store.set_auto_resync().ok();
    
//       let ca_cert_context = store.find_by_subject_str(&params.ca_cert)?;
//        let ca_cert = ca_cert_context.first().unwrap();
    
//        let mut root_store = RootCertStore::empty();
//        root_store.add(&Certificate(ca_cert.as_der().to_vec()))?;
    
            
        server_config = ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
//            .with_client_cert_verifier(Arc::new(AllowAnyAuthenticatedClient::new(root_store)))
            .with_cert_resolver(Arc::new(ServerCertResolver(store)));
    }

    let server = TcpListener::bind(format!("0.0.0.0:{}", PORT))?;

    // to test: openssl s_client -servername HOSTNAME -connect localhost:8000
    accept(server, Arc::new(server_config))?;

    Ok(())
}
