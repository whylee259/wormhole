use solana_client::client_error::ClientError;
use solana_client::rpc_client::RpcClient;
use solana_sdk::fee_calculator::FeeCalculator;
use solana_sdk::instruction::Instruction;
use solana_sdk::program_error::ProgramError;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::{read_keypair_file, Keypair, Signer};
use solana_sdk::transaction::Transaction;
use spl_token::state::Account;
use tokio::stream::Stream;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tonic::{transport::Server, Code, Request, Response, Status};

use service::agent_server::{Agent, AgentServer};
use service::{
    lockup_event::Event, Empty, LockupEvent, LockupEventNew, LockupEventVaaPosted,
    SubmitVaaRequest, SubmitVaaResponse, WatchLockupsRequest,
};
use spl_bridge::instruction::{post_vaa, CHAIN_ID_SOLANA};
use spl_bridge::state::{Bridge, TransferOutProposal};
use std::env;
use std::mem::size_of;
use std::rc::Rc;
use std::str::FromStr;
use std::sync::mpsc::RecvError;
use std::thread::sleep;

use crate::monitor::{ProgramNotificationMessage, PubsubClient};

mod monitor;

pub mod service {
    include!(concat!(env!("OUT_DIR"), concat!("/", "agent.v1", ".rs")));
}

pub struct AgentImpl {
    url: String,
    bridge: Pubkey,

    rpc_url: String,
    key: Keypair,
}

#[tonic::async_trait]
impl Agent for AgentImpl {
    async fn submit_vaa(
        &self,
        request: Request<SubmitVaaRequest>,
    ) -> Result<Response<SubmitVaaResponse>, Status> {
        // Hack to clone keypair
        let b = self.key.to_bytes();
        let key = Keypair::from_bytes(&b).unwrap();

        let ix = match post_vaa(&self.bridge, &key.pubkey(), request.get_ref().vaa.clone()) {
            Ok(v) => v,
            Err(e) => {
                return Err(Status::new(
                    Code::InvalidArgument,
                    format!("could not create instruction: {}", e),
                ));
            }
        };

        let mut transaction = Transaction::new_with_payer(&[ix], Some(&key.pubkey()));
        let rpc_url = self.rpc_url.clone();

        // we need to spawn an extra thread because tokio does not allow nested runtimes
        std::thread::spawn(move || {
            let rpc = RpcClient::new(rpc_url);
            let (recent_blockhash, fee_calculator) = match rpc.get_recent_blockhash() {
                Ok(v) => v,
                Err(e) => {
                    return Err(Status::new(
                        Code::Unavailable,
                        format!("could not fetch recent blockhash: {}", e),
                    ));
                }
            };
            transaction.sign(&[&key], recent_blockhash);
            match rpc.send_and_confirm_transaction(&transaction) {
                Ok(s) => Ok(Response::new(SubmitVaaResponse {
                    signature: s.to_string(),
                })),
                Err(e) => Err(Status::new(
                    Code::Unavailable,
                    format!("tx sending failed: {}", e),
                )),
            }
        })
        .join()
        .unwrap()

        //check_fee_payer_balance(
        //    config,
        //    minimum_balance_for_rent_exemption
        //        + fee_calculator.calculate_fee(&transaction.message()),
        //)?;
    }

    type WatchLockupsStream = mpsc::Receiver<Result<LockupEvent, Status>>;

    async fn watch_lockups(
        &self,
        req: Request<WatchLockupsRequest>,
    ) -> Result<Response<Self::WatchLockupsStream>, Status> {
        let (mut tx, rx) = mpsc::channel(1);
        let mut tx1 = tx.clone();
        let url = self.url.clone();
        let bridge = self.bridge.clone();
        // creating a new task
        tokio::spawn(async move {
            // looping and sending our response using stream
            let sub = PubsubClient::program_subscribe(&url, &bridge).unwrap();
            loop {
                let item = sub.1.recv();
                match item {
                    Ok(v) => {
                        //
                        let b = match Bridge::unpack_immutable::<TransferOutProposal>(
                            v.value.account.data.as_slice(),
                        ) {
                            Ok(v) => v,
                            Err(_) => continue,
                        };

                        let mut amount_b: [u8; 32] = [0; 32];
                        b.amount.to_big_endian(&mut amount_b);

                        let event = if b.vaa_time == 0 {
                            // The Lockup was created
                            LockupEvent {
                                slot: v.context.slot,
                                event: Some(Event::New(LockupEventNew {
                                    nonce: b.nonce,
                                    source_chain: CHAIN_ID_SOLANA as u32,
                                    target_chain: b.to_chain_id as u32,
                                    source_address: b.source_address.to_vec(),
                                    target_address: b.foreign_address.to_vec(),
                                    token_chain: b.asset.chain as u32,
                                    token_address: b.asset.address.to_vec(),
                                    amount: amount_b.to_vec(),
                                })),
                            }
                        } else {
                            // The VAA was submitted
                            LockupEvent {
                                slot: v.context.slot,
                                event: Some(Event::VaaPosted(LockupEventVaaPosted {
                                    nonce: b.nonce,
                                    source_chain: CHAIN_ID_SOLANA as u32,
                                    target_chain: b.to_chain_id as u32,
                                    source_address: b.source_address.to_vec(),
                                    target_address: b.foreign_address.to_vec(),
                                    token_chain: b.asset.chain as u32,
                                    token_address: b.asset.address.to_vec(),
                                    amount: amount_b.to_vec(),
                                    vaa: b.vaa.to_vec(),
                                })),
                            }
                        };

                        let mut amount_b: [u8; 32] = [0; 32];
                        b.amount.to_big_endian(&mut amount_b);

                        if let Err(_) = tx.send(Ok(event)).await {
                            return;
                        };
                    }
                    Err(_) => {
                        tx.send(Err(Status::new(Code::Aborted, "watcher died")))
                            .await;
                        return;
                    }
                };
            }
        });
        tokio::spawn(async move {
            // We need to keep the channel alive https://github.com/hyperium/tonic/issues/378
            loop {
                tx1.send(Ok(LockupEvent {
                    slot: 0,
                    event: Some(Event::Empty(Empty {})),
                }))
                .await;
                sleep(Duration::new(1, 0))
            }
        });
        Ok(Response::new(rx))
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    // TODO use clap
    if args.len() < 6 {
        println!("<bridge> <rpc_host> <rpc_port> <ws_port> <port>");
        return Ok(());
    }

    let bridge = &args[1];
    let host = &args[2];
    let rpc_port: u16 = args[3].parse()?;
    let ws_port: u16 = args[4].parse()?;
    let port: u16 = args[5].parse()?;

    let addr = format!("[::]:{}", port).parse().unwrap();

    let agent = AgentImpl {
        url: String::from(format!("ws://{}:{}", host, ws_port)),
        rpc_url: format!("http://{}:{}", host, rpc_port),
        bridge: Pubkey::from_str(bridge).unwrap(),
        key: Keypair::new(), // TODO
    };

    println!("Agent listening on {}", addr);

    Server::builder()
        .add_service(AgentServer::new(agent))
        .serve(addr)
        .await?;

    Ok(())
}