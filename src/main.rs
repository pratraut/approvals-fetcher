use std::{
    collections::{HashMap, HashSet},
    ops::Add,
};

use alloy::{
    primitives::{Address, U256},
    providers::{Provider, ProviderBuilder},
    rpc::types::Filter,
    sol,
    sol_types::SolEvent,
};
use clap::Parser;
use comfy_table::{
    modifiers::UTF8_ROUND_CORNERS, presets::UTF8_FULL, Attribute, Cell, Color, ContentArrangement,
    Table,
};
use eyre::Result;
use num_format::{Locale, ToFormattedString};
use regex::Regex;

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IERC20,
    "src/abi/IERC20.json",
);

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    IFeedRegistry,
    "src/abi/IFeedRegistry.json",
);

const BASE: u64 = 10000000000;
const ALLOWED_BLOCK_RANGE: u64 = 2000;

#[derive(Debug, Clone)]
pub struct ExtraHeader {
    pub cookie_name: String,
    pub cookie_value: String,
    pub cookie_expires: f64,
    pub user_agent: String,
}

async fn fetch_from_url(url: &str, extra_header: &Option<ExtraHeader>) -> Result<String> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        reqwest::header::ACCEPT,
        reqwest::header::HeaderValue::from_static("*/*"),
    );

    if let Some(extra) = extra_header {
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&extra.user_agent)?,
        );
        headers.insert(
            reqwest::header::COOKIE,
            reqwest::header::HeaderValue::from_str(&format!(
                "{}={}",
                extra.cookie_name, extra.cookie_value
            ))?,
        );
    }

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()?;

    let res = client.get(url).send().await?;
    if res.status().is_client_error() {
        return Err(eyre::eyre!(
            "Client side error (code: {}: {}): Failed to fetch : {}",
            res.status().as_str(),
            res.status(),
            url
        ));
    }
    Ok(res.text().await.unwrap())
}

async fn fetch_price_from_etherscan_tracker(token: String) -> Result<f64> {
    let url = format!("https://etherscan.io/token/{}", token);
    let body = fetch_from_url(&url, &None).await?;

    let captures = Regex::new(r#"(?ms)<div\s+id=['|"]ContentPlaceHolder1_tr_valuepertoken['|"].*?>.*?<div>.*?<span.*?>.*?\$(.*?)<\/span>"#)?.captures(&body);

    if captures.is_some() {
        let price = captures
            .unwrap()
            .get(1)
            .map(|m| m.as_str().trim().to_string())
            .unwrap();
        let price = price.replace(",", "");
        return Ok(price.parse()?);
    }

    Ok(0.0)
}

#[allow(dead_code)]
struct ApprovalData {
    token: String,
    owner: String,
    spender: String,
    amount_approved: String,
    owner_actual_balance: String,
    actual_value_in_usd: String,
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// RPC URL
    #[arg(short, long)]
    rpc: String,

    /// From block number
    #[arg(short, long)]
    from_block: u64,

    /// To block number
    #[arg(short, long, default_value = None)]
    to_block: Option<u64>,

    /// Spender Address
    #[arg(short, long)]
    spender: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let start = tokio::time::Instant::now();

    let args = Args::parse();

    // Create a provider.
    let rpc_url = args.rpc.parse()?;
    let provider = ProviderBuilder::new().on_http(rpc_url);

    // Get logs from the latest block
    let latest_block = provider.get_block_number().await?;
    println!("Latest Block: {}", latest_block);

    // Get all logs from the latest block that match the transfer event signature/topic.
    let mut filter = Filter::new().event_signature(IERC20::Approval::SIGNATURE_HASH);

    // Get all logs from the latest block that match the filter.
    let logs = {
        let end = args.to_block.unwrap_or(latest_block);
        let mut start = args.from_block;
        let mut logs = Vec::new();
        while start <= end {
            let local_end = u64::min(start + ALLOWED_BLOCK_RANGE, end);
            filter = filter.from_block(start).to_block(local_end);
            logs.extend(provider.get_logs(&filter).await?);
            start = local_end + 1;
        }
        logs
    };

    let approved_to = Address::parse_checksummed(args.spender, None)?;

    let mut cache_price = HashMap::new();
    let mut cache_approvals = HashSet::new();
    let mut total_in_usd = U256::ZERO;
    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "Token",
            "Owner",
            "Spender",
            "Amount Spendable",
            "Spendable Value(USD)",
        ]);

    let mut unknown_asset_table = Table::new();
    unknown_asset_table
        .load_preset(UTF8_FULL)
        .apply_modifier(UTF8_ROUND_CORNERS)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec![
            "Token",
            "Owner",
            "Spender",
            "Amount Approved",
            "Owner's Actual Balance",
        ]);

    for log in logs {
        if let Ok(data) = log.log_decode() {
            let IERC20::Approval {
                owner,
                spender,
                value,
            } = data.inner.data;
            if value.is_zero() {
                continue;
            }
            if spender == approved_to {
                let token = log.address();

                // Check for duplicate approvals
                let key = (token, owner, spender);
                if cache_approvals.get(&key).is_some() {
                    continue;
                } else {
                    cache_approvals.insert(key);
                }

                let token = IERC20::new(token, provider.clone());
                let IERC20::balanceOfReturn { _0 } = token.balanceOf(owner).call().await?;
                if _0.is_zero() {
                    continue;
                }
                let balance = _0;
                let IERC20::decimalsReturn { _0 } = token.decimals().call().await?;
                let decimals = _0;
                let actual_value = value.min(balance);

                // Fetch price from Etherscan
                let price = if let Some(p) = cache_price.get(token.address()) {
                    *p
                } else {
                    let p = fetch_price_from_etherscan_tracker(token.address().to_string()).await?;
                    cache_price.insert(*token.address(), p);
                    p
                };

                let price_with_base = (price * BASE as f64) as u64;
                let value_in_usd = actual_value
                    .saturating_mul(U256::from(price_with_base))
                    .div_rem(U256::from(10_u64.pow(decimals.into())))
                    .0
                    .div_rem(U256::from(BASE))
                    .0;
                if !value_in_usd.is_zero() {
                    total_in_usd = total_in_usd.add(value_in_usd);

                    table.add_row(vec![
                        Cell::new(token.address().to_string()),
                        Cell::new(owner.to_string()),
                        Cell::new(spender.to_string()),
                        Cell::new(actual_value.to_string()),
                        Cell::new(format!(
                            "${}",
                            value_in_usd
                                .to_string()
                                .parse::<u64>()?
                                .to_formatted_string(&Locale::en)
                        ))
                        .add_attribute(Attribute::Bold)
                        .fg(Color::Green),
                    ]);
                } else {
                    unknown_asset_table.add_row(vec![
                        Cell::new(token.address().to_string()),
                        Cell::new(owner.to_string()),
                        Cell::new(spender.to_string()),
                        if value.eq(&U256::MAX) {
                            Cell::new("INF")
                        } else {
                            Cell::new(value.to_string())
                        },
                        Cell::new(balance.to_string()),
                    ]);
                }
            }
        }
    }

    println!("{}", table);
    println!(
        "\nTOTAL VALUE APPROVED TO {} FROM BLOCK {} TO {} IN USD: ${}",
        approved_to,
        args.from_block,
        args.to_block.unwrap_or(latest_block),
        total_in_usd
            .to_string()
            .parse::<u64>()?
            .to_formatted_string(&Locale::en)
    );

    if !unknown_asset_table.is_empty() {
        println!("\nNot able to find values in USD:");
        println!("{}", unknown_asset_table);
    }
    print!("\nTime took: {:?} seconds", start.elapsed());
    Ok(())
}
