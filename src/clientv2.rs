use errors::*;

use hyper::net::HttpsConnector;
use hyper_rustls;
use hyper::Client as HyperClient;
use hyper::header::UserAgent;
use serde_json::{Value, from_str};
use url::Url;

use std::collections::BTreeMap;
use std::io::prelude::*;
use std::str::FromStr;

pub struct Clientv2<'a> {
    client: HyperClient,
    user_agent: &'a str,
}

#[derive(Debug, Clone)]
pub struct AccountBreachRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    account: &'a str,
    truncate: bool,
    domain: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct AllBreachesRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    domain: Option<&'a str>,
}

#[derive(Debug, Clone)]
pub struct BreachRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    name: &'a str,
}

#[derive(Debug, Clone)]
pub struct DataClassRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
}

#[derive(Debug, Clone)]
pub struct PasteRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    account: &'a str,
}

#[derive(Debug, Clone)]
pub struct Breach {
    name: String,
    title: Option<String>,
    domain: Option<String>,
    breach_date: Option<String>,
    added_date: Option<String>,
    pwn_count: Option<u64>,
    description: Option<String>,
    data_classes: Option<Vec<String>>,
    is_verified: Option<bool>,
    is_sensitive: Option<bool>,
    is_retired: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct Paste {
    source: String,
    id: String,
    title: Option<String>,
    date: Option<String>,
    email_count: u64,
}

fn get_serde_string(obj: &Value) -> Result<String> {
    match obj.as_str() {
        Some(s) => Ok(s.to_owned()),
        None => Err(format!("Failed to parse value to string: {:#?}", obj).into()),
    }
}

fn get_serde_array(obj: &Value) -> Result<Vec<Value>> {
    match obj.as_array() {
        Some(s) => Ok(s.to_owned()),
        None => Err(format!("Failed to parse value to array: {:#?}", obj).into()),
    }
}

fn get_serde_u64(obj: &Value) -> Result<u64> {
    match obj.as_u64() {
        Some(s) => Ok(s),
        None => Err(format!("Failed to parse value to u64: {:#?}", obj).into()),
    }
}

fn get_serde_bool(obj: &Value) -> Result<bool> {
    match obj.as_bool() {
        Some(s) => Ok(s),
        None => Err(format!("Failed to parse value to bool: {:#?}", obj).into()),
    }
}

// fn get_serde_object<'a>(obj: &'a Value) -> Result<&'a BTreeMap<String, Value>> {
//     match obj.as_object() {
//         Some(s) => Ok(s),
//         None => Err(format!("Failed to parse value to object: {:#?}", obj).into()),
//     }
// }

fn get_or_err<'a>(name: &str, obj: &'a BTreeMap<String, Value>) -> Result<&'a Value> {
    match obj.get(name) {
        Some(n) => Ok(n),
        None => Err(format!("Failed to get field: {:?}", name).into()),
    }
}

fn parse_breach(obj: &BTreeMap<String, Value>) -> Result<Breach> {
    Ok(Breach {
        name: try!(get_serde_string(try!(get_or_err("Name", obj)))),
        title: try!(obj.get("Title").map(get_serde_string).map_or(Ok(None), |t| t.map(Some))),
        domain: try!(obj.get("Domain")
            .map(get_serde_string)
            .map_or(Ok(None), |t| t.map(Some))),
        breach_date: try!(obj.get("BreachDate")
            .map(get_serde_string)
            .map_or(Ok(None), |t| t.map(Some))),
        added_date: try!(obj.get("AddedDate")
            .map(get_serde_string)
            .map_or(Ok(None), |t| t.map(Some))),
        pwn_count: try!(obj.get("PwnCount")
            .map(get_serde_u64)
            .map_or(Ok(None), |t| t.map(Some))),
        description: try!(obj.get("Description")
            .map(get_serde_string)
            .map_or(Ok(None), |t| t.map(Some))),
        data_classes: try!(obj.get("DataClasses")
            .map(|dc| {
                let v = try!(get_serde_array(dc));
                v.iter()
                    .map(get_serde_string)
                    .collect::<Result<Vec<_>>>()
            })
            .map_or(Ok(None), |t| t.map(Some))),
        is_verified: try!(obj.get("IsVerified")
            .map(get_serde_bool)
            .map_or(Ok(None), |t| t.map(Some))),
        is_sensitive: try!(obj.get("IsSensitive")
            .map(get_serde_bool)
            .map_or(Ok(None), |t| t.map(Some))),
        is_retired: try!(obj.get("IsRetired")
            .map(get_serde_bool)
            .map_or(Ok(None), |t| t.map(Some))),
    })
}

fn breaches_from_str(s: &str) -> Result<Vec<Breach>> {
    let data: Value = try!(from_str(&s)
        .chain_err(|| format!("Failed to parse breaches: {:#?}", s)));

    if let Some(data) = data.as_array() {
        data.iter()
            .map(|d| d.as_object())
            .collect::<Option<Vec<_>>>()
            .map_or(Err(format!("Failed to convert internal object from response: {:#?}",
                                data)
                        .into()),
                    |o| {
                        o.into_iter()
                            .map(parse_breach)
                            .collect::<Result<Vec<_>>>()
                    })
    } else if let Some(data) = data.as_object() {
        vec![parse_breach(&data)].into_iter().collect()
    } else {
        Err(format!("Improperly formatted response: {:#?}", s).into())
    }
}

fn parse_paste(obj: &BTreeMap<String, Value>) -> Result<Paste> {
    Ok(Paste {
        source: try!(get_serde_string(try!(get_or_err("Source", obj)))),
        id: try!(get_serde_string(try!(get_or_err("Id", obj)))),
        title: try!(get_or_err("Title", obj)).as_str().map(String::from),
        date: try!(get_or_err("Date", obj)).as_str().map(String::from),
        email_count: try!(get_serde_u64(try!(get_or_err("EmailCount", obj)))),
    })
}

fn pastes_from_str(s: &str) -> Result<Vec<Paste>> {
    let data: Value = try!(from_str(&s).chain_err(|| format!("Failed to parse pastes: {:#?}", s)));

    match data.as_array() {
        Some(data) => {
            data.iter()
                .map(|d| d.as_object())
                .collect::<Option<Vec<_>>>()
                .map_or(Err(format!("Failed to convert internal object from response: {:#?}",
                                    data)
                            .into()),
                        |o| {
                            o.into_iter()
                                .map(parse_paste)
                                .collect::<Result<Vec<_>>>()
                        })
        }
        None => Err(format!("Improperly formatted response: {:#?}", s).into()),
    }
}

impl<'a> Clientv2<'a> {
    pub fn new(user_agent: &'a str) -> Clientv2 {
        Clientv2 {
            client:
                HyperClient::with_connector(HttpsConnector::new(hyper_rustls::TlsClient::new())),
            user_agent: user_agent,
        }
    }

    pub fn get_breaches_acct(&'a self, acct: &'a str) -> AccountBreachRequest<'a> {
        AccountBreachRequest {
            client: &self.client,
            user_agent: &self.user_agent,
            account: acct,
            truncate: false,
            domain: None,
        }
    }

    pub fn get_breaches(&'a self) -> AllBreachesRequest<'a> {
        AllBreachesRequest {
            client: &self.client,
            user_agent: &self.user_agent,
            domain: None,
        }
    }

    pub fn get_breach(&'a self, name: &'a str) -> BreachRequest<'a> {
        BreachRequest {
            client: &self.client,
            user_agent: &self.user_agent,
            name: name,
        }
    }

    pub fn get_data_classes(&'a self) -> DataClassRequest<'a> {
        DataClassRequest {
            client: &self.client,
            user_agent: &self.user_agent,
        }
    }

    pub fn get_pastes(&'a self, account: &'a str) -> PasteRequest<'a> {
        PasteRequest {
            client: &self.client,
            user_agent: &self.user_agent,
            account: &account,
        }
    }
}

impl<'a> AccountBreachRequest<'a> {
    pub fn set_truncate(&mut self, t: bool) -> &mut Self {
        self.truncate = t;
        self
    }

    pub fn set_domain(&mut self, d: &'a str) -> &mut Self {
        self.domain = Some(d);
        self
    }

    fn build_url(&self) -> Url {
        let mut base = String::new();
        base.push_str("https://haveibeenpwned.com/api/v2/breachedaccount/");
        base.push_str(self.account);

        let mut url = Url::parse(&base).unwrap();

        if let Some(d) = self.domain {
            url.query_pairs_mut().append_pair("domain", d);
        }

        if self.truncate {
            url.query_pairs_mut().append_pair("truncateResponse", "true");
        }
        url
    }

    pub fn send(&mut self) -> Result<Vec<Breach>> {
        let url = self.build_url();

        let mut res = try!(self.client
            .get(url.clone())
            .header(UserAgent(self.user_agent.to_owned()))
            .send()
            .chain_err(|| {
                format!("Failed to send GET request for AccountBreach for url {:#?}",
                        url)
            }));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));
        breaches_from_str(&r)
    }
}


impl<'a> AllBreachesRequest<'a> {
    pub fn set_domain(&mut self, d: &'a str) -> &mut Self {
        self.domain = Some(d);
        self
    }

    fn build_url(&self) -> Url {
        let mut url = Url::parse("https://haveibeenpwned.com/api/v2/breaches").unwrap();

        if let Some(d) = self.domain {
            url.query_pairs_mut().append_pair("domain", d);
        }

        url
    }

    pub fn send(&mut self) -> Result<Vec<Breach>> {
        let url = self.build_url();

        let mut res = try!(self.client
            .get(url.clone())
            .header(UserAgent(self.user_agent.to_owned()))
            .send()
            .chain_err(|| {
                format!("Failed to send GET request for AllBreaches for url: {}",
                        url)
            }));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));
        breaches_from_str(&r)
    }
}


impl<'a> BreachRequest<'a> {
    fn build_url(&self, name: &str) -> String {
        let mut url = String::with_capacity(43 + name.len());

        url.push_str("https://haveibeenpwned.com/api/v2/breach/");
        url.push_str(name);

        url
    }

    pub fn send(&mut self) -> Result<Vec<Breach>> {
        let url = self.build_url(&self.name);

        let mut res = try!(self.client
            .get(&url)
            .header(UserAgent(self.user_agent.to_owned()))
            .send()
            .chain_err(|| "Failed to sent GET request for Breach"));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));

        breaches_from_str(&r)
    }
}

impl<'a> DataClassRequest<'a> {
    pub fn send(&mut self) -> Result<Vec<String>> {
        let mut res = try!(self.client
            .get("https://haveibeenpwned.com/api/v2/dataclasses")
            .header(UserAgent(self.user_agent.to_owned()))
            .send()
            .chain_err(|| "Failed to sent GET request for Breach"));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));



        let data: Value = try!(from_str(&r)
            .chain_err(|| format!("Failed to parse data classes: {:#?}", r)));

        data.as_array()
            .map(|d| {
                d.into_iter()
                    .map(get_serde_string)
                    .collect::<Result<Vec<_>>>()
            })
            .unwrap_or(Err((format!("Failed to parse DataClass into array of string: {}", data)
                .into())))
    }
}

impl<'a> PasteRequest<'a> {
    fn build_url(&self) -> Url {
        Url::from_str(&format!("https://haveibeenpwned.com/api/v2/pasteaccount/{}",
                               self.account))
            .unwrap()
    }

    pub fn send(&mut self) -> Result<Vec<Paste>> {
        let url = self.build_url();
        let mut res = try!(self.client
            .get(url)
            .header(UserAgent(self.user_agent.to_owned()))
            .send()
            .chain_err(|| "Failed to sent GET request for pastes"));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));
        if r.is_empty() {
            Ok(vec![])
        } else {
            pastes_from_str(&r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {

        let mut client = Clientv2::new("test-rust-client");

        let r = client.get_breaches_acct("test@example.com")
            .send()
            .unwrap();

        let r = client.get_breaches()
            .send()
            .unwrap();


        let r = client.get_data_classes().send().unwrap();

        let r = client.get_pastes("test@example.com").send().unwrap();
    }
}
