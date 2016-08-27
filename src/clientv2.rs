use errors::*;

use hyper::Client as HyperClient;
use hyper::header::UserAgent;
use serde_json::{Value, from_str};

use std::collections::BTreeMap;
use std::io::prelude::*;

pub struct Clientv2<'a> {
    client: HyperClient,
    user_agent: &'a str,
}

#[derive(Debug)]
pub struct AccountBreachRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    account: &'a str,
    truncate: bool,
    domain: Option<&'a str>,
}

#[derive(Debug)]
pub struct AllBreachesRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    domain: Option<&'a str>,
}

#[derive(Debug)]
pub struct BreachRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
    name: &'a str,
}

#[derive(Debug)]
pub struct DataClassRequest<'a> {
    client: &'a HyperClient,
    user_agent: &'a str,
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

fn get_serde_object<'a>(obj: &'a Value) -> Result<&'a BTreeMap<String, Value>> {
    match obj.as_object() {
        Some(s) => Ok(s),
        None => Err(format!("Failed to parse value to object: {:#?}", obj).into()),
    }
}

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

impl<'a> Clientv2<'a> {
    pub fn new(user_agent: &'a str) -> Clientv2 {
        Clientv2 {
            client: HyperClient::new(),
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

    pub fn get_breache(&'a self, name: &'a str) -> BreachRequest<'a> {
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

    fn build_url(&self) -> String {
        let mut url = String::with_capacity(51 + self.account.len() +
                                            match self.domain {
            Some(d) => d.len() + 8,
            None => 0,
        } +
                                            if self.truncate {
            23
        } else {
            0
        });

        url.push_str("https://haveibeenpwned.com/api/v2/breachedaccount/");
        url.push_str(self.account);

        if let Some(d) = self.domain {
            url.push_str("?domain=");
            url.push_str(d);
        }

        if self.truncate {
            url.push_str("?truncateResponse=true");
        }
        url
    }

    pub fn send(&mut self) -> Result<Vec<Breach>> {
        let url = self.build_url();

        let mut res = try!(self.client
                               .get(&url)
                               .header(UserAgent(self.user_agent.to_owned()))
                               .send()
                               .chain_err(|| "Failed to sent GET request for AccountBreach"));

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

    fn build_url(&self) -> String {
        let mut url = String::with_capacity(43 +
                                            match self.domain {
            Some(d) => d.len() + 8,
            None => 0,
        });

        url.push_str("https://haveibeenpwned.com/api/v2/breaches");

        if let Some(d) = self.domain {
            url.push_str("?domain=");
            url.push_str(d);
        }

        url
    }

    pub fn send(&mut self) -> Result<Vec<Breach>> {
        let url = self.build_url();

        let mut res = try!(self.client
                               .get(&url)
                               .header(UserAgent(self.user_agent.to_owned()))
                               .send()
                               .chain_err(|| "Failed to sent GET request for AllBreaches"));

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
        const url: &'static str = "https://haveibeenpwned.com/api/v2/dataclasses";

        let mut res = try!(self.client
                               .get(url)
                               .header(UserAgent(self.user_agent.to_owned()))
                               .send()
                               .chain_err(|| "Failed to sent GET request for Breach"));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));



        let data: Value = try!(from_str(&r).chain_err(|| {
            format!("Failed to parse data classes: {:#?}", r)
        }));

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {

        let mut client = Clientv2::new("test-rust-client");

        let r = client.get_breaches_acct("insanitybit@gmail.com")
                      .send()
                      .unwrap();

        let r = client.get_breaches()
                      .send()
                      .unwrap();


        let r = client.get_data_classes().send().unwrap();
    }
}
