use errors::*;

use hyper::Client as HyperClient;
use hyper::header::UserAgent;
use serde_json::{Value, from_str};

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



fn breaches_from_str(s: &str) -> Vec<Breach> {
    let data: Value = from_str(&s).unwrap();
    let mut v = Vec::new();

    if data.is_array() {
        let data = data.as_array().unwrap();
        for d in data {
            let d = d.as_object().unwrap();
            let breach = Breach {
                name: d.get("Name").map(|d| d.as_str().unwrap().to_owned()).unwrap(),
                title: d.get("Title").map(|t| t.as_str().unwrap().to_owned()),
                domain: d.get("Domain").map(|d| d.as_str().unwrap().to_owned()),
                breach_date: d.get("BreachDate").map(|d| d.as_str().unwrap().to_owned()),
                added_date: d.get("AddedDate").map(|d| d.as_str().unwrap().to_owned()),
                pwn_count: d.get("PwnCount").map(|p| p.as_u64().unwrap()),
                description: d.get("Description").map(|d| d.as_str().unwrap().to_owned()),
                data_classes: d.get("DataClasses").map(|dc| {
                    let a = dc.as_array().unwrap();
                    a.into_iter().map(|s| s.as_str().unwrap().to_owned()).collect()
                }),
                is_verified: d.get("IsVerified").map(|p| p.as_bool().unwrap()),
                is_sensitive: d.get("IsSensitive").map(|p| p.as_bool().unwrap()),
                is_retired: d.get("IsRetired").map(|p| p.as_bool().unwrap()),
            };

            v.push(breach);
        }
    } else {
        let d = data.as_object().unwrap();
        let breach = Breach {
            name: d.get("Name").map(|d| d.as_str().unwrap().to_owned()).unwrap(),
            title: d.get("Title").map(|t| t.as_str().unwrap().to_owned()),
            domain: d.get("Domain").map(|d| d.as_str().unwrap().to_owned()),
            breach_date: d.get("BreachDate").map(|d| d.as_str().unwrap().to_owned()),
            added_date: d.get("AddedDate").map(|d| d.as_str().unwrap().to_owned()),
            pwn_count: d.get("PwnCount").map(|p| p.as_u64().unwrap()),
            description: d.get("Description").map(|d| d.as_str().unwrap().to_owned()),
            data_classes: d.get("DataClasses").map(|dc| {
                let a = dc.as_array().unwrap();
                a.into_iter().map(|s| s.as_str().unwrap().to_owned()).collect()
            }),
            is_verified: d.get("IsVerified").map(|p| p.as_bool().unwrap()),
            is_sensitive: d.get("IsSensitive").map(|p| p.as_bool().unwrap()),
            is_retired: d.get("IsRetired").map(|p| p.as_bool().unwrap()),
        };
        v.push(breach);
    }

    v
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
        let breaches = breaches_from_str(&r);
        Ok(breaches)
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
        println!("reading response {:?}", r);
        let breaches = breaches_from_str(&r);
        Ok(breaches)
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
        println!("reading response {:?}", r);
        let breaches = breaches_from_str(&r);
        Ok(breaches)
    }
}

impl<'a> DataClassRequest<'a> {
    pub fn send(&mut self) -> Result<Vec<Breach>> {
        const url: &'static str = "https://haveibeenpwned.com/api/v2/dataclasses";

        let mut res = try!(self.client
                               .get(url)
                               .header(UserAgent(self.user_agent.to_owned()))
                               .send()
                               .chain_err(|| "Failed to sent GET request for Breach"));

        let mut r = String::new();
        try!(res.read_to_string(&mut r).chain_err(|| "Failed to read response to string"));
        println!("reading response {:?}", r);
        let breaches = breaches_from_str(&r);
        Ok(breaches)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {

        let mut client = Clientv2::new("test-rust-client");

        let r = client.get_breaches_acct("insanitybit@gmail.com")
                      .send();
        println!("{:?}", r.unwrap());

        let r = client.get_breaches()
                      .send();
        println!("{:?}", r.unwrap());

    }
}
