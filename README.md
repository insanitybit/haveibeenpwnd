# haveibeenpwnd
A client for the Have I Been Pwned? API v2 for Rust

```rust

  let client = Clientv2::new("test-rust-client");

  let r = client.get_breaches_acct("test@example.com")
                .send()
                .unwrap();

  let r = client.get_breaches()
                .send()
                .unwrap();


  let r = client.get_data_classes().send().unwrap();

  let r = client.get_pastes("test@example.com").send().unwrap();
```
