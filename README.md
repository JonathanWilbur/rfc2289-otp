# RFC 2289 One-Time Password

Implements the One-Time Password (OTP) algorithm described in
[IETF RFC 2289](https://www.rfc-editor.org/rfc/rfc2289.html), including
functions for parsing strings and mapping between dictionary words and OTP
values.

This algorithm is **NOT** the same as the TOTP and HOTP algorithms widely in use
today for multifactor authentication: these are defined in other RFCs. This
algorithm, however, is used in the `OTP` SASL mechanism as described in
[IETF RFC 2444](https://www.rfc-editor.org/rfc/rfc2444.html).

## Security

Note that there are only three hash algorithms defined for use with this
algorithm, **all of which are no longer considered secure**. These are:

- MD4
- MD5
- SHA1

**However**, I am of the non-professional opinion that these algorithms are
generally fine for the way that they are used by the OTP algorithm, because the
OTP algorithm performs the hash a fixed number of times with a fixed seed and a
passphrase. Still, I **highly** recommend using the `sha1` algorithm
exclusively. It is the newest and most secure of the three.

If more algorithms are ever made official, you should see the new algorithms
[here](https://www.iana.org/assignments/otp-parameters/otp-parameters.xhtml).

I plan to implement more algorithms for this, even though they are not
standardized. The principles that belie the standard algorithms have obvious
corollaries in more modern algorithms. If you would like to see a particular
algorithm supported, ask!

## Feature Flags

The feature flags for this library are:

- `md4`: MD4 support
- `md5`: MD5 support
- `sha1`: SHA1 support
- `words`: Translation to and from dictionary words
- `dyndig`: Support for any digest that implements `digest::DynDigest`
- `parsing`: Parsing OTP strings

All of the above are enabled by default.

## Usage

Let's say you receive an OTP challenge as a string like so:

```
otp-md5 499 ke1234 ext
```

Decode this string like so:

```rust
let challenge_str = "otp-md5 487 dog2";
let challenge = parse_otp_challenge(challenge_str).unwrap();
```

If it is a valid string, you should get a data structure that looks like this:

```rust
pub struct OTPChallenge <'a> {
    pub hash_alg: &'a str,
    pub hash_count: usize,
    pub seed: &'a str,
}
```

You can use this data structure to calculate the OTP like so:

```rust
let extremely_secure_passphrase = "banana";
let otp = calculate_otp(
    challenge.hash_alg,
    extremely_secure_passphrase,
    challenge.seed,
    challenge.hash_count,
    None,
).unwrap();
```

If the algorithm was understood, and there wasn't any other problem, you should
get a `[u8; 8]` back (64-bits), which is your OTP value.

You can directly convert this value to hex, and prepend `hex:` to it to produce
a valid OTP response.

Or, you can convert it to dictionary words using the standard dictionary defined
in the specification using `convert_to_word_format`. Join these words with
spaces and prefix it with `word:`.

If implementing an OTP server, you can parse these responses like so:

```rust
let otp_response = "hex:5Bf0 75d9 959d 036f";
let r = parse_otp_response(&otp_response).unwrap();
```

If the syntax is valid, you should get an `OTPResponse` as shown below:

```rust
pub enum HexOrWords <'a> {
    Hex(Hex64Bit),
    Words(&'a str),
}

pub struct OTPInit <'a> {
    pub current_otp: HexOrWords<'a>,
    pub new_otp: HexOrWords<'a>,
    pub new_alg: &'a str,
    pub new_seq_num: usize,
    pub new_seed: &'a str,
}

pub enum OTPResponse <'a> {
    Init(OTPInit <'a>),
    Current(HexOrWords<'a>)
}
```

The server will need to calculate the OTP and compare that value to the decoded
hex or words supplied by the client. You can decode words to the binary OTP
value using `decode_word_format_with_std_dict` like so:

```rust
let decoded = decode_word_format_with_std_dict(words).unwrap();
```

If the client response is one of the `Init` variants, how the server chooses to
handle this is an implementation detail.

## License

Copyright 2024 (c) Jonathan M. Wilbur.

This is licensed under the MIT license. Dual-licensing is so annoying and I
don't understand the rationale. If you really need an Apache license, just ask
me and I'll fix it.
