XAES-256-GCM for Ruby
========

This is an implementation of XAES-256-GCM as proposed by Filippo Valsorda, for Ruby.

Resources:
* Original post by Filippo: https://words.filippo.io/dispatches/xaes-256-gcm/
* The XAES-256-GCM specification: https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md
* Reference implementations for Go and OpenSSL: https://github.com/C2SP/C2SP/tree/main/XAES-256-GCM


# Using

Get from Rubygem.org: https://rubygems.org/gems/xaes_256_gcm

```ruby
require "xaes_256_gcm"

key = # assign to some key.
plaintext = "Hello XAES-256-GCM from Ruby"

xaes = Xaes256Gcm::Xaes256GcmCipher.new(key)

# Seal, or encrypt
ciphertext = xaes.seal(plaintext)

# Open, or decrypt
decrypted = xaes.open(ciphertext)
```

Optionally, AAD (additional authenticated data) can be passed as a 2nd argument to `seal` and `open`.

This implementation of XAES-256-GCM will generate secure nonce for you automatically when using `seal` and `open`.
If low-level control over the nonce is required, `encrypt` and `decrypt` accept a nonce independently. It is recommended
that the high-level `seal` and `open` that create a nonce for you is used unless strict control over the nonce is required.

The "simple" nonce managed APIs are not formally specified in by C2SP. Here we define them simply as

Encryption:

```plain
N = CSPRNG_bytes(24)
ciphertext = encrypt(N, plaintext, aad)
sealed = N || ciphertext
```

Decryption:

```plain
N = sealed[:24]
ciphertext = sealed[24:]
plaintext = decrypt(N, ciphertext, add)
```

# Tests

Tests can be run with `bin/bundle exec rspec`
