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
require "securerandom"

key = # assign to some key.
nonce = SecureRandom.random_bytes(Xaes256Gcm::Xaes256GcmCipher::NONCE_SIZE)
plaintext = "Hello XAES-256-GCM from Ruby"

xaes = Xaes256Gcm::Xaes256GcmCipher.new(key)

# Seal, or encrypt
ciphertext = xaes.encrypt(plaintext, nonce)

# Open, or decrypt
decrypted = xaes.decrypt(ciphertext, nonce)
```

Optionally, AAD (additional authenticated data) can be passed as a 3rd argument to `seal` and `open`.

# Tests

Tests can be run with `bin/bundle exec rspec`
