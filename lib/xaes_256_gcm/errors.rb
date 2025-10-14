# frozen_string_literal: true
# typed: true

module Xaes256Gcm
  # A base error that all Xaes256Gcm errors derive from.
  Error = Class.new(StandardError)

  # Indicates that the provided key is invalid because it is nil or the incorrect length.
  InvalidKeyError = Class.new(Error)

  # Indicates that the provided nonce is invalid because it is nil or the incorrect length.
  InvalidNonceError = Class.new(Error)

  # Indicates that the provided ciphertext is invalid because the authentication tag failed to verify.
  #
  # This may indicate that one of the inputs to open was invalid, or the ciphertext has been modified.
  InvalidCiphertextError = Class.new(Error)
end