# frozen_string_literal: true
# typed: true

module Xaes256Gcm
  Error = Class.new(StandardError)
  InvalidKeyError = Class.new(Error)
  InvalidNonceError = Class.new(Error)
  InvalidCiphertextError = Class.new(Error)
end