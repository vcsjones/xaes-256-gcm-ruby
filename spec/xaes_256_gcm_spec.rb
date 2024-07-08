# frozen_string_literal: true
# typed: true

require "xaes_256_gcm"
require "rspec"

include Xaes256Gcm

RSpec.describe Xaes256GcmCipher do
  T.bind(self, T::untyped) # Sorbet and rspec do not seem to get along.

  context "#initialize" do

    it "errors with a nil key" do
      expect { Xaes256GcmCipher.new(T.unsafe(nil)) }.to raise_error(TypeError)
    end

    it "errors when given no key" do
      expect { T.unsafe(Xaes256GcmCipher).new }.to raise_error(ArgumentError)
    end

    it "errors with a different typed key" do
      expect { Xaes256GcmCipher.new(T.unsafe([1, 2, 3])) }.to raise_error(TypeError)
    end

    it "errors with too short key" do
      expect { Xaes256GcmCipher.new("A" * (Xaes256GcmCipher::KEY_SIZE - 1)) }.to raise_error(Xaes256Gcm::InvalidKeyError)
    end

    it "errors with too large key" do
      expect { Xaes256GcmCipher.new("A" * (Xaes256GcmCipher::KEY_SIZE + 1)) }.to raise_error(Xaes256Gcm::InvalidKeyError)
    end

    it "initialize with key" do
      _ = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
    end

  end

  context "authentication" do
    it "errors with tampered tag" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.seal("hello", nonce)

      ciphertext_tampered = T.must(ciphertext.byteslice(0, ciphertext.bytesize - 1)) + "\0"

      expect { xaes.open(ciphertext_tampered, nonce) }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with sliced off tag" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.seal("hello this is a good day we are having", nonce)

      ciphertext_tampered = T.must(ciphertext.byteslice(0, ciphertext.bytesize - Xaes256GcmCipher::OVERHEAD))

      expect { xaes.open(ciphertext_tampered, nonce) }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with added aad" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.seal("hello again", nonce)
      expect { xaes.open(ciphertext, nonce, "other aad") }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with missing aad" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.seal("hello again", nonce, "some aad")
      expect { xaes.open(ciphertext, nonce) }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with different aad" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.seal("hello again", nonce, "some aad")
      expect { xaes.open(ciphertext, nonce, "some aad2") }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end
  end

  context "test vector" do
    let(:nonce) { "ABCDEFGHIJKLMNOPQRSTUVWX" }
    let(:plaintext) { "XAES-256-GCM" }

    it "functions with C2SP vectors - no aad" do
      key = "\x01" * Xaes256GcmCipher::KEY_SIZE
      expected = "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
      xaes = Xaes256GcmCipher.new(key)

      ciphertext = xaes.seal(plaintext, nonce)
      ciphertext_hex = ciphertext.unpack1("H*")

      expect(ciphertext_hex).to eq(expected)

      decrypted = xaes.open(ciphertext, nonce)
      expect(decrypted).to eq(plaintext)
    end

    it "functions with C2SP vectors - with aad" do
      key = "\x03" * Xaes256GcmCipher::KEY_SIZE
      aad = "c2sp.org/XAES-256-GCM"
      expected = "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"
      xaes = Xaes256GcmCipher.new(key)

      ciphertext = xaes.seal(plaintext, nonce, aad)
      ciphertext_hex = ciphertext.unpack1("H*")

      expect(ciphertext_hex).to eq(expected)

      decrypted = xaes.open(ciphertext, nonce, aad)
      expect(decrypted).to eq(plaintext)
    end
  end
end