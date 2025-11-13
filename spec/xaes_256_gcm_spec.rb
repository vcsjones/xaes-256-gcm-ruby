# frozen_string_literal: true

require "xaes_256_gcm"
require "rspec"

include Xaes256Gcm

RSpec.describe Xaes256GcmCipher do
  context "#initialize" do

    it "errors with a nil key" do
      expect { Xaes256GcmCipher.new(nil) }.to raise_error(Xaes256Gcm::InvalidKeyError)
    end

    it "errors when given no key" do
      expect { Xaes256GcmCipher.new }.to raise_error(ArgumentError)
    end

    it "errors with a different typed key" do
      expect { Xaes256GcmCipher.new([1, 2, 3]) }.to raise_error(Xaes256Gcm::InvalidKeyError)
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
      ciphertext = xaes.encrypt("hello", nonce)

      ciphertext_tampered = ciphertext.byteslice(0, ciphertext.bytesize - 1) + "\0"

      expect { xaes.decrypt(ciphertext_tampered, nonce) }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with sliced off tag" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.encrypt("hello this is a good day we are having", nonce)

      ciphertext_tampered = ciphertext.byteslice(0, ciphertext.bytesize - Xaes256GcmCipher::OVERHEAD_ENCRYPTION)

      expect { xaes.decrypt(ciphertext_tampered, nonce) }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with added aad" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.encrypt("hello again", nonce)
      expect { xaes.decrypt(ciphertext, nonce, "other aad") }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with missing aad" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.encrypt("hello again", nonce, "some aad")
      expect { xaes.decrypt(ciphertext, nonce) }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end

    it "errors with different aad" do
      xaes = Xaes256GcmCipher.new("A" * Xaes256GcmCipher::KEY_SIZE)
      nonce = "B" * Xaes256GcmCipher::NONCE_SIZE
      ciphertext = xaes.encrypt("hello again", nonce, "some aad")
      expect { xaes.decrypt(ciphertext, nonce, "some aad2") }.to raise_error(Xaes256Gcm::InvalidCiphertextError)
    end
  end

  context "simple" do
    let (:key) { "\xCA" * Xaes256GcmCipher::KEY_SIZE }

    it "randomly generates a nonce" do
      xaes = Xaes256GcmCipher.new(key)
      sealed1 = xaes.seal("potato")
      sealed2 = xaes.seal("potato")
      expect(sealed1).not_to eq(sealed2)
    end

    it "roundtrips with no aad" do
      xaes = Xaes256GcmCipher.new(key)
      plaintext = "carrots"

      sealed = xaes.seal(plaintext)
      opened = xaes.open(sealed)
      expect(opened).to eq(plaintext)
    end

    it "roundtrips with aad" do
      xaes = Xaes256GcmCipher.new(key)
      plaintext = "carrots"
      aad = "beets"

      sealed = xaes.seal(plaintext, aad)
      opened = xaes.open(sealed, aad)
      expect(opened).to eq(plaintext)
    end

    it "can roundtrip empty" do
      xaes = Xaes256GcmCipher.new(key)
      plaintext = ""
      aad = ""
      sealed = xaes.seal(plaintext, aad)
      opened = xaes.open(sealed, aad)
      expect(opened).to eq(plaintext)
    end
  end

  context "test vector" do
    let(:nonce) { "ABCDEFGHIJKLMNOPQRSTUVWX" }
    let(:plaintext) { "XAES-256-GCM" }

    it "functions with C2SP vectors - no aad" do
      key = "\x01" * Xaes256GcmCipher::KEY_SIZE
      expected = "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
      xaes = Xaes256GcmCipher.new(key)

      ciphertext = xaes.encrypt(plaintext, nonce)
      ciphertext_hex = ciphertext.unpack1("H*")

      expect(ciphertext_hex).to eq(expected)

      decrypted = xaes.decrypt(ciphertext, nonce)
      expect(decrypted).to eq(plaintext)

      decrypted = xaes.open(nonce + ciphertext)
      expect(decrypted).to eq(plaintext)
    end

    it "functions with C2SP vectors - with aad" do
      key = "\x03" * Xaes256GcmCipher::KEY_SIZE
      aad = "c2sp.org/XAES-256-GCM"
      expected = "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"
      xaes = Xaes256GcmCipher.new(key)

      ciphertext = xaes.encrypt(plaintext, nonce, aad)
      ciphertext_hex = ciphertext.unpack1("H*")

      expect(ciphertext_hex).to eq(expected)

      decrypted = xaes.decrypt(ciphertext, nonce, aad)
      expect(decrypted).to eq(plaintext)

      decrypted = xaes.open(nonce + ciphertext, aad)
      expect(decrypted).to eq(plaintext)
    end
  end

  context "inspection" do
    it "inspect does not reveal key" do
      xaes = Xaes256GcmCipher.new("potato potato potato potato beet")
      str = xaes.inspect
      expect(str).not_to match(/potato/)
      expect(str).not_to match(/beet/)
      expect(str).to match(/hidden/)
    end

    it "interpolation does not reveal key" do
      xaes = Xaes256GcmCipher.new("potato potato potato potato beet")
      str = "#{xaes}"
      expect(str).not_to match(/potato/)
      expect(str).not_to match(/beet/)
    end
  end
end