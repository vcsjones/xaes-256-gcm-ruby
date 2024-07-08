# frozen_string_literal: true
# typed: strict

module Xaes256Gcm
  class Xaes256GcmCipher
    extend T::Sig

    NONCE_SIZE = T.let(24.freeze, Integer)

    KEY_SIZE = T.let(32.freeze, Integer)

    OVERHEAD = T.let(16.freeze, Integer)

    BLOCK_SIZE = T.let(16.freeze, Integer)
    private_constant :BLOCK_SIZE

    sig { params(key: String).void }
    def initialize(key)
      raise InvalidKeyError.new if key.bytesize != KEY_SIZE

      @aes = T.let(OpenSSL::Cipher::AES256.new(:ECB), OpenSSL::Cipher::AES256)
      @aes.encrypt
      @aes.padding = 0
      @aes.key = key

      k1init = "\0".b * BLOCK_SIZE
      k1init = @aes.update(k1init)

      msb = 0
      k1 = T.cast(k1init.bytes, T::Array[Integer])

      for i in (k1.length - 1).downto(0)
        msbC = msb
        msb = T.must(k1[i]) >> 7
        k1[i] = ((T.must(k1[i]) << 1) & 0b11111111) | msbC;
      end

      k1[-1] = T.must(k1[-1]) ^ ((msb * 0b10000111) & 0b11111111)
      @k1 = T.let(NoInspectBox.new(k1), NoInspectBox[T::Array[Integer]])
    end

    sig { params(plaintext: String, nonce: String, additionalData: T.nilable(String)).returns(String) }
    def seal(plaintext, nonce, additionalData = nil)
      raise InvalidNonceError if nonce.bytesize != NONCE_SIZE

      key = derive_key(T.must(nonce.byteslice(0, 12)))
      gcm = OpenSSL::Cipher::AES256.new(:GCM)
      gcm.encrypt
      gcm.iv = T.must(nonce.byteslice(12, 12))
      gcm.key = key
      gcm.auth_data = additionalData unless additionalData.nil?

      ciphertext = ""
      ciphertext = gcm.update(plaintext) if plaintext.bytesize > 0
      ciphertext += gcm.final
      ciphertext + gcm.auth_tag
    end

    sig { params(ciphertext: String, nonce: String, additionalData: T.nilable(String)).returns(String) }
    def open(ciphertext, nonce, additionalData = nil)
      ct_bytes = ciphertext.bytesize
      raise InvalidNonceError if nonce.bytesize != NONCE_SIZE
      raise InvalidCiphertextError if ciphertext.bytesize < OVERHEAD

      tagless_ciphertext = T.must(ciphertext.byteslice(0, ct_bytes - OVERHEAD))
      tag = T.must(ciphertext.byteslice(ct_bytes - OVERHEAD, OVERHEAD))

      key = derive_key(T.must(nonce.byteslice(0, 12)))
      gcm = OpenSSL::Cipher::AES256.new(:GCM)
      gcm.decrypt
      gcm.iv = T.must(nonce.byteslice(12, 12))
      gcm.key = key
      gcm.auth_data = additionalData unless additionalData.nil?
      gcm.auth_tag = tag

      plaintext = ""
      plaintext = gcm.update(tagless_ciphertext) if tagless_ciphertext.bytesize > 0

      begin
        plaintext += gcm.final
      rescue OpenSSL::Cipher::CipherError => ex
        raise InvalidCiphertextError.new
      end

      return plaintext
    end

    private

    sig { params(nonce: String).returns(String) }
    def derive_key(nonce)
      nonce_bytes = nonce.bytes

      # 0x58 is the ASCII value for "X"
      m1 = [0, 1, 0x58, 0] + nonce_bytes
      m2 = [0, 2, 0x58, 0] + nonce_bytes
      xor(m1, @k1.value)
      xor(m2, @k1.value)

      m12 = (m1 + m2).pack("C*")
      @aes.update(m12)
    end

    sig { params(destination: T::Array[Integer], other: T::Array[Integer]).void }
    def xor(destination, other)
      destination.each_with_index do |value, index|
        destination[index] = T.must(destination[index]) ^ T.must(other[index])
      end
    end

    # This is just a smaller helper class that returns a redacted value for to_s and inspect.
    # It exists to simply make sure any state on the instance is not accidentally logged or printed.
    class NoInspectBox
      extend T::Sig
      extend T::Generic

      TValue = type_member

      sig { params(value: TValue).void }
      def initialize(value)
        @value = value
      end

      sig { returns(TValue) }
      def value
        @value
      end

      sig { returns(String) }
      def inspect
        return "hidden"
      end

      sig { returns(String) }
      def to_s
        return "hidden"
      end
    end

    private_constant :NoInspectBox
  end
end