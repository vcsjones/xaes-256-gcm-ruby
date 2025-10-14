# frozen_string_literal: true

##
# The module containing XAES-256-GCM.
module Xaes256Gcm

  # Represents an instance of the XAES-256-GCM algorithm.
  class Xaes256GcmCipher

    # The nonce size of the algorithm, in bytes.
    NONCE_SIZE = 24.freeze

    # The key size of the algorithm, in bytes.
    KEY_SIZE = 32.freeze

    # The overhead of a ciphertext.
    #
    # When a plaintext is encrypted, the resulting ciphertext will be larger because of the authentication tag.
    # This value indicates how much larger a ciphertext will be than a plaintext.
    OVERHEAD = 16.freeze

    BLOCK_SIZE = 16.freeze
    private_constant :BLOCK_SIZE

    # Creates a new instance of the XAES-256-GCM algorithm.
    def initialize(key)
      raise InvalidKeyError.new if key.nil? || !key.is_a?(String) || key.bytesize != KEY_SIZE

      @aes = OpenSSL::Cipher::AES256.new(:ECB)
      @aes.encrypt
      @aes.padding = 0
      @aes.key = key

      k1init = "\0".b * BLOCK_SIZE
      k1init = @aes.update(k1init)

      msb = 0
      k1 = k1init.bytes

      for i in (k1.length - 1).downto(0)
        msbC = msb
        msb = k1[i] >> 7
        k1[i] = ((k1[i] << 1) & 0b11111111) | msbC;
      end

      k1[-1] = k1[-1] ^ ((msb * 0b10000111) & 0b11111111)
      @k1 = NoInspectBox.new(k1)
    end

    # Seals, or encrypts, a plaintext with a nonce.  Optional additional authenticated data can be provided.
    def seal(plaintext, nonce, additionalData = nil)
      raise InvalidNonceError if nonce.bytesize != NONCE_SIZE

      key = derive_key(nonce.byteslice(0, 12))
      gcm = OpenSSL::Cipher::AES256.new(:GCM)
      gcm.encrypt
      gcm.iv = nonce.byteslice(12, 12)
      gcm.key = key
      gcm.auth_data = additionalData unless additionalData.nil?

      ciphertext = ""
      ciphertext = gcm.update(plaintext) if plaintext.bytesize > 0
      ciphertext += gcm.final
      ciphertext + gcm.auth_tag
    end

    def open(ciphertext, nonce, additionalData = nil)
      ct_bytes = ciphertext.bytesize
      raise InvalidNonceError if nonce.bytesize != NONCE_SIZE
      raise InvalidCiphertextError if ciphertext.bytesize < OVERHEAD

      tagless_ciphertext = ciphertext.byteslice(0, ct_bytes - OVERHEAD)
      tag = ciphertext.byteslice(ct_bytes - OVERHEAD, OVERHEAD)

      key = derive_key(nonce.byteslice(0, 12))
      gcm = OpenSSL::Cipher::AES256.new(:GCM)
      gcm.decrypt
      gcm.iv = nonce.byteslice(12, 12)
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

    def xor(destination, other)
      destination.each_with_index do |value, index|
        destination[index] = destination[index] ^ other[index]
      end
    end

    # This is just a smaller helper class that returns a redacted value for to_s and inspect.
    # It exists to simply make sure any state on the instance is not accidentally logged or printed.
    class NoInspectBox
      def initialize(value)
        @value = value
      end

      def value
        @value
      end

      def inspect
        return "hidden"
      end

      def to_s
        return "hidden"
      end
    end

    private_constant :NoInspectBox
  end
end