
##  Imports from OpenSSL's Message Digest API
@[Link("openssl")]
lib MD

  ##  We need to know the size of this type to create new values
  struct Context
    digest, engine : Pointer(Void)
    flags : UInt64
    md_data, pctx, update_function : Pointer(Void)
  end

  ##  Used as an opaque handle
  alias Digest = Void

  ##  Functions to import
  fun context_init   = EVP_MD_CTX_init(context : Context*) : Void
  fun digest_init    = EVP_DigestInit(context : Context*, type : Digest*) : Int32
  fun ripemd160      = EVP_ripemd160() : Digest*
  fun sha256         = EVP_sha256() : Digest*
  fun digest_update  = EVP_DigestUpdate(context : Context*, d : Pointer(Void), count : LibC::SizeT) : Int32
  fun digest_final   = EVP_DigestFinal(context : Context*,  md : UInt8*, size : UInt32*) : Int32
  fun digest_cleanup = EVP_MD_CTX_cleanup(context : Context*)
end


##  Let's wrap the message digests in a nice class
module BitcoinAddress

  class Digest

    ##  Tuple for digest lengths
    Lengths = {ripemd160: 20, sha256: 32}


    ##  Exceptions
    class InvalidDigestType < Exception; end
    class IncorrectDigestLength < Exception; end


    ##  Create a new RIPEMD160 Digest
    def self.ripemd160(data)
      self.new(:ripemd160, data)
    end


    ##  Create a new SHA256 Digest
    def self.sha256(data)
      self.new(:sha256, data)
    end


    ##  Create the specified Digest type
    def initialize(type : Symbol, data)
      context = initialize_context
      set_digest_type(pointerof(context), type)
      length = Lengths[type]

      @output = Bytes.new(length, 0u8)
      actual_length = uninitialized UInt32

      data.each do |bytes|
        MD.digest_update(pointerof(context), bytes, bytes.size)
      end

      MD.digest_final(pointerof(context), @output, pointerof(actual_length))
      MD.digest_cleanup(pointerof(context))

      unless length == actual_length
        raise(IncorrectDigestLength.new)
      end
    end


    ##  Return the digest as binary
    def digest : Bytes
      @output
    end


    ##  Return the digest as hex
    def hexdigest : String
      @output.map do |byte|
        "%02.X" % byte
      end.join
    end


    ##  Set the digest type
    private def set_digest_type(context : MD::Context*, type : Symbol) : Void
      case type
      when :ripemd160
        MD.digest_init(context, MD.ripemd160())
      when :sha256
        MD.digest_init(context, MD.sha256())
      else
        raise(InvalidDigestType.new)
      end
    end


    ##  Initialize a message digest context
    private def initialize_context : MD::Context
      context = uninitialized MD::Context
      MD.context_init(pointerof(context))
      context
    end
  end

end
