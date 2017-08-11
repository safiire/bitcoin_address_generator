
##  Imports from OpenSSL's BigNum API
@[Link("openssl")]
lib BN

  ##  Here is the memory layout of a BigNum
  struct BigNum
    long : UInt64*
    top, dmax, neg, flags : Int32
  end

  ##  Context seems to be an opaque handle
  alias Context = Void

  ##  Functions to import
  fun context_new      = BN_CTX_new() : Context*
  fun init             = BN_init(bignum : BigNum*)
  fun hex_to_bignum    = BN_hex2bn(bignum : BigNum**, string : UInt8*) : Int32
  fun bignum_to_binary = BN_bn2bin(a : BigNum*, to : UInt8*) : Int32
  fun bignum_to_hex    = BN_bn2hex(a : BigNum*) : UInt8*
end
