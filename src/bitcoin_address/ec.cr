require "./bn.cr"

##  Imports from OpenSSL's Eliptic Curve API
@[Link("openssl")]
lib EC

  ##  These types are only ever used as pointers, and often opaque handles
  alias ECKey = Void
  alias ECPoint = Void
  alias ECGroup = Void

  ##  Relevant constants from ec.h
  NID_secp256k1 = 714
  POINT_CONVERSION_COMPRESSED = 2
  POINT_CONVERSION_UNCOMPRESSED = 4
  POINT_CONVERSION_HYBRID = 6

  ##  Functions to import
  fun key_new_by_curve_name        = EC_KEY_new_by_curve_name(nid : Int32) : ECKey*
  fun key_get0_group               = EC_KEY_get0_group(key : ECKey*) : ECGroup*
  fun point_new                    = EC_POINT_new(group : ECGroup*) : ECPoint*
  fun set_private_key              = EC_KEY_set_private_key(key : ECKey*, prv : BN::BigNum*) : Int32
  fun point_mul                    = EC_POINT_mul(group : ECGroup*, r : ECPoint*, n : BN::BigNum*, q : ECPoint*, m : BN::BigNum*, context : BN::Context*) : Int32
  fun set_public_key               = EC_KEY_set_public_key(key : ECKey*, pub : ECPoint*) : Int32
  fun point_to_hex                 = EC_POINT_point2hex(group : ECGroup*, point : ECPoint*, convert_form : Int32, context : BN::Context*) : UInt8*
  fun point_get_affine_coordinates = EC_POINT_get_affine_coordinates_GFp(group : ECGroup*, point : ECPoint*, x : BN::BigNum*, y : BN::BigNum*, context : BN::Context*) : Int32
end


##  Let's wrap the eliptic curve functions in a class
module BitcoinAddress

  class ElipticCurve

    ##  Exceptions
    class PointMultiplicationFailed < Exception; end


    ##  Create an ECDSA eliptic curve, from an sha256(string) as private key
    def initialize(string : String)
      ##  Initialize a bignum to hold the private key
      bignum_context = BN.context_new
      @private_key_bignum = uninitialized BN::BigNum
      private_key_bignum_ptr = pointerof(@private_key_bignum)
      BN.init(private_key_bignum_ptr)

      private_key_hex = Digest.sha256([string]).hexdigest
      BN.hex_to_bignum(pointerof(private_key_bignum_ptr), private_key_hex)

      ##  Create a point on an Eliptic Curve
      ec_key = EC.key_new_by_curve_name(EC::NID_secp256k1)
      group = EC.key_get0_group(ec_key)
      public_key_point = EC.point_new(group)

      ##  Set our private key, and mutiply to get public point
      EC.set_private_key(ec_key, private_key_bignum_ptr)
      if EC.point_mul(group, public_key_point, private_key_bignum_ptr, nil, nil, bignum_context).zero?
        raise(PointMultiplicationFailed.new)
      end
      EC.set_public_key(ec_key, public_key_point)

      ##  Extract the public point coordinates
      @x = uninitialized BN::BigNum
      @y = uninitialized BN::BigNum
      BN.init(pointerof(@x))
      BN.init(pointerof(@y))
      EC.point_get_affine_coordinates(group, public_key_point, pointerof(@x), pointerof(@y), bignum_context)
    end


    ##  Return the public key's coordinates as BigNum
    def public_coordinates
      [@x, @y]
    end


    ##  Return the public key's coordinates in hex
    def public_coordinates_hex
      x = String.new(BN.bignum_to_hex(pointerof(@x)))
      y = String.new(BN.bignum_to_hex(pointerof(@y)))
      [x, y]
    end


    ##  Return public key's coordinates in binary
    def public_coordinates_binary
      x_binary = Bytes.new(32)
      y_binary = Bytes.new(32)
      BN.bignum_to_binary(pointerof(@x), x_binary)
      BN.bignum_to_binary(pointerof(@y), y_binary)
      [x_binary, y_binary]
    end


    ##  Return the private key as a bignum
    def private_key
      @private_key_bignum
    end


    ##  Return the private key as hex
    def private_key_hex
      String.new(BN.bignum_to_hex(pointerof(@private_key_bignum)))
    end

  end

end
