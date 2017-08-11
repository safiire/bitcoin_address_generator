require "./bitcoin_address/*"
require "big_int"
require "yaml"

module BitcoinAddress

  ##  A class to generate a bitcoin address
  class Address

    @address : String
    @private_key_hex : String

    def initialize(string : String)
      ##  Create a curve
      curve = ElipticCurve.new(string)
      x, y = curve.public_coordinates_binary

      ##  SHA256 the public key
      header = Bytes.new(1, 4u8)
      step3 = Digest.sha256([header, x, y]).digest

      ##  RIPEMD160 previous result
      digest = Digest.ripemd160([step3])
      step4 = digest.digest
      step4_hex = digest.hexdigest

      ##  Add Network byte 0x00 and SHA256 again
      network_byte = Bytes.new(1, 0u8)
      step5 = Digest.sha256([network_byte, step4]).digest

      ##  And again for checksum bytes
      step6 = Digest.sha256([step5]).digest
      checksum_hex = step6[0, 4].map {|byte| "%02.X" % byte}.join

      ##  Network byte + Step4 + checksum
      address = "00" + step4_hex + checksum_hex

      ##  Base58Check the address
      @address = base58_check(address)
      @private_key_hex = curve.private_key_hex
    end


    ##  base58 check
    private def base58_check(hexstring : String) : String
      code_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
      x = BigInt.new(hexstring, 16)
      output_string = ""
      while x > 0
        x, remainder = (x / 58), (x % 58)
        output_string += code_string[remainder]
      end
      md = hexstring.match(/^(0+)/)
      unless md.nil?
        output_string += code_string[0]
      end
      output_string.reverse
    end


    ##  Return the private key as hex
    def private_key_hex
      @private_key_hex
    end


    ##  Return the address
    def address
      @address
    end
  end
end


filename = ARGV.first

File.open(filename, "r") do |fp|
  values = fp.each_line.map do |line|
    phrase = line.chomp.strip
    address = BitcoinAddress::Address.new(phrase)
    {address: address.address, phrase: phrase, key: address.private_key_hex}
  end.to_a

  File.open("output.yaml", "w") do |output|
    output.write(values.to_yaml.to_slice)
  end
end
