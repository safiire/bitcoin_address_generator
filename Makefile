
build:
	crystal build src/bitcoin_address.cr

release:
	crystal build src/bitcoin_address.cr --release

clean:
	rm -f output.yaml
	rm bitcoin_address
