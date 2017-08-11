# Bitcoin Address Generator

This program takes a list of phrases and transforms them into working bitcoin addresses.  It works by taking
the `sha256(phrase)`, and using that as the private key for a bitcoin address.

At one time or another, people were using addresses like this and calling them "BrainWallets", because instead
of needing to remember a large private key to access their coins, they could just remember a phrase that could
be easily transformed into a working address.

Ultimately people realized that it was easy to "snipe" the money out of addresses constructed this way, and
that it's a bad idea to use brainwallets.  I've even watched someone announce on Reddit a few years ago,
that they'd put 1BTC in an unspecified brainwallet, and whoever can figure out the private key can have the money.

Even with no other information given, the private key was found within minutes.


# Realistic uses
This code can also be used to create good bitcoin addresses, if we just allow OpenSSL to create the ECDSA key
by itself, or provide it with a good random private key.

This code was actually written in order to test out the Crystal programming language's ability to call into
external libraries written in C, in this case OpenSSL.  So really, just an excuse to make something in Crystal.
