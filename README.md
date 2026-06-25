This is a drop-in replacement for OpenSSL **written entirely by AI** 🤖.

 - **Model**: [`deepseek-v4-pro`](https://openrouter.ai/deepseek/deepseek-v4-pro)
 - **Harness**: [CodeWhale](https://github.com/Hmbown/CodeWhale)
 - **Cost**: $84
 - **Tokens**: 573 million
 - **Time**: 5 days
 - **Steps**:
   - Ask the AI to write `ossl.h`.
   - Ask the AI to write `test.c`.
   - Ask the AI to write `ossl.c`.
   - Ask the AI to debug until it works. However, this only implemented TSL 1.2.
   - Ask the AI to add support for TSL 1.3.
   - Ask the AI to review and fix its own code.

The library builds on all platforms using [crossbuild](https://github.com/afl5c/crossbuild).
Root CAs are extracted from `/etc/ssl/certs/ca-certificates.crt` from within the build image and dumped into `cacerts.h` (see `Makefile`).

I place this code in the public domain. You can do whatever you want with it.
