This is a drop-in replacement for OpenSSL **written entirely by AI** 🤖.

 - **Model**: [`deepseek-v4-pro`](https://openrouter.ai/deepseek/deepseek-v4-pro)
 - **Harness**:
    - 90% [CodeWhale](https://github.com/Hmbown/CodeWhale). This seems to be better for long-running tasks, but can randomly hang or crash.
    - 10% [Crush](https://github.com/charmbracelet/crush). This seems to be better for small fixes, although it requires some time to set up (to generate AGENTS.md for itself).
 - **Cost**: $161
 - **Tokens**: 1.09 billion
 - **Time**: 7 days of chatting
 - **Steps**:
   - Ask the AI to write `ossl.h`.
   - Ask the AI to write `test.c`.
   - Ask the AI to write `ossl.c`.
   - Ask the AI to debug until it works. This only implemented TLS 1.2.
   - Ask the AI to add support for TLS 1.3.
   - Ask the AI to write `server.c`.
   - Ask the AI to add server support. This also optimized the code.
   - Ask the AI to review and fix its own code.

The library builds on all platforms using [crossbuild](https://github.com/afl5c/crossbuild).
Root CAs are extracted from `/etc/ssl/certs/ca-certificates.crt` from within the build image and dumped into `cacerts.h`.
Additionally, Let's Encrypt certificates are downloaded and added separately, since they don't seem to be part of the Linux root CAs by default.
See `Makefile` for more details.

I place this code in the public domain. You can do whatever you want with it.
Part of the code seems to be memorized from [agl/curve25519-donna](https://github.com/agl/curve25519-donna/) (see comment in `ossl.c`), so I don't claim any rights over that portion.
