# RSALibrary
Small library for a class that uses RSA to encrypt/decrypt/sign/verify

Keys can be used with openssl

    echo test | openssl rsautl -encrypt -pubin -inkey ./public.key > message.enc
    openssl rsautl -decrypt -inkey ./priv.pem < message.enc
    