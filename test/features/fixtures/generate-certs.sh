openssl x509 -req -in server.req -CA CA.crt -CAkey CA.key -set_serial 0x4DDD97EA2B9610CA -days 365 -outform PEM -out unknown-dp.crt -extfile extfile-unknown-dp
