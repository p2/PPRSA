RSA
===

Simple RSA encryption and decryption for iOS.
These classes **do not require OpenSSL** to be built for iOS, you only need `Security.framework`.
OpenSSL is needed to generate the key pairs, however, which you probably want to do on your Desktop machine.
See below.


Usage
-----

For encryption, you can add the public key (`{name}.crt`) to your app bundle and load it.
For decryption you _could_ add your p12 (`{name}.p12`) to your app bundle and load it.
BUT you probably don't want to add your .p12 to the app bundle because it can easily be extracted.
Instead you should load the private key data into your app somehow and create an `NSData` representation from it:

```obj-c
NSString *string = @"This is a string to encrypt. No longer than 245 bytes!";
NSData *data = [string dataUsingEncoding:NSUTF8StringEncoding];

NSString *private = <# Base64 String of your private p12 data #>;
NSData *privateKey = [[NSData alloc] initWithBase64EncodedString:private options:0];

PPRSA *rsa = [PPRSA new];
NSError *error = nil;
if ([rsa loadPublicKeyFromBundledCertificate:@"public" error:&error]) {
    if ([rsa loadPrivateKeyFromP12Data:privateKey password:@"t4co9x" error:&error]) {
        NSData *encrypted = [rsa encryptData:data error:&error];
        if (encrypted) {
            NSData *decrypted = [rsa decryptData:encrypted error:&error];
            NSString *final = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
            NSLog(@"--> %@", final);
        }
    }
}
```


Key Generation
--------------

Generate a new key pair (into `public.crt` and `private.pem`).
You will need to supply a password.

```bash
openssl req -x509 -days 3652 -out public.crt -outform DER -new -newkey rsa:2048 -keyout private.pem
```

Create a signing request.
You'll be asked some questions about country, company and so on; fill whatever works for you.

```bash
openssl req -new -key private.pem -out signing-request.csr
```

Create a self-signed certificate, valid for 10 years in this example.
You'll be prompted to enter the private key's password.

```bash
openssl x509 -req -days 3652 -in signing-request.csr -signkey private.pem -out certificate.crt
```

Export the private key and certificate into a p12 file (`private.p12`).
You'll again be asked for the private key password and are prompted to create a new password for the p12.

```bash
openssl pkcs12 -export -out private.p12 -inkey private.pem -in certificate.crt
```


License
=======

This work is in the public domain.

Code snippets were sources from various places, especially StackOverflow and [Chris Luke's Blog](http://blog.flirble.org/2011/01/05/rsa-public-key-openssl-ios/#its-all-in-the-format).
