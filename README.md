# applepay-php

applepay-php is a PHP extension that verifies and decrypts Apple Pay payment
tokens according to Apple's spec[1]. It relies on OpenSSL for all crypto
operations. Currently, it serves as the backbone for Etsy's PHP-based Apple Pay
token handling endpoint.

### Build

    $ # Clone repo
    $ git clone https://github.com/etsy/applepay-php.git
    $ cd applepay-php
    $
    $ # Install OpenSSL development files
    $ sudo yum install openssl-devel
    $ # -or- sudo apt-get install libssl-dev
    $ # etc...
    $
    $ # Build extension
    $ phpize && ./configure && make
    $
    $ # Optionally install
    $ sudo make install
    $ echo 'extension=applepay.so' | sudo tee /etc/php.d/applepay.ini
    $ # -or- echo 'extension=applepay.so' | sudo tee -a /etc/php.ini
    $ # etc...

### Demo

Before running the demo, you'll need a `Payment Processing Certificate` and a private key
from Apple (apple_pay.cer and priv.p12 below). You can generate these at Apple's Dev
Center. You'll also need an example payment token generated on an end-user
device and the timestamp at which it was generated. For more info check out the
Apple Pay Programming Guide[2].

    $ # Copy in your merchant cert, private key, and test token
    $ cd examples
    $ cp /secret/place/priv.p12 .
    $ cp /secret/place/apple_pay.cer .
    $ cp /secret/place/token.dat .
    $
    $ # Get intermediate and root certs from Apple
    $ wget -O int.cer 'https://www.apple.com/certificateauthority/AppleAAICAG3.cer'
    $ wget -O root.cer 'https://www.apple.com/certificateauthority/AppleRootCA-G3.cer'
    $
    $ # Verify chain of trust
    $ openssl x509 -inform DER -in apple_pay.cer -pubkey > pub.pem
    $ openssl x509 -inform DER -in root.cer > root.pem
    $ openssl x509 -inform DER -in int.cer > int_apple_pay.pem
    $ openssl x509 -inform DER -in apple_pay.cer >> int_apple_pay.pem
    $ openssl verify -verbose -CAfile root.pem int_apple_pay.pem # should output OK
    $
    $ # Run demo
    $ cd ..
    $ php -denable_dl=on -dextension=`pwd`/modules/applepay.so examples/applepay.php -p <privkey_pass> -c examples/token.dat -t <time_of_transaction>

If everything goes well you should see decrypted payment data.

### Future work

* Split up library into libapplepay and a PHP wrapper
* HHVM port

[1] https://developer.apple.com/library/prerelease/ios/documentation/PassKit/Reference/PaymentTokenJSON/PaymentTokenJSON.html

[2] https://developer.apple.com/library/ios/ApplePay_Guide/
