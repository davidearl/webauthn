# PHP webauthn implementation

[webauthn](https://www.w3.org/TR/webauthn/) allows for browser logins
using a physical key (such as a [Yubikey 2 security
key](https://www.yubico.com/product/security-key-by-yubico/)) or, in
due course, biometrics such as fingerprints, that support the
protocol. Google also recently started selling [Titan](https://www.cnet.com/news/google-made-the-titan-key-to-toughen-up-your-online-security/), a pair of compatible hardware keys,
<del>but I don't have one yet to test code this with</del> which I have now been able to test with
and confirmed works with no change to the code.

Webauthn was [announced for Firefox
60](https://blog.mozilla.org/blog/2018/05/09/firefox-gets-down-to-business-and-its-personal/)
in May 2018 and also later added to Chrome. The idea of the age of
password-less logins was widely broadcast in the technical press. But
the reality is the whole thing is just too complicated for easy
adoption. It needs another layer to simplify it for routine use.

There are a couple examples in Javascript (see the
["coffee" example](https://webauthn.bin.coffee/)). But the whole point is that the
challenge and authentication must be done server-side.

It's fiendishly complicated, not so much in the cryptography as the
way the structures are packed and named. Unnecessarily so
([CBOR](https://tools.ietf.org/html/rfc7049)? What? Surely browsers
could have unpacked it from that even if space is at such a premium
that keys themselves require this weird binary format; and why not
produce the key in PEM format. And so on).

So I spent quite a while translating the "coffee" example into a PHP
class, while doing the minimum at the browser side (just unpacking
enough to put into a convenient JSON form to transport to the server),
and I thought I would share it.

## Changes from branch 0.1.0

The original code was updated in August 2019 by a number of
contributors (thank you!) to use composer for dependencies and update
name space, class and method names into line with conventions.

As a result, if you downloaded the original code, the various names in
your code will need to be updated. Now `\Davidearl` for the namespace
(upper case D), class name and the directory where it lives is now
`WebAuthn`, and the method names are `camelCase`.

If you want the code with the original names, download branch 0.1.0. That will not be updated in future.

## Dependencies

This requires

* [PHP CBOR library](https://github.com/2tvenom/CBOREncode): can be installed using _composer install_ in the project directory
* A recent openssl included in PHP ([openssl_verify](http://php.net/manual/en/function.openssl-verify.php)
in particular)
* PHP 5.6 or later (preferably PHP 7)

## Example

The example code is live at [https://webauthn.savesnine.info](https://webauthn.savesnine.info).

To host the example yourself,
* put the code in the document hierarchy for your server (say `https://example.com/webauthn`),
* install CBOR using `composer install`
* visit _yoururl_`/example` (e.g.`https://example.com/webauthn/example`)

If you put all the directories in webauthn at your document root and
add an index.php as follows, you can run it at the top level as e.g.
`https://example.com` (use your domain name, obviously).

`        <?php chdir('example'); include_once('index.php');`
