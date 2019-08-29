<?php

namespace Davidearl\WebAuthn;

use phpseclib\Crypt\RSA;
use phpseclib\Math\BigInteger;

/**
* @package davidearl\webauthn
*
*
* A class to help manage keys via the webauthn protocol.
*
* Webauthn allows for browser logins using a physical key (such as a
* Yubikey 2) or, in due course, biometrics such as fingerprints, that
* support the protocol.
*
* This is based on the Javascript example at
* https://webauthn.bin.coffee/, but offers a PHP server side.
*
* You need to store a webauthn string (which does not need to be
* indexed) in user records in your database, the value of which is
* consulted and amended by the various functions in this class.
*
* Errors are thrown as simple Exception, with code 0 for user errors (such as validation failure) or 1 for
* programming errors (wrong argument types etc)
*
* Dependencies
* ------------
*
* - You will need to include https://github.com/2tvenom/CBOREncode
* - openssl that supports SHA256
*/

class WebAuthn
{

    const ES256 = -7;
    const RS256 = -257; // Windows Hello support
    /**
    * construct object on which to operate
    *
    * @param string $appid a string identifying your app, typically the domain of your website which people
    *                      are using the key to log in to. If you have the URL (ie including the
    *                      https:// on the front) to hand, give that;
    *                      if it's not https, well what are you doing using this code?
    */
    public function __construct($appid)
    {
        if (! is_string($appid)) {
            $this->oops('appid must be a string');
        }
        $this->appid = $appid;
        if (strpos($this->appid, 'https://') === 0) {
            $this->appid = substr($this->appid, 8); /* drop the https:// */
        }
    }

    /**
    * cancel all keys for a user
    * @return string to store as the user's webauthn field in your database
    */
    public function cancel()
    {
        return '';
    }

    /**
    * generate a challenge ready for registering a hardware key, fingerprint or whatever:
    * @param $username string by which the user is known potentially displayed on the hardware key
    * @param $userid string by which the user can be uniquely identified. Don't use email address as this can change,
    *                user perhaps the database record id
    * @param $crossPlatform bool default=FALSE, whether to link the identity to the key (TRUE, so it 
    *               can be used cross-platofrm, on different computers) or the platform (FALSE, only on 
    *               this computer, but with any available authentication device, e.g. known to Windows Hello)
    * @return string pass this JSON string back to the browser
    */
  public function prepareChallengeForRegistration($username, $userid, $crossPlatform=FALSE)
    {
        $result = (object)array();
        $rbchallenge = self::randomBytes(16);
        $result->challenge = self::stringToArray($rbchallenge);
        $result->user = (object)array();
        $result->user->name = $result->user->displayName = $username;
        $result->user->id = self::stringToArray($userid);

        $result->rp = (object)array();
        $result->rp->name = $result->rp->id = $this->appid;

        $result->pubKeyCredParams = [
            [
                'alg' => self::ES256,
                'type' => 'public-key'
            ],
            [
                'alg' => self::RS256,
                'type' => 'public-key'
            ]
        ];

        $result->authenticatorSelection = (object)array();
        if ($crossPlatform) { $result->authenticatorSelection->authenticatorAttachment = 'cross-platform'; }

        $result->authenticatorSelection->requireResidentKey = false;
        $result->authenticatorSelection->userVerification = 'discouraged';

        $result->attestation = null;
        $result->timeout = 60000;
        $result->excludeCredentials = []; // No excludeList
        $result->extensions = (object)array();
        $result->extensions->exts = true;

        return json_encode(array('publicKey'=>$result,
        'b64challenge'=>rtrim(strtr(base64_encode($rbchallenge), '+/', '-_'), '=')));
    }

    /**
    * registers a new key for a user
    * requires info from the hardware via javascript given below
    * @param string $info supplied to the PHP script via a POST, constructed by the Javascript given below, ultimately
    *        provided by the key
    * @param string $userwebauthn the exisitng webauthn field for the user from your
    *        database (it's actaully a JSON string, but that's entirely internal to
    *        this code)
    * @return string modified to store in the user's webauthn field in your database
    */
    public function register($info, $userwebauthn)
    {
        if (! is_string($info)) {
            $this->oops('info must be a string', 1);
        }
        $info = json_decode($info);
        if (empty($info)) {
            $this->oops('info is not properly JSON encoded', 1);
        }
        if (empty($info->response->attestationObject)) {
            $this->oops('no attestationObject in info', 1);
        }
        if (empty($info->rawId)) {
            $this->oops('no rawId in info');
        }

        /* check response from key and store as new identity. This is a hex string representing the raw CBOR
        attestation object received from the key */

        $aos = self::arrayToString($info->response->attestationObject);
        $ao = (object)(\CBOR\CBOREncoder::decode($aos));
        if (empty($ao)) {
            $this->oops('cannot decode key response (1)');
        }
        if (empty($ao->fmt)) {
            $this->oops('cannot decode key response (2)');
        }
        if (empty($ao->authData)) {
            $this->oops('cannot decode key response (3)');
        }
        $bs = $ao->authData->get_byte_string();

        if ($ao->fmt == 'fido-u2f') {
            $this->oops("cannot decode FIDO format responses, sorry");
        } elseif ($ao->fmt != 'none' && $ao->fmt != 'packed') {
            $this->oops('cannot decode key response (4)');
        }

        $ao->rpIdHash = substr($bs, 0, 32);
        $ao->flags = ord(substr($bs, 32, 1));
        $ao->counter = substr($bs, 33, 4);

        $hashId = hash('sha256', $this->appid, true);
        if ($hashId != $ao->rpIdHash) {
            //log(bin2hex($hashId).' '.bin2hex($ao->rpIdHash));
            $this->oops('cannot decode key response (5)');
        }

        if (! ($ao->flags & 0x41)) {
            $this->oops('cannot decode key response (6)');
        } /* TUP and AT must be set */

        $ao->attData = (object)array();
        $ao->attData->aaguid = substr($bs, 37, 16);
        $ao->attData->credIdLen = (ord($bs[53])<<8)+ord($bs[54]);
        $ao->attData->credId = substr($bs, 55, $ao->attData->credIdLen);
        $cborPubKey  = substr($bs, 55+$ao->attData->credIdLen); // after credId to end of string

        $ao->attData->keyBytes = self::COSEECDHAtoPKCS($cborPubKey);

        $rawId = self::arrayToString($info->rawId);
        if ($ao->attData->credId != $rawId) {
            $this->oops('cannot decode key response (16)');
        }

        $publicKey = (object)array();
        $publicKey->key = $ao->attData->keyBytes;
        $publicKey->id = $info->rawId;
        //log($publicKey->key);

        if (empty($userwebauthn)) {
            $userwebauthn = [$publicKey];
        } else {
            $userwebauthn = json_decode($userwebauthn);
            $found = false;
            foreach ($userwebauthn as $idx => $key) {
                if (implode(',', $key->id) != implode(',', $publicKey->id)) {
                    continue;
                }
                $userwebauthn[$idx]->key = $publicKey->key;
                $found = true;
                break;
            }
            if (! $found) {
                array_unshift($userwebauthn, $publicKey);
            }
        }
        $userwebauthn = json_encode($userwebauthn);
        return $userwebauthn;
    }

    /**
    * generates a new key string for the physical key, fingerprint
    * reader or whatever to respond to on login
    * @param string $userwebauthn the existing webauthn field for the user from your database
    * @return string to pass to javascript webauthnAuthenticate
    */
    public function prepareForLogin($userwebauthn)
    {
        $allow = (object)array();
        $allow->type = 'public-key';
        $allow->transports = array('usb','nfc','ble','internal');
        $allow->id = null;
        $allows = array();
        if (! empty($userwebauthn)) {
            foreach (json_decode($userwebauthn) as $key) {
                $allow->id = $key->id;
                $allows[] = clone $allow;
            }
        } else {
            /* including empty user, so they can't tell whether the user exists or not (need same result each
            time for each user) */
            // log("fabricating key");
            $allow->id = array();
            $rb = md5((string)time());
            $allow->id = self::stringToArray($rb);
            $allows[] = clone $allow;
        }

        /* generate key request */
        $publickey = (object)array();
        $publickey->challenge = self::stringToArray(self::randomBytes(16));
        $publickey->timeout = 60000;
        $publickey->allowCredentials = $allows;
        $publickey->userVerification = 'discouraged';
        $publickey->extensions = (object)array();
        $publickey->extensions->txAuthSimple = 'Execute order 66';
        $publickey->rpId = str_replace('https://', '', $this->appid);

        return json_encode($publickey);
    }

    /**
    * validates a response for login or 2fa
    * requires info from the hardware via javascript given below
    * @param string $info supplied to the PHP script via a POST, constructed by the Javascript given below, ultimately
    *        provided by the key
    * @param string $userwebauthn the exisiting webauthn field for the user from your
    *        database (it's actaully a JSON string, but that's entirely internal to
    *        this code)
    * @return boolean true for valid authentication or false for failed validation
    */
    public function authenticate($info, $userwebauthn)
    {
        if (! is_string($info)) {
            $this->oops('info must be a string', 1);
        }
        $info = json_decode($info);
        if (empty($info)) {
            $this->oops('info is not properly JSON encoded', 1);
        }
        $webauthn = empty($userwebauthn) ? array() : json_decode($userwebauthn);

        /* find appropriate key from those stored for user (usually there'll only be one, but if
        someone has, say, a physical yubikey on desktop and fingerprint reader on mobile, for
        example, may be more than one. */
        $key = null;
        foreach ($webauthn as $candkey) {
            if (implode(',', $candkey->id) != implode(',', $info->rawId)) {
                continue;
            }
            $key = $candkey;
            break;
        }
        if (empty($key)) {
            $this->oops("no key with id ".implode(',', $info->rawId));
        }

        /* cross-check challenge */
        $oc = rtrim(strtr(base64_encode(self::arrayToString($info->originalChallenge)), '+/', '-_'), '=');
        if ($oc != $info->response->clientData->challenge) {
            $this->oops("challenge mismatch");
        }

        /* cross check origin */
        $origin = parse_url($info->response->clientData->origin);
        if ($this->appid != $origin['host']) {
            $this->oops("origin mismatch '{$info->response->clientData->origin}'");
        }

        if ($info->response->clientData->type != 'webauthn.get') {
            $this->oops("type mismatch '{$info->response->clientData->type}'");
        }

        $bs = self::arrayToString($info->response->authenticatorData);
        $ao = (object)array();

        $ao->rpIdHash = substr($bs, 0, 32);
        $ao->flags = ord(substr($bs, 32, 1));
        $ao->counter = substr($bs, 33, 4);

        $hashId = hash('sha256', $this->appid, true);
        if ($hashId != $ao->rpIdHash) {
            // log(bin2hex($hashId).' '.bin2hex($ao->rpIdHash));
            $this->oops('cannot decode key response (2b)');
        }

        /* experience shows that at least one device (OnePlus 6T/Pie (Android phone)) doesn't set this,
        so this test would fail. This is not correct according to the spec, so  pragmatically it may
        have to be removed */
        if (($ao->flags & 0x1) != 0x1) {
            $this->oops('cannot decode key response (2c)');
        } /* only TUP must be set */

        /* assemble signed data */
        $clientdata = self::arrayToString($info->response->clientDataJSONarray);
        $signeddata = $hashId . chr($ao->flags) . $ao->counter . hash('sha256', $clientdata, true);

        if (count($info->response->signature) < 70) {
            $this->oops('cannot decode key response (3)');
        }

        $signature = self::arrayToString($info->response->signature);

        //$key = str_replace(chr(13), '', $key->key);
        $key = $key->key;
        // log($key);
        switch (@openssl_verify($signeddata, $signature, $key, OPENSSL_ALGO_SHA256)) {
        case 1:
        return true; /* hooray, we're in */
        case 0:
        return false;
        default:
        $this->oops('cannot decode key response (4) '.openssl_error_string());
    }

        return true;
    }

    /**
    * convert an array of uint8's to a binary string
    * @param array $a to be converted (array of unsigned 8 bit integers)
    * @return string converted to bytes
    */
    private static function arrayToString($a)
    {
        $s = '';
        foreach ($a as $c) {
            $s .= chr($c);
        }
        return $s;
    }

    /**
    * convert a binary string to an array of uint8's
    * @param string $s to be converted
    * @return array converted to array of unsigned integers
    */
    private static function stringToArray($s)
    {
        /* convert binary string to array of uint8 */
        $a = [];
        for ($idx = 0; $idx < strlen($s); $idx++) {
            $a[] = ord($s[$idx]);
        }
        return $a;
    }

    /**
    * convert a public key from the hardware to PEM format
    * @param string $key to be converted to PEM format
    * @return string converted to PEM format
    */
    private function pubkeyToPem($key)
    {
        /* see https://github.com/Yubico/php-u2flib-server/blob/master/src/u2flib_server/U2F.php */
        if (strlen($key) !== 65 || $key[0] !== "\x04") {
            return null;
        }
        /*
        * Convert the public key to binary DER format first
        * Using the ECC SubjectPublicKeyInfo OIDs from RFC 5480
        *
        *  SEQUENCE(2 elem)                        30 59
        *   SEQUENCE(2 elem)                       30 13
        *    OID1.2.840.10045.2.1 (id-ecPublicKey) 06 07 2a 86 48 ce 3d 02 01
        *    OID1.2.840.10045.3.1.7 (secp256r1)    06 08 2a 86 48 ce 3d 03 01 07
        *   BIT STRING(520 bit)                    03 42 ..key..
        */
        $der  = "\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01";
        $der .= "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42";
        $der .= "\x00".$key;
        $pem  = "-----BEGIN PUBLIC KEY-----\x0A";
        $pem .= chunk_split(base64_encode($der), 64, "\x0A");
        $pem .= "-----END PUBLIC KEY-----\x0A";
        return $pem;
    }

    /**
     * Convert COSE ECDHA to PKCS
     * @param string binary string to be converted
     * @return string converted public key
     */
    private function COSEECDHAtoPKCS($binary)
    {
        $cosePubKey = \CBOR\CBOREncoder::decode($binary);

        if (! isset($cosePubKey[3] /* cose_alg */)) {
            $this->oops('cannot decode key response (8)');
        }

        switch ($cosePubKey[3]) {
            case self::ES256:
                /* COSE Alg: ECDSA w/ SHA-256 */
                if (! isset($cosePubKey[-1] /* cose_crv */)) {
                    $this->oops('cannot decode key response (9)');
                }

                if (! isset($cosePubKey[-2] /* cose_crv_x */)) {
                    $this->oops('cannot decode key response (10)');
                }

                if ($cosePubKey[-1] != 1 /* cose_crv_P256 */) {
                    $this->oops('cannot decode key response (14)');
                }

                if (!isset($cosePubKey[-2] /* cose_crv_x */)) {
                    $this->oops('x coordinate for curve missing');
                }

                if (! isset($cosePubKey[1] /* cose_kty */)) {
                    $this->oops('cannot decode key response (7)');
                }

                if (! isset($cosePubKey[-3] /* cose_crv_y */)) {
                    $this->oops('cannot decode key response (11)');
                }

                if (!isset($cosePubKey[-3] /* cose_crv_y */)) {
                    $this->oops('y coordinate for curve missing');
                }

                if ($cosePubKey[1] != 2 /* cose_kty_ec2 */) {
                    $this->oops('cannot decode key response (12)');
                }

                $x = $cosePubKey[-2]->get_byte_string();
                $y = $cosePubKey[-3]->get_byte_string();
                if (strlen($x) != 32 || strlen($y) != 32) {
                    $this->oops('cannot decode key response (15)');
                }
                $tag = "\x04";
                return $this->pubkeyToPem($tag.$x.$y);
                break;
            case self::RS256:
                /* COSE Alg: RSASSA-PKCS1-v1_5 w/ SHA-256 */
                if (!isset($cosePubKey[-2])) {
                    $this->oops('RSA Exponent missing');
                }
                if (!isset($cosePubKey[-1])) {
                    $this->oops('RSA Modulus missing');
                }
                $e = new BigInteger(bin2hex($cosePubKey[-2]->get_byte_string()), 16);
                $n = new BigInteger(bin2hex($cosePubKey[-1]->get_byte_string()), 16);
                $rsa = new RSA();
                $rsa->loadKey(compact('e', 'n'));
                return $rsa->getPublicKey();
            default:
                $this->oops('cannot decode key response (13)');
        }
    }

    /**
    * shim for random_bytes which doesn't exist pre php7
    * @param int $length the number of bytes required
    * @return string length cryptographically random bytes
    */
    private static function randomBytes($length)
    {
      if (function_exists('random_bytes')) {
          return random_bytes($length);
      } else if (function_exists('openssl_random_pseudo_bytes')) {
          $bytes = openssl_random_pseudo_bytes($length, $crypto_strong);
          if (! $crypto_strong) {
              throw new \Exception("openssl_random_pseudo_bytes did not return a cryptographically strong result", 1);
          }
          return $bytes;
      } else {
          throw new \Exception("Neither random_bytes not openssl_random_pseudo_bytes exists. PHP too old? openssl PHP extension not installed?", 1);
      }
    }

    /**
    * just an abbreviation to throw an error: never returns
    * @param string $s error message
    * @param int $c error code (0 for user error, 1 for incorrect usage)
    *
    */
    private function oops($s, $c=0)
    {
        error_log("oops: {$s} {$c}");
        throw new \Exception($s, $c);
    }

    protected function getUrlSuffix()
    {
    }
}
