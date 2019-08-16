/*

This is key registration part of the client (browser) side of webauthn
authentication.

This really does little more than fetch the info from the physical key
or fingerprint reader etc, and repackage it in a palatable form for
sending to the server.

When registering a user account, or allowing them to add a key in their profile,
or whatever, request a challenge from $webauthn->challenge() (e.g. using Ajax)
and pass the resulting key string to
  webauthnRegister(key, callback)
where key is the contents of the hidden field (or however else you stored
the challenge string).

The function will ask the browser to identify their key or touch fingerprint
or whatever.

On completion it will call the callback function callback:
  function callback(success, info)
success is a boolean, true for successful acquisition of info from the key,
in which case pass the info back to the server, call $webauth->register to
validate it, and put the resulting string back in the user record for use
in future logins.

If success is false, then either info is the string 'abort', meaning the
user failed to complete the process, or an error message of whatever else
went wrong.

*/

function webauthnRegister(key, callback){
	key = JSON.parse(key);
	key.publicKey.attestation = undefined;
	key.publicKey.challenge = new Uint8Array(key.publicKey.challenge); // convert type for use by key
	key.publicKey.user.id = new Uint8Array(key.publicKey.user.id);

	// console.log(key);
	navigator.credentials.create({publicKey: key.publicKey})
		.then(function (aNewCredentialInfo) {
			// console.log("Credentials.Create response: ", aNewCredentialInfo);
			var cd = JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)));
			if (key.b64challenge != cd.challenge) {
				callback(false, 'key returned something unexpected (1)');
			}
			if ('https://'+key.publicKey.rp.name != cd.origin) {
				return callback(false, 'key returned something unexpected (2)');
			}
			if (! ('type' in cd)) {
				return callback(false, 'key returned something unexpected (3)');
			}
			if (cd.type != 'webauthn.create') {
				return callback(false, 'key returned something unexpected (4)');
			}

			var ao = [];
			(new Uint8Array(aNewCredentialInfo.response.attestationObject)).forEach(function(v){
				ao.push(v);
			});
			var rawId = [];
			(new Uint8Array(aNewCredentialInfo.rawId)).forEach(function(v){
				rawId.push(v);
			});
			var info = {
				rawId: rawId,
				id: aNewCredentialInfo.id,
				type: aNewCredentialInfo.type,
				response: {
					attestationObject: ao,
					clientDataJSON:
					  JSON.parse(String.fromCharCode.apply(null, new Uint8Array(aNewCredentialInfo.response.clientDataJSON)))
				}
			};
			callback(true, JSON.stringify(info));
		})
		.catch(function (aErr) {
			if (
				("name" in aErr) && (aErr.name == "AbortError" || aErr.name == "NS_ERROR_ABORT")
				|| aErr.name == 'NotAllowedError'
			) {
				callback(false, 'abort');
			} else {
				callback(false, aErr.toString());
			}
		});
}
