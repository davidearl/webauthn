<?php

/*
If you put the whole webauthn directory in the www document root and put an index.php in there
which just includes this file, it should then work. Alternatively set it as a link to this file.
*/

require_once(dirname(__DIR__).'/vendor/autoload.php');

/* In this example, the user database is simply a directory of json files
  named by their username (urlencoded so there are no weird characters
  in the file names). For simplicity, it's in the HTML tree so someone
  could look at it - you really, really don't want to do this for a
  live system */
define('USER_DATABASE', dirname(dirname(__DIR__)).'/.users');
if (! file_exists(USER_DATABASE)) {
  if (! @mkdir(USER_DATABASE)) {
    error_log(sprintf('Cannot create user database directory - is the html directory writable by the web server? If not: "mkdir %s; chmod 777 %s"', USER_DATABASE, USER_DATABASE));
    die(sprintf("cannot create %s - see error log", USER_DATABASE));
  }
}
session_start();

function oops($s){
  http_response_code(400);
  echo "{$s}\n";
  exit;
}

function userpath($username){
  $username = str_replace('.', '%2E', $username);
  return sprintf('%s/%s.json', USER_DATABASE, urlencode($username));
}

function getuser($username){
  $user = @file_get_contents(userpath($username));
  if (empty($user)) { oops('user not found'); }
  $user = json_decode($user);
  if (empty($user)) { oops('user not json decoded'); }
  return $user;
}

function saveuser($user){
  file_put_contents(userpath($user->name), json_encode($user));
}

/* A post is an ajax request, otherwise display the page */
if (! empty($_POST)) {

  try {

    $webauthn = new \Davidearl\WebAuthn\WebAuthn($_SERVER['HTTP_HOST']);

    switch(TRUE){

    case isset($_POST['registerusername']):
      /* initiate the registration */
      $username = $_POST['registerusername'];
      $crossplatform = ! empty($_POST['crossplatform']) && $_POST['crossplatform'] == 'Yes';
      $userid = md5(time() . '-'. rand(1,1000000000));

      if (file_exists(userpath($username))) {
        oops("user '{$username}' already exists");
      }

      /* Create a new user in the database. In principle, you can store more
         than one key in the user's webauthnkeys,
         but you'd probably do that from a user profile page rather than initial
         registration. The procedure is the same, just don't cancel existing
         keys like this.*/
      $user = (object)['name'=> $username,
                       'id'=> $userid,
                       'webauthnkeys' => $webauthn->cancel()];
      saveuser($user);
      $_SESSION['username'] = $username;
      $j = ['challenge' => $webauthn->prepareChallengeForRegistration($username, $userid, $crossplatform)];
      break;

    case isset($_POST['register']):
      /* complete the registration */
      if (empty($_SESSION['username'])) { oops('username not set'); }
      $user = getuser($_SESSION['username']);

      /* The heart of the matter */
      $user->webauthnkeys = $webauthn->register($_POST['register'], $user->webauthnkeys);

      /* Save the result to enable a challenge to be raised agains this
         newly created key in order to log in */
      saveuser($user);
      $j = 'ok';

      break;

    case isset($_POST['loginusername']):
      /* initiate the login */
      $username = $_POST['loginusername'];
      $user = getuser($username);
      $_SESSION['loginname'] = $user->name;

      /* note: that will emit an error if username does not exist. That's not
         good practice for a live system, as you don't want to have a way for
         people to interrogate your user database for existence */

      $j['challenge'] = $webauthn->prepareForLogin($user->webauthnkeys);

      /* Save user again, which sets server state to include the challenge expected */
      saveuser($user);
      break;

    case isset($_POST['login']):
      /* authenticate the login */
      if (empty($_SESSION['loginname'])) { oops('username not set'); }
      $user = getuser($_SESSION['loginname']);

      if (! $webauthn->authenticate($_POST['login'], $user->webauthnkeys)) {
        http_response_code(401);
        echo 'failed to authenticate with that key';
        exit;
      }
      /* Save user again, which sets server state to include the challenge expected */
      saveuser($user);
      $j = 'ok';

      break;

    default:
      http_response_code(400);
      echo "unrecognized POST\n";
      break;
    }

  } catch(Exception $ex) {
    oops($ex->getMessage());
  }

  header('Content-type: application/json');
  echo json_encode($j);
  exit;
}

?><!doctype html>
<html>
<head>
<title>webauthn php server side example and test</title>
<style>
body {
  font-family: Verdana, sans-serif;
}
h1 {
  font-size: 1.5em;
}
h2 {
  font-size: 1.2em;
}
.ccontent {
  display: flex;
  flex-wrap: wrap;
  margin: 10px;
}
.cbox {
  width: 100%;
  max-width: 480px;
  min-height: 150px;
  border: 1px solid black;
  padding: 10px;
  margin: 10px;
  line-height: 2;
}
.cdokey {
  display: none;
  background-color: orange;
  color: white;
  font-weight: bold;
  margin: 10px 0;
  padding: 10px;
}
.cerror {
  display: none;
  background-color: tomato;
  color: white;
  padding: 10px;
  font-weight: bold;
}
.cdone {
  display: none;
  background-color: darkgreen;
  color: white;
  padding: 10px;
  font-weight: bold;
}
.chint {
  max-width: 450px;
  margin-left: 2em;
}
</style>

</head>
<body>
  <h1>webauthn php server side example and test</h1>
  <ul>
	<li><a href='https://github.com/davidearl/webauthn'>GitHub</a>
  </ul>

  <div class='cerror'></div>
  <div class='cdone'></div>

  <div class='ccontent'>

	<div class='cbox' id='iregister'>
	  <h2>User Registration</h2>
	  <form id='iregisterform' action='/' method='POST'>
		<label> enter a new username (eg email address): <input type='text' name='registerusername'></label><br>
        cross-platform?<sup>*</sup> <select name='cp'>
          <option value=''>(choose one)</option>
          <option>No</option>
          <option>Yes</option>
        </select><br>
		<input type='submit' value='Submit'><br>
	  </form>
	  <div class='cdokey' id='iregisterdokey'>
		Do your thing: press button on key, swipe fingerprint or whatever
	  </div>
	</div>

	<div class='cbox' id='ilogin'>
	  <h2>User Login</h2>
	  <form id='iloginform' action='/' method='POST'>
		<label> enter existing username: <input type='text' name='loginusername'></label><br>
		<input type='submit' value='Submit'>
	  </form>
	  <div class='cdokey' id='ilogindokey'>
		Do your thing: press button on key, swipe fingerprint or whatever
	  </div>

	</div>

  </div>

  <p class='chint'>* Use cross-platform 'Yes' when you have a removable device, like
  a Yubico key, which you would want to use to login on different
  computers; say 'No' when your device is attached to the computer (in
  that case in Windows 10 1903 release, your login
  is linked to Windows Hello and you can use any device it supports
  whether registered with that device or not, but only on that
  computer). The choice affects which device(s) are offered by the
  browser and/or computer security system.</p>
  
<script type="application/javascript">
<?php
echo file_get_contents(dirname(__DIR__).'/src/webauthnregister.js');
echo file_get_contents(dirname(__DIR__).'/src/webauthnauthenticate.js');
?>

</script>

<!-- only for the example, the webauthn js does not need jquery itself -->
<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>

<script>
  $(function(){

	$('#iregisterform').submit(function(ev){
		var self = $(this);
		ev.preventDefault();
		var cp = $('select[name=cp]').val();
		if (cp == "") {
			$('.cerror').show().text("Please choose cross-platform setting - see note below about what this means");
			return;
		}
		
		$('.cerror').empty().hide();

		$.ajax({url: '/',
				method: 'POST',
				data: {registerusername: self.find('[name=registerusername]').val(), crossplatform: cp},
				dataType: 'json',
				success: function(j){
					$('#iregisterform,#iregisterdokey').toggle();
					/* activate the key and get the response */
					webauthnRegister(j.challenge, function(success, info){
						if (success) {
							$.ajax({url: '/',
									method: 'POST',
									data: {register: info},
									dataType: 'json',
									success: function(j){
										$('#iregisterform,#iregisterdokey').toggle();
										$('.cdone').text("registration completed successfully").show();
										setTimeout(function(){ $('.cdone').hide(300); }, 2000);
									},
									error: function(xhr, status, error){
										$('.cerror').text("registration failed: "+error+": "+xhr.responseText).show();
									}
								   });
						} else {
							$('.cerror').text(info).show();
						}
					});
				},

				error: function(xhr, status, error){
					$('#iregisterform').show();
					$('#iregisterdokey').hide();
					$('.cerror').text("couldn't initiate registration: "+error+": "+xhr.responseText).show();
				}
			   });
	});

	$('#iloginform').submit(function(ev){
		var self = $(this);
		ev.preventDefault();
		$('.cerror').empty().hide();

		$.ajax({url: '/',
				method: 'POST',
				data: {loginusername: self.find('[name=loginusername]').val()},
				dataType: 'json',
				success: function(j){
					$('#iloginform,#ilogindokey').toggle();
					/* activate the key and get the response */
					webauthnAuthenticate(j.challenge, function(success, info){
						if (success) {
							$.ajax({url: '/',
									method: 'POST',
									data: {login: info},
									dataType: 'json',
									success: function(j){
										$('#iloginform,#ilogindokey').toggle();
										$('.cdone').text("login completed successfully").show();
										setTimeout(function(){ $('.cdone').hide(300); }, 2000);
									},
									error: function(xhr, status, error){
										$('.cerror').text("login failed: "+error+": "+xhr.responseText).show();
									}
								   });
						} else {
							$('.cerror').text(info).show();
						}
					});
				},

				error: function(xhr, status, error){
					$('#iloginform').show();
					$('#ilogindokey').hide();
					$('.cerror').text("couldn't initiate login: "+error+": "+xhr.responseText).show();
				}
			   });
	});

});
</script>

</body>
</html>
