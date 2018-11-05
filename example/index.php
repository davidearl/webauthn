<?php

/*
If you put the whole webauthn directory in the www document root and put an index.php in there 
which just includes this file, it should then work. Alternatively set it as a link to this file.
*/
 
include_once($_SERVER['DOCUMENT_ROOT'].'/webauthn/src/webauthn.php');

/* from https://github.com/2tvenom/CBOREncode :  */
include_once($_SERVER['DOCUMENT_ROOT'].'/CBOREncode/src/CBOR/CBOREncoder.php');
include_once($_SERVER['DOCUMENT_ROOT'].'/CBOREncode/src/CBOR/Types/CBORByteString.php');
include_once($_SERVER['DOCUMENT_ROOT'].'/CBOREncode/src/CBOR/CBORExceptions.php');

/* In this example, the user database is simply a directory of json files 
  named by their username (urlencoded so there are no weird characters 
  in the file names). For simplicity, it's in the HTML tree so someone 
  could look at it - you really, really don't want to do this for a 
  live system */
define('USER_DATABASE', dirname(dirname(__DIR__)).'/.users');
if (! file_exists(USER_DATABASE)) {
  if (! @mkdir(USER_DATABASE)) {
    error_log('Cannot create user database directory - is the html directory writable by the web server? If not: "mkdir .users; chmod 777 .users"');
    die("cannot create .users - see error log");
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

/* A post is an ajax request, otherwise display the page */
if (! empty($_POST)) {

  try {
  
    $webauthn = new davidearl\webauthn\WebAuthn($_SERVER['HTTP_HOST']);

    switch(TRUE){

    case isset($_POST['registerusername']):
      /* initiate the registration */
      $username = $_POST['registerusername'];
      
      $userid = md5(time() . '-'. rand(1,1000000000));

      if (file_exists(userpath($username))) {
        oops("user '{$username}' already exists");
      }

      /* Create a new user in the database. In principle, you can store more 
         than one key in the user's webauthnkeys,
         but you'd probably do that from a user profile page rather than initial 
         registration. The procedure is the same, just don't cancel existing 
         keys like this.*/
      file_put_contents(userpath($username), json_encode(['name'=> $username,
                                                          'id'=> $userid,
                                                          'webauthnkeys' => $webauthn->cancel()]));
      $_SESSION['username'] = $username;
      $j = ['challenge' => $webauthn->prepare_challenge_for_registration($username, $userid)];
      break;

    case isset($_POST['register']):
      /* complete the registration */
      if (empty($_SESSION['username'])) { oops('username not set'); }
      $user = getuser($_SESSION['username']);

      /* The heart of the matter */
      $user->webauthnkeys = $webauthn->register($_POST['register'], $user->webauthnkeys);

      /* Save the result to enable a challenge to be raised agains this 
         newly created key in order to log in */
      file_put_contents(userpath($user->name), json_encode($user));
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

      $j['challenge'] = $webauthn->prepare_for_login($user->webauthnkeys);
      break;

    case isset($_POST['login']):
      /* authenticate the login */
      if (empty($_SESSION['loginname'])) { oops('username not set'); }
      $user = getuser($_SESSION['loginname']);

      if (! $webauthn->authenticate($_POST['login'], $user->webauthnkeys)) {
        http_response_code(401);
        echo 'failed to authticate with that key';
        exit;
      }
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
		<input type='submit' value='Submit'>
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

<script src='/webauthn/src/webauthnregister.js'></script>
<script src='/webauthn/src/webauthnauthenticate.js'></script>
<!-- only for the example, the webauthn js does not need jquery itself -->
<script src='https://code.jquery.com/jquery-3.3.1.min.js'></script>

<script>
  $(function(){

	$('#iregisterform').submit(function(ev){
		var self = $(this);
		ev.preventDefault();
		$('.cerror').empty().hide();
		
		$.ajax({url: '/',
				method: 'POST',
				data: {registerusername: self.find('[name=registerusername]').val()},
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
