#!/usr/bin/env perl

### All the additional perl modules required for this script to run.
use Mojolicious::Lite;
use Mojo::mysql;
use Mojolicious::Plugin::DefaultHelpers;
use String::Random qw(random_regex random_string);
use strict;
use warnings;
use Crypt::CBC;
use Email::Valid;
use Email::Sender::Simple qw(sendmail);
use Email::Sender::Transport::SMTP ();
use Email::Simple ();
use Email::Simple::Creator ();
use MIME::Base64;
use Authen::SASL;

### Variables required for smtp to work, I use AWS SES smtp server myself.
my $smtpserver = '';
my $smtpport = 587;
my $smtpuser   = '';
my $smtppassword = '';

### Set a empty "myerror" variable. (no longer sure why i did this)
my $myerror;

### Initialize how we want to encrypt, we use AES with a 256bit key, you must specify a key yourself.
my $key = 'YOUR KEY HERE';
my $cipher = Crypt::CBC->new(
    -key       => $key,
    -keylength => '256',
    -cipher    => "Crypt::OpenSSL::AES"
);

### Initialize how we connect to MySQL.
my $mysql = Mojo::mysql->new('mysql://USERNAME:PASSWORD@localhost/CAPSTONE');

### Mojolicious route stuff.
get '/' => 'index';
get '/emailverification' => 'emailverification';
post '/emailverification' => sub {
  ### Initialize c variable.
  my $c = shift;

  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;
  
  ### Initialize user input from form.
  my $emailverificationcode = $c->req->body_params->param('emailverificationcode');

  ### Make sure user did input a code.
  if ($emailverificationcode eq "") 
  {
    my $myerror = 'Please fill in your email verification code.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'emailverification');
  }
  
  ### Verify if code exist in DB if not error, if exist change it to 0.
  my $VerifyDBEmailverificationcode = $db->query('SELECT COUNT(1) FROM users WHERE EmailVerification = (?)', $emailverificationcode)->text;
  if ($VerifyDBEmailverificationcode == 1)
  {
    $db->query('UPDATE users SET EmailVerification = "0" WHERE EmailVerification = (?)', $emailverificationcode);

    return $c->redirect_to('login/emailverified');
  } else {
    my $myerror = 'This code is not valid please check your email.';
    $c->stash(
                 myerror => $myerror,
                );

    return $c->render(template => 'emailverification');
  }
};
get '/index.html' => 'index';
get '/login' => 'login';
get '/login/emailverified' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  # Set a message to inform email has been verified.
  my $myerror = 'Email verification successful please login.';
  $c->stash( 
            myerror => $myerror, 
            );
} => 'login';
post '/login' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;
  
  ### Initialize user input from form.
  my $VerifyInputUsername = $c->req->body_params->param('username');
  my $VerifyInputPassword = $c->req->body_params->param('password');

  ### If user input is empty then error.
  if ($VerifyInputUsername eq "" | $VerifyInputPassword eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'login');
  }
  
  ### make sure username are only alphanumeric characters.
  if ($VerifyInputUsername !~ /^[a-zA-Z]+$/)
  {
    my $myerror = 'You can use only alphanumeric characters for "username"';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'login');
  }
  
  ### Verify if UserName exists in DB.
  my $DBUsernameMatch;
  my $VerifyDBUsername = $db->query('SELECT COUNT(1) FROM users WHERE UserName = (?)', $VerifyInputUsername);
  if ($VerifyDBUsername == 1) 
  {
    my $myerror = 'UserName or Password is invalid.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'login');
  } else {
    $DBUsernameMatch = "yes";
  }
  
  ### Decrypt password from DB and match with InputPassword.
  my $DBPasswordMatch;
  my $VerifyDBPassword = $db->query('SELECT Password FROM users WHERE UserName = (?)', $VerifyInputUsername)->text;
  my $DecryptedDBPassword = $cipher->decrypt_hex($VerifyDBPassword);

  if ($DecryptedDBPassword ne $VerifyInputPassword)
  {
    my $myerror = 'UserName or Password is invalid.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'login');
  } else {
    $DBPasswordMatch = "yes";
  }
  
  ### If username and password match then login.
  if ($DBPasswordMatch eq "yes" && $DBUsernameMatch eq "yes")
  {
    return $c->render(text => 'Logged in!');
  } else {
    return $c->render(text => 'Wrong username/password', status => 403);
  }
  
};
get '/register' => 'register';
post '/register' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### Get all the input variables from the form.  
  my $VerifyInputLastname = $c->req->body_params->param('lastname');
  my $VerifyInputFirstname = $c->req->body_params->param('firstname');
  my $VerifyInputEmail = $c->req->body_params->param('email');
  my $VerifyInputUsername = $c->req->body_params->param('username');
  my $VerifyInputPassword = $c->req->body_params->param('password');
  my $VerifyInputPasswordverify = $c->req->body_params->param('passwordverify');
  
  ### Check if any field is empty if so error.  
  if ($VerifyInputLastname eq "" | $VerifyInputFirstname eq "" | $VerifyInputEmail eq "" | $VerifyInputUsername eq "" | $VerifyInputPassword eq "" | $VerifyInputPasswordverify eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }

  ### Make sure first name, lastname and username are only alphanumeric characters.
  if ($VerifyInputLastname !~ /^[a-zA-Z]+$/ | $VerifyInputFirstname !~ /^[a-zA-Z]+$/ | $VerifyInputUsername !~ /^[a-zA-Z]+$/){
    my $myerror = 'You can use only alphanumeric characters for "username"';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }
  
  ### Check the the inputed email is really a email.
  if (Email::Valid->address($VerifyInputEmail)) {
  # meh no idea how to only check wrong.
  } else {
    my $myerror = 'You did not input a valid email';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register'); 
  }
  
  ### Verify that user typed same password twice.
  if ($VerifyInputPassword ne $VerifyInputPasswordverify | $VerifyInputPasswordverify ne $VerifyInputPassword){
    my $myerror = 'passwords did not match';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register'); 
  }
  
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;

  ### Verify user input of UserName if it already exists in DB.
  my $VerifyDBUsername = $db->query('SELECT COUNT(1) FROM users WHERE Username = (?)', $VerifyInputUsername)->text;
  if ($VerifyDBUsername == 1) 
  {
    my $myerror = 'UserName is invalid or already in use please choose another one.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }
  
  ### Verify user input of Email if it already exists in DB.
  my $VerifyDBEmail = $db->query('SELECT COUNT(1) FROM users WHERE Email = (?)', $VerifyInputEmail)->text;
  if ($VerifyDBEmail == 1) 
  {
    my $myerror = 'Email not valid or already registered please choose another Email.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }

  ### Encrypt users password.
  my $EncryptedPassword = $cipher->encrypt_hex($c->req->body_params->param('password'));
  
  ## Set random string for email verification.
  my $emailverification = random_string("CCcnCnnCcc");
  
  ### Insert all encrypted information into "users" table in DB.
  $db->query('INSERT INTO users (LastName, FirstName, Email, UserName, Password, EmailVerification, MFAEnabled) VALUES (?, ?, ?, ?, ?, ?, ?)', $VerifyInputLastname, $VerifyInputFirstname, $VerifyInputEmail, $VerifyInputUsername, $EncryptedPassword, $emailverification, 'no');
  
  ### Sent the Email Verification code to user specified email address with encrypted smtp.
  my $transport = Email::Sender::Transport::SMTP->new({
    host => $smtpserver,
    port => $smtpport,
    ssl => "starttls",
    sasl_username => $smtpuser,
    sasl_password => $smtppassword,
  });

  my $smtpemail = Email::Simple->create(
    header => [
      To      => "$VerifyInputEmail",
      From    => 'hello@ulyaoth.net',
      Subject => 'Verify Email - Cybersecurity Capston Project',
    ],
    body => "Please verify your email with this code: $emailverification\n url: https://cybersecurity-capstone-project.ulyaoth.net/emailverification",
  );

  sendmail($smtpemail, { transport => $transport });
  
  ### Move user web page to email verification.
  $c->redirect_to('emailverification');
  };
  

### Mojolicious html templates.
app->start;
__DATA__
@@ login.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Login</title>
<style>
@import url(https://fonts.googleapis.com/css?family=Roboto:300);

.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
.form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 45px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
.form input {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
.form button {
  font-family: "Roboto", sans-serif;
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
.form button:hover,.form button:active,.form button:focus {
  background: #43A047;
}
.form .message {
  margin: 15px 0 0;
  color: #b3b3b3;
  font-size: 12px;
}
.form .message a {
  color: #4CAF50;
  text-decoration: none;
}
.form .register-form {
  display: none;
}
.container {
  position: relative;
  z-index: 1;
  max-width: 300px;
  margin: 0 auto;
}
.container:before, .container:after {
  content: "";
  display: block;
  clear: both;
}
.container .info {
  margin: 50px auto;
  text-align: center;
}
.container .info h1 {
  margin: 0 0 15px;
  padding: 0;
  font-size: 36px;
  font-weight: 300;
  color: #1a1a1a;
}
.container .info span {
  color: #4d4d4d;
  font-size: 12px;
}
.container .info span a {
  color: #000000;
  text-decoration: none;
}
.container .info span .fa {
  color: #EF3B3A;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  font-family: "Roboto", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;      
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="login-page">
<center><font size="6"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
  <div class="form">
    <form class="login-form" action="/login" method="post">
	  <input type="text" name="username" placeholder="Username"/>
      <input type="password" name="password" placeholder="Password"/>
      <button>login</button>
      <p class="message">Not registered? <a href="register">Create an account</a></p>
	  <p class="message">Verify your email? <a href="emailverification">Verify Email</a></p>
    </form>
  </div>
</div>
</body>

</html>

@@ index.html.ep
%= include 'login'

@@ register.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Register</title>
<style>
@import url(https://fonts.googleapis.com/css?family=Roboto:300);

.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
.form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 45px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
.form input {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
.form button {
  font-family: "Roboto", sans-serif;
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
.form button:hover,.form button:active,.form button:focus {
  background: #43A047;
}
.form .message {
  margin: 15px 0 0;
  color: #b3b3b3;
  font-size: 12px;
}
.form .message a {
  color: #4CAF50;
  text-decoration: none;
}
.form .register-form {
  display: none;
}
.container {
  position: relative;
  z-index: 1;
  max-width: 300px;
  margin: 0 auto;
}
.container:before, .container:after {
  content: "";
  display: block;
  clear: both;
}
.container .info {
  margin: 50px auto;
  text-align: center;
}
.container .info h1 {
  margin: 0 0 15px;
  padding: 0;
  font-size: 36px;
  font-weight: 300;
  color: #1a1a1a;
}
.container .info span {
  color: #4d4d4d;
  font-size: 12px;
}
.container .info span a {
  color: #000000;
  text-decoration: none;
}
.container .info span .fa {
  color: #EF3B3A;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  font-family: "Roboto", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;      
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="login-page">
<center><font size="6"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
  <div class="form">
    <form class="login-form" action="/register" method="post">
	  <input type="text" name="username" placeholder="Username"/>
      <input type="password" name="password" placeholder="Password"/>
	  <input type="password" name="passwordverify" placeholder="Type your password again"/>
      <input type="text" name="firstname" placeholder="First Name"/>
	  <input type="text" name="lastname" placeholder="Last Name"/>
	  <input type="text" name="email" placeholder="Email"/>
      <button>register</button>
      <p class="message">Already registered? <a href="login">Sign In</a></p>
	  <p class="message">Verify your email? <a href="emailverification">Verify Email</a></p>
    </form>
  </div>
</div>
</body>

</html>

@@ emailverification.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Register</title>
<style>
@import url(https://fonts.googleapis.com/css?family=Roboto:300);

.login-page {
  width: 360px;
  padding: 8% 0 0;
  margin: auto;
}
.form {
  position: relative;
  z-index: 1;
  background: #FFFFFF;
  max-width: 360px;
  margin: 0 auto 100px;
  padding: 45px;
  text-align: center;
  box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
}
.form input {
  font-family: "Roboto", sans-serif;
  outline: 0;
  background: #f2f2f2;
  width: 100%;
  border: 0;
  margin: 0 0 15px;
  padding: 15px;
  box-sizing: border-box;
  font-size: 14px;
}
.form button {
  font-family: "Roboto", sans-serif;
  text-transform: uppercase;
  outline: 0;
  background: #4CAF50;
  width: 100%;
  border: 0;
  padding: 15px;
  color: #FFFFFF;
  font-size: 14px;
  -webkit-transition: all 0.3 ease;
  transition: all 0.3 ease;
  cursor: pointer;
}
.form button:hover,.form button:active,.form button:focus {
  background: #43A047;
}
.form .message {
  margin: 15px 0 0;
  color: #b3b3b3;
  font-size: 12px;
}
.form .message a {
  color: #4CAF50;
  text-decoration: none;
}
.form .register-form {
  display: none;
}
.container {
  position: relative;
  z-index: 1;
  max-width: 300px;
  margin: 0 auto;
}
.container:before, .container:after {
  content: "";
  display: block;
  clear: both;
}
.container .info {
  margin: 50px auto;
  text-align: center;
}
.container .info h1 {
  margin: 0 0 15px;
  padding: 0;
  font-size: 36px;
  font-weight: 300;
  color: #1a1a1a;
}
.container .info span {
  color: #4d4d4d;
  font-size: 12px;
}
.container .info span a {
  color: #000000;
  text-decoration: none;
}
.container .info span .fa {
  color: #EF3B3A;
}
body {
  background: #76b852; /* fallback for old browsers */
  background: -webkit-linear-gradient(right, #76b852, #8DC26F);
  background: -moz-linear-gradient(right, #76b852, #8DC26F);
  background: -o-linear-gradient(right, #76b852, #8DC26F);
  background: linear-gradient(to left, #76b852, #8DC26F);
  font-family: "Roboto", sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;      
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="login-page">
<center><font size="6"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
  <div class="form">
    <form class="login-form" action="/emailverification" method="post">
	  <input type="text" name="emailverificationcode" placeholder="Email verification code."/>
      <button>Verify Email</button>
      <p class="message">Already registered? <a href="login">Sign In</a></p>
	  <p class="message">No yet registered? <a href="register">Register Now</a></p>
    </form>
  </div>
</div>
</body>

</html>