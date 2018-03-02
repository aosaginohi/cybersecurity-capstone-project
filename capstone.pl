#!/usr/bin/env perl
use Mojolicious::Lite;
use Mojo::mysql;
use Mojolicious::Plugin::DefaultHelpers;
use String::Random qw(random_regex random_string);
use strict;
use warnings;
use Crypt::CBC;
use Email::Valid;

my $myerror;
my $key = 'YOU SECRET KET!';
my $cipher = Crypt::CBC->new(
    -key       => $key,
    -keylength => '256',
    -cipher    => "Crypt::OpenSSL::AES"
);

my $mysql = Mojo::mysql->new('mysql://USERNAME:PASSWORD@localhost/CAPSTONE');

get '/' => 'index';
get '/index.html' => 'index';
get '/login' => 'index';
get '/register' => 'register';
post '/register' => sub {
  my $c = shift;
  
  my $VerifyInputLastname = $c->req->body_params->param('lastname');
  my $VerifyInputFirstname = $c->req->body_params->param('firstname');
  my $VerifyInputEmail = $c->req->body_params->param('email');
  my $VerifyInputUsername = $c->req->body_params->param('username');
  my $VerifyInputPassword = $c->req->body_params->param('password');
  my $VerifyInputPasswordverify = $c->req->body_params->param('passwordverify');
    
  if ($VerifyInputLastname eq "" | $VerifyInputFirstname eq "" | $VerifyInputEmail eq "" | $VerifyInputUsername eq "" | $VerifyInputPassword eq "" | $VerifyInputPasswordverify eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }

  if ($VerifyInputLastname !~ /^[a-zA-Z]+$/ | $VerifyInputFirstname !~ /^[a-zA-Z]+$/ | $VerifyInputUsername !~ /^[a-zA-Z]+$/){
    my $myerror = 'You can use only alphanumeric characters for "username"';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }
  
  if (Email::Valid->address($VerifyInputEmail)) {
  # meh no idea how to only check wrong.
  } else {
    my $myerror = 'You did not input a valid email';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register'); 
  }
  
  if ($VerifyInputPassword ne $VerifyInputPasswordverify | $VerifyInputPasswordverify ne $VerifyInputPassword){
    my $myerror = 'passwords did not match';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register'); 
  }
  
  my $lastname = $cipher->encrypt_hex($c->req->body_params->param('lastname'));
  my $firstname = $cipher->encrypt_hex($c->req->body_params->param('firstname'));
  my $email = $cipher->encrypt_hex($c->req->body_params->param('email'));
  my $username = $cipher->encrypt_hex($c->req->body_params->param('username'));
  my $password = $cipher->encrypt_hex($c->req->body_params->param('password'));
  my $emailverification = random_string("..........");

  my $db = $mysql->db;
  $db->query('INSERT INTO users (LastName, FirstName, Email, UserName, Password, EmailVerification) VALUES (?, ?, ?, ?, ?, ?)', $lastname, $firstname, $email, $username, $password, $emailverification);
  
  $c->render(template => 'index');
  };
  


app->start;
__DATA__
@@ index.html.ep
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
<div class="login-page" action="/login" method="post">
  <div class="form">
    <form class="login-form">
      <input type="text" placeholder="Username"/>
      <input type="password" placeholder="Password"/>
      <button>login</button>
      <p class="message">Not registered? <a href="register">Create an account</a></p>
    </form>
  </div>
</div>
</body>

</html>

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
    </form>
  </div>
</div>
</body>

</html>