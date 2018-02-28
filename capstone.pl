#!/usr/bin/env perl
use Mojolicious::Lite;
use Mojo::mysql;

my $mysql = Mojo::mysql->new('mysql://USERNAME:PASSWORD@localhost/CAPSTONE');

get '/' => 'index';
get '/index.html' => 'index';
get '/register' => 'register';
post '/register' => sub {
  my ($mojo) = @_;
  my $lastname = $mojo->param("lastname");
  my $firstname = $mojo->param("firstname");
  my $email = $mojo->param("email");
  my $username = $mojo->param("username");
  my $password = $mojo->param("password");

  my $db = $mysql->db;
  $db->query('insert into users (LastName) values (?)', "$lastname");
  $db->query('insert into users (FirstName) values (?)', "$firstname");
  $db->query('insert into users (Email) values (?)', "$email");
  $db->query('insert into users (UserName) values (?)', "$username");
  $db->query('insert into users (Password) values (?)', "$password");
};


app->start;
__DATA__
@@ index.html.ep
<HTML>
<HEAD><TITLE>Cybersecurity Capstone Project - Login</TITLE>
</HEAD>
<BODY bgcolor="000000" text="ffffff"><p><b>Cybersecurity Capstone Project - Login</b><hr><p>

<center>
<table cellpadding=1 cellspacing=0 border="0">
<form method=post action="login" target=_top>
<tr><td colspan=2><center><b></center></b></td></tr>
<tr><td align=right><b>Username </b></td><td align=left> <input size=14 maxlength=100 type=text name="username" value=""></td></tr>
<tr><td align=right><b>Password </b></td><td align=left> <input size=14 maxlength=100 type=text name="password" value=""></td></tr>
<input type=hidden name="a" value="login">
<tr><td colspan=2 align=center><input type=submit VALUE="Enter Message System"></td></tr>
</form></table></center><p></body>
<center><a href="register">Register your account</a> | <a href="https://github.com/sbagmeijer/cybersecurity-capstone-project">Download Source Code</a></center>
</HTML>

@@ register.html.ep
<HEAD><title>Cybersecurity Capstone Project - Registration</TITLE>
<BODY BGCOLOR="000000" TEXT="FFFFFF" onLoad="window.status='Cybersecurity Capstone Project - Registration'">
<b><center>Cybersecurity Capstone Project - Registration</center>

<FORM METHOD="POST" name="m" ACTION="register">

<center><table width=500><tr><td><b><font size=-1>

Choose a username:<br>

<INPUT type="text" name="username" maxlength=21 value=""><p>

Choose a password.(please use a sentence):<br>

<INPUT type="password" name="password" maxlength=100 value=""><p>

Input the Same Password again (verification):<br>

<INPUT type="password" name="passwordverify" maxlength=100 value=""><p>

Input your E-mail Address:<br>

<INPUT type="text" name="email" maxlength=700 value=""><p>

Fill in your First Name:<br>

<INPUT type="text" name="firstname" maxlength=50 value=""><p>

Fill in your Surname:<br>

<INPUT type="text" name="lastname" maxlength=50 value=""><p>

<center><INPUT TYPE=SUBMIT Value=" SUBMIT FORM "></center>
</table></center>
<br>
<center><a href="index.html">Already registered? Login here.</a></center>
</body></html>