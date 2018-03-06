#!/usr/bin/env perl

### All the additional perl modules required for this script to run.
use Mojolicious::Lite;
use Mojo::mysql;
use Mojolicious::Plugin::DefaultHelpers;
use Mojolicious::Plugin::Authentication;
use Mojolicious::Sessions;
use Mojolicious::Plugin::RenderFile;
use Mojo::Util qw(secure_compare);
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
use DateTime;

plugin 'RenderFile';

### Variables required for smtp to work, I use AWS SES smtp server myself.
my $smtpserver = '';
my $smtpport = 587;
my $smtpuser   = '';
my $smtppassword = '';

### Set a empty "myerror" variable. (no longer sure why i did this)
my $myerror;

### Initialize how we want to encrypt, we use AES with a 256bit key, you must specify a key yourself.
my $key = 'YOUR SECRET KEY HERE';
my $cipher = Crypt::CBC->new(
    -key       => $key,
    -keylength => '256',
    -cipher    => "Crypt::OpenSSL::AES"
);

### Initialize how we connect to MySQL.
my $mysql = Mojo::mysql->new('mysql://USERNAME:PASSWORD@localhost/CAPSTONE');

### Mojolicious route stuff.
get '/'  => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### if the user is authenticated then go to login.
  $c->redirect_to('member') unless ($c->session('authenticated') != 1);
} => 'index';
get '/dbdump' => sub {
  ### Initialize c variable.
  my $c = shift;

  ### Download database dump file
  $c->render_file('filepath' => '/srv/capstone/public/dbdump/dbdump.sql');
};
get '/member' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### if the user is not authenticated then go to login.
  $c->redirect_to('login') unless ($c->session('authenticated') == 1);
  
  ### Show the member area.
  $c->render('member');
};
get '/member/inbox' => sub {
  ### Initialize c variable.
  my $c = shift;
 
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;
 
  ### if the user is not authenticated then go to login.
  $c->redirect_to('login') unless ($c->session('authenticated') == 1);
 
  my $results = $db->query('select from_user, datetime, message from messages where to_user = (?) order by datetime', $c->session('username'));
  my $rows = $results->arrays;
  for my $row (@$rows) { $row->[2] = $cipher->decrypt_hex($row->[2]) }  
  $c->stash( rows => $rows );
 
  ### Show the inbox.
  $c->render('inbox');
};
get '/member/sendmessages' => sub {
  ### Initialize c variable.
  my $c = shift;
 
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;
 
  ### if the user is not authenticated then go to login.
  $c->redirect_to('login') unless ($c->session('authenticated') == 1);
 
  ### Show the member area.
  $c->render('sendmessages');
};
post '/member/sendmessages' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;
    
  ### Initialize user input from form.
  my $VerifyInputReceiverUsername = $c->req->body_params->param('receiverusername');
  my $VerifyInputMembermessage = $c->req->body_params->param('membermessage');
  
  ### Make sure user did input all fields.
  if ($VerifyInputReceiverUsername eq "" || $VerifyInputMembermessage eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
              myerror => $myerror,
             ); 
                                 
    return $c->render(template => 'sendmessages');
  }
  
  ### make sure username are only alphanumeric characters.
  if ($VerifyInputReceiverUsername !~ /^[a-zA-Z0-9]+$/)
  {
    my $myerror = 'You can use only a-z, A-Z, 0-9 characters for the receivers "username"';
    $c->stash( 
              myerror => $myerror,
                ); 
                                 
    return $c->render(template => 'sendmessages');
  }

  ### Do not sent message to yourself.
  if ($VerifyInputReceiverUsername eq $c->session('username'))
  {
    my $myerror = 'Why would you message yourself?';
    $c->stash( 
              myerror => $myerror,
                ); 
                                 
    return $c->render(template => 'sendmessages');
  }
  
  ### Check if receivers name exist.
  my $VerifyDBUsername = $db->query('SELECT COUNT(1) FROM users WHERE UserName = (?)', $VerifyInputReceiverUsername)->text;
  $VerifyDBUsername =~ s/\W//g;
  if ($VerifyDBUsername != 1) 
  {
    my $myerror = 'Receivers Username does not exist.';
    $c->stash( 
              myerror => $myerror,
                ); 
                                 
    return $c->render(template => 'sendmessages');
  }
  
  ### Insert messages into database.
  my $EncryptedMessage = $cipher->encrypt_hex($VerifyInputMembermessage);
  my $dt = DateTime->now;
  $db->query('INSERT INTO messages (to_user, from_user, message, datetime) VALUES (?, ?, ?, ?)', $VerifyInputReceiverUsername, $c->session('username'), $EncryptedMessage, $dt);

  my $myerror = 'Your message has been sent!.';
  $c->stash( 
              myerror => $myerror,
           ); 

  return $c->render(template => 'sendmessages');  
};
get '/member/messages' => sub {
  ### Initialize c variable.
  my $c = shift;
 
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;
 
  ### if the user is not authenticated then go to login.
  $c->redirect_to('login') unless ($c->session('authenticated') == 1);
 
  my $results = $db->query('select from_user, datetime, message from messages where to_user = (?) order by datetime', $c->session('username'));
  my $rows = $results->arrays;
  for my $row (@$rows) { $row->[2] = $cipher->decrypt_hex($row->[2]) }  
  $c->stash( rows => $rows );
 
  ### Show the member area.
  $c->render('messages');
};
post '/member/messages' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;

  my $results = $db->query('select from_user, datetime, message from messages where to_user = (?) order by datetime', $c->session('username'));
  my $rows = $results->arrays;
  for my $row (@$rows) { $row->[2] = $cipher->decrypt_hex($row->[2]) }  
  $c->stash( rows => $rows );
    
  ### Initialize user input from form.
  my $VerifyInputReceiverUsername = $c->req->body_params->param('receiverusername');
  my $VerifyInputMembermessage = $c->req->body_params->param('membermessage');
  
  ### Make sure user did input all fields.
  if ($VerifyInputReceiverUsername eq "" || $VerifyInputMembermessage eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
              myerror => $myerror,
			  rows => $rows,
             ); 
                                 
    return $c->render(template => 'messages');
  }
  
  ### make sure username are only alphanumeric characters.
  if ($VerifyInputReceiverUsername !~ /^[a-zA-Z0-9]+$/)
  {
    my $myerror = 'You can use only a-z, A-Z, 0-9 characters for the receivers "username"';
    $c->stash( 
              myerror => $myerror,
			  rows => $rows,
                ); 
                                 
    return $c->render(template => 'messages');
  }

  ### Do not sent message to yourself.
  if ($VerifyInputReceiverUsername eq $c->session('username'))
  {
    my $myerror = 'Why would you message yourself?';
    $c->stash( 
              myerror => $myerror,
			  rows => $rows,
                ); 
                                 
    return $c->render(template => 'messages');
  }
  
  ### Check if receivers name exist.
  my $VerifyDBUsername = $db->query('SELECT COUNT(1) FROM users WHERE UserName = (?)', $VerifyInputReceiverUsername)->text;
  $VerifyDBUsername =~ s/\W//g;
  if ($VerifyDBUsername != 1) 
  {
    my $myerror = 'Receivers Username does not exist.';
    $c->stash( 
              myerror => $myerror,
			  rows => $rows,
                ); 
                                 
    return $c->render(template => 'messages');
  }
  
  ### Insert messages into database.
  my $EncryptedMessage = $cipher->encrypt_hex($VerifyInputMembermessage);
  my $dt = DateTime->now;
  $db->query('INSERT INTO messages (to_user, from_user, message, datetime) VALUES (?, ?, ?, ?)', $VerifyInputReceiverUsername, $c->session('username'), $EncryptedMessage, $dt);

  my $myerror = 'Your message has been sent!.';
  $c->stash( 
              myerror => $myerror,
			  rows => $rows,
           ); 

  return $c->render(template => 'messages');  
};
get '/source' => sub {
  ### Initialize c variable.
  my $c = shift;

  ### Download database dump file
  $c->render_file('filepath' => '/srv/capstone/public/source/source.zip');
};
get '/member/mysettings' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### if the user is not authenticated then go to login.
  $c->redirect_to('login') unless ($c->session('authenticated') == 1);
  
  ### Show the member area.
  $c->render('member');
};
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
  
  ### Verify if code exist in DB if not error, if exist change it to verified.
  my $VerifyDBEmailverificationcode = $db->query('SELECT COUNT(1) FROM users WHERE EmailVerification = (?)', $emailverificationcode)->text;
  if ($VerifyDBEmailverificationcode == 1)
  {
    $db->query('UPDATE users SET EmailVerification = "verified" WHERE EmailVerification = (?)', $emailverificationcode);

    return $c->redirect_to('login/emailverified');
  } else {
    my $myerror = 'This code is not valid please check your email.';
    $c->stash(
                 myerror => $myerror,
                );

    return $c->render(template => 'emailverification');
  }
};
get '/logout' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### if the user is authenticated continue else go to login.
  $c->redirect_to('login') unless ($c->session('authenticated') == 1);
  
  ### Expire session if user is authenticated to logout.
  $c->session(expires => 1);
  
  ### Redirect to login page.
  $c->redirect_to('login');
};
get '/index.html' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### if the user is authenticated then go to member area.
  $c->redirect_to('member') unless ($c->session('authenticated') != 1);
} => 'index';
get '/login' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### if the user is authenticated then go to member area.
  $c->redirect_to('member') unless ($c->session('authenticated') != 1);
} => 'login';
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
  if ($VerifyInputUsername eq "" || $VerifyInputPassword eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'login');
  }
  
  ### make sure username are only alphanumeric characters.
  if ($VerifyInputUsername !~ /^[a-zA-Z0-9]+$/)
  {
    my $myerror = 'You can use only a-z, A-Z, 0-9 characters for "username"';
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

  ### If username and password match then set a session and go to member area.
  if ($DBPasswordMatch eq "yes" && $DBUsernameMatch eq "yes")
  {
    my $CheckEmailVerification = $db->query('SELECT EmailVerification FROM users WHERE UserName = (?)', $VerifyInputUsername)->text;
	$CheckEmailVerification =~ s/\W//g;
    if ($CheckEmailVerification ne 'verified') 
    {
      return $c->redirect_to('emailverification');
    }

	$c->session( 'username' => $VerifyInputUsername );
	$c->session( 'authenticated' => 1 );
	$c->redirect_to('member');
  } else {
    my $myerror = 'UserName or Password is invalid.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'login');
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
  if ($VerifyInputLastname eq "" || $VerifyInputFirstname eq "" || $VerifyInputEmail eq "" || $VerifyInputUsername eq "" || $VerifyInputPassword eq "" || $VerifyInputPasswordverify eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'register');
  }

  ### Make sure first name, lastname and username are only alphanumeric characters.
  if ($VerifyInputLastname !~ /^[a-zA-Z]+$/ || $VerifyInputFirstname !~ /^[a-zA-Z]+$/ || $VerifyInputUsername !~ /^[a-zA-Z0-9]+$/){
    my $myerror = 'You can use only a-z A-Z characters for Fristname/Lastname and a-z, A-Z, 0-9 for Username.';
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
  
  
  ### Verify that user uses atleast 8 characters password.
  if (length($VerifyInputPassword) < 8){
    my $myerror = 'Password is not atleast 8 characters.';
    $c->stash( 
                 myerror => $myerror, 
                );
    return $c->render(template => 'register'); 
  }
  
  ### Verify that user typed same password twice.
  if ($VerifyInputPassword ne $VerifyInputPasswordverify || $VerifyInputPasswordverify ne $VerifyInputPassword){
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
get '/requestpasswordreset' => 'requestpasswordreset';
post '/requestpasswordreset' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### Get all the input variables from the form.  
  my $VerifyInputEmail = $c->req->body_params->param('passwordresetemail');

  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;

  ### Verify user input of UserName if it already exists in DB.
  my $VerifyDBEmail = $db->query('SELECT COUNT(1) FROM users WHERE Email = (?)', $VerifyInputEmail)->text;
  if ($VerifyDBEmail == 1) 
  {
  ## Set random string for password reset code.
  my $passwordresetcode = random_string("CCcnCnnCcc");
  
  ### Insert all encrypted information into "users" table in DB.
  $db->query('UPDATE users SET PasswordVerification = (?) WHERE Email = (?)', $passwordresetcode, $VerifyInputEmail);
  
  ### Sent the password reset code to user specified email address with encrypted smtp.
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
      Subject => 'Password Reset Code - Cybersecurity Capston Project',
    ],
    body => "Please use this code to reset your password, if you did not request this password reset than simply ignore this email: $passwordresetcode\n url: https://cybersecurity-capstone-project.ulyaoth.net/resetpassword",
  );

  sendmail($smtpemail, { transport => $transport });
  
  ### Move user to reset password page.
  $c->redirect_to('resetpassword');
  } else {
  ### Move user to reset password page.
  $c->redirect_to('resetpassword');
  };
};
get '/resetpassword'  => 'resetpassword';
post '/resetpassword' => sub {
  ### Initialize c variable.
  my $c = shift;
  
  ### Get all the input variables from the form.  
  my $VerifyInputPasswordresetcode = $c->req->body_params->param('passwordresetcode');
  my $VerifyInputNewpassword = $c->req->body_params->param('newpassword');
  my $VerifyInputNewpassword2 = $c->req->body_params->param('newpassword2');  
  
  $VerifyInputPasswordresetcode =~ s/\W//g;
  
  ### Initialize DB variable for MySQL access.
  my $db = $mysql->db;

    ### Check if any field is empty if so error.  
  if ($VerifyInputPasswordresetcode eq "" || $VerifyInputNewpassword eq "" || $VerifyInputNewpassword2 eq "") 
  {
    my $myerror = 'Please fill in all fields.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
    return $c->render(template => 'resetpassword');
  }
  
  ### Verify that user uses atleast 8 characters password.
  if (length($VerifyInputNewpassword) < 8){
    my $myerror = 'Password is not atleast 8 characters.';
    $c->stash( 
                 myerror => $myerror, 
                );
	return $c->render(template => 'resetpassword');
  }
  
  ### Verify that user typed same password twice.
  if ($VerifyInputNewpassword ne $VerifyInputNewpassword2 || $VerifyInputNewpassword2 ne $VerifyInputNewpassword){
    my $myerror = 'new passwords did not match';
    $c->stash( 
                 myerror => $myerror, 
                ); 
                                 
	return $c->render(template => 'resetpassword');
  }
  
  ### Verify user input of UserName if it already exists in DB.
  my $VerifyDBPasswordresetcode = $db->query('SELECT COUNT(1) FROM users WHERE PasswordVerification = (?)', $VerifyInputPasswordresetcode)->text;
  if ($VerifyDBPasswordresetcode == 1) 
  {
  
  ## Set random string for password reset code.
  my $passwordresetcode = random_string("CCcnCnnCcc");

  ### Encrypt users password.
  my $EncryptedPassword = $cipher->encrypt_hex($VerifyInputNewpassword);
  
  ### Insert all encrypted information into "users" table in DB.
  $db->query('UPDATE users SET Password = (?) WHERE PasswordVerification = (?)', $EncryptedPassword, $VerifyInputPasswordresetcode);
  $db->query('UPDATE users SET PasswordVerification = (?) WHERE Password = (?)', $passwordresetcode, $EncryptedPassword);

  my $myerror = 'Password reset was successful';
  $c->stash( 
            myerror => $myerror, 
            ); 
  
  return $c->render(template => 'login');
  
  
  } else {
    my $myerror = 'Password Verification Code does not exist.';
    $c->stash( 
                 myerror => $myerror, 
                ); 
	return $c->render(template => 'resetpassword');
  }
  
  return $c->render(template => 'resetpassword');
};

  
### Set a app secret  
app->secrets(['YOUR SECRET KEY HERE']);

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

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project</b><p><font></center>
<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/login" method="post">
	  <input type="text" name="username" placeholder="Username"/>
      <input type="password" name="password" placeholder="Password"/>
      <button>login</button>
      <p class="message">Not registered? <a href="register">Create an account</a></p>
	  <p class="message">Reset Password? <a href="requestpasswordreset">Reset Password</a></p>
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

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project - Register</b><p></font></center>
<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p></font></center>
<div class="login-page">
  <div class="form">
  	  <p><font size="1">Username: min 3 char, letters a-zA-Z, numbers 0-9</font>
      <p><font size="1">Password: min 8 char<font>
	  <p><font size="1">Firstname: max 50 char, letters a-zA-Z</font>
	  <p><font size="1">Lastname: max 50 char, letters a-zA-Z</font></p>
    <form class="login-form" action="/register" method="post">
	  <input type="text" name="username" placeholder="Username"/>
      <input type="password" name="password" placeholder="Password"/>
	  <input type="password" name="passwordverify" placeholder="Type your password again"/>
      <input type="text" name="firstname" placeholder="First Name"/>
	  <input type="text" name="lastname" placeholder="Last Name"/>
	  <input type="text" name="email" placeholder="Email"/>
      <button>register</button>
      <p class="message">Already registered? <a href="login">Sign In</a></p>
	  <p class="message">Reset Password? <a href="requestpasswordreset">Reset Password</a></p>
	  <p class="message">Verify your email? <a href="emailverification">Verify Email</a></p>
    </form>
</div>
</body>

</html>

@@ emailverification.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Email Verification</title>
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

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project - Email Verification</b><p><font></center>
<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/emailverification" method="post">
	  <input type="text" name="emailverificationcode" placeholder="Email verification code."/>
      <button>Verify Email</button>
      <p class="message">Already registered? <a href="https://cybersecurity-capstone-project.ulyaoth.net/login">Sign In</a></p>
	  <p class="message">No yet registered? <a href="https://cybersecurity-capstone-project.ulyaoth.net/register">Register Now</a></p>
	  <p class="message">Reset password? <a href="https://cybersecurity-capstone-project.ulyaoth.net/requestpasswordreset">Reset Password</a></p>
    </form>
  </div>
</div>
</body>

</html>

@@ requestpasswordreset.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Request Password Reset</title>
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

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project - Request Password Reset</b><p><font></center>
<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/requestpasswordreset" method="post">
	  <input type="text" name="passwordresetemail" placeholder="Your email."/>
      <button>Request Code</button>
      <p class="message">Already registered? <a href="login">Sign In</a></p>
	  <p class="message">No yet registered? <a href="register">Register Now</a></p>
    </form>
  </div>
</div>
</body>

</html>

@@ resetpassword.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Reset Password</title>
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

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project - Reset Password</b><p><font></center>
<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/resetpassword" method="post">
	  <input type="text" name="passwordresetcode" placeholder="Your password reset code."/>
	  <input type="password" name="newpassword" placeholder="Your new password."/>
	  <input type="password" name="newpassword2" placeholder="Your new password again."/>
      <button>Reset Password</button>
      <p class="message">Already registered? <a href="login">Sign In</a></p>
	  <p class="message">No yet registered? <a href="register">Register Now</a></p>
    </form>
  </div>
</div>
</body>

</html>


@@ not_found.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Not Found</title>
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

.sidenav {
    width: 250px;
    position: fixed;
    z-index: 1;
    top: 20px;
    left: 10px;
    background: #FFFFFF;
    overflow-x: hidden;
    padding: 8px 0;
}

.sidenav a {
    font-family: "Lato", sans-serif;
    padding: 6px 8px 6px 16px;
    text-decoration: none;
    font-size: 25px;
    color: #2196F3;
    display: block;
}

.sidenav a:hover {
    color: #064579;
}

.main {
    margin-left: 140px; /* Same width as the sidebar + left position in px */
    font-size: 28px; /* Increased text to enable scrolling */
    padding: 0px 10px;
}

@media screen and (max-height: 450px) {
    .sidenav {padding-top: 15px;}
    .sidenav a {font-size: 18px;}
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="sidenav">
  <a href="https://cybersecurity-capstone-project.ulyaoth.net">Home</a>
</div>

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project</b><p><font></center>
<div class="login-page">
  <div class="form">
      <center><font size="6"><p style="color:green"><b>404 Not Found!</b><p><font></center>
	  <center><font size="3"><p style="color:green"><b>Please use the menu on the left to go back to our home page.</b><p><font></center>
    </form>
  </div>
</div>
</body>

</html>

@@ exception.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Exception</title>
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

.sidenav {
    width: 250px;
    position: fixed;
    z-index: 1;
    top: 20px;
    left: 10px;
    background: #FFFFFF;
    overflow-x: hidden;
    padding: 8px 0;
}

.sidenav a {
    font-family: "Lato", sans-serif;
    padding: 6px 8px 6px 16px;
    text-decoration: none;
    font-size: 25px;
    color: #2196F3;
    display: block;
}

.sidenav a:hover {
    color: #064579;
}

.main {
    margin-left: 140px; /* Same width as the sidebar + left position in px */
    font-size: 28px; /* Increased text to enable scrolling */
    padding: 0px 10px;
}

@media screen and (max-height: 450px) {
    .sidenav {padding-top: 15px;}
    .sidenav a {font-size: 18px;}
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="sidenav">
  <a href="https://cybersecurity-capstone-project.ulyaoth.net">Home</a>
</div>

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project</b><p><font></center>
<div class="login-page">
  <div class="form">
      <center><font size="6"><p style="color:green"><b>500 Exception!</b><p><font></center>
	  <center><font size="3"><p style="color:green"><b>Please use the menu on the left to go back to our home page.</b><p><font></center>
    </form>
  </div>
</div>
</body>

</html>

@@ member.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Member</title>
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

.sidenav {
    width: 250px;
    position: fixed;
    z-index: 1;
    top: 20px;
    left: 10px;
    background: #FFFFFF;
    overflow-x: hidden;
    padding: 8px 0;
}

.sidenav a {
    font-family: "Lato", sans-serif;
    padding: 6px 8px 6px 16px;
    text-decoration: none;
    font-size: 25px;
    color: #2196F3;
    display: block;
}

.sidenav a:hover {
    color: #064579;
}

.main {
    margin-left: 140px; /* Same width as the sidebar + left position in px */
    font-size: 28px; /* Increased text to enable scrolling */
    padding: 0px 10px;
}

@media screen and (max-height: 450px) {
    .sidenav {padding-top: 15px;}
    .sidenav a {font-size: 18px;}
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="sidenav">
  <b><a href="/member" style="color:red">Home</a></b>
  <a href="/member/inbox">inbox</a>
  <a href="/member/sendmessages">Send Messages</a>
  <a href="/member/messages">Messages (beta)</a>
  <a href="/member/downloaddb">Download DB</a>
  <a href="/member/downloadsource">Download Source</a>
  <a href="/member/mysettings">My Settings</a>
  <a href="/logout">Logout</a>
</div>

<center><font size="6"><p style="color:white"><b>Cybersecurity CAPSTONE Project</b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/message" method="post">
      <center><font size="6"><p style="color:green"><b>Welcome to the Members area!</b><p><font></center>
	  <center><font size="3"><p style="color:green"><b>Please use the menu on the left to choose what you wish to do.</b><p><font></center>
    </form>
  </div>
</div>
</body>

</html>

@@ messages.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Messages</title>
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

.sidenav {
    width: 250px;
    position: fixed;
    z-index: 1;
    top: 20px;
    left: 10px;
    background: #FFFFFF;
    overflow-x: hidden;
    padding: 8px 0;
}

.sidenav a {
    font-family: "Lato", sans-serif;
    padding: 6px 8px 6px 16px;
    text-decoration: none;
    font-size: 25px;
    color: #2196F3;
    display: block;
}

.sidenav a:hover {
    color: #064579;
}

.main {
    margin-left: 140px; /* Same width as the sidebar + left position in px */
    font-size: 28px; /* Increased text to enable scrolling */
    padding: 0px 10px;
}

@media screen and (max-height: 450px) {
    .sidenav {padding-top: 15px;}
    .sidenav a {font-size: 18px;}
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="sidenav">
  <a href="/member">Home</a>
  <a href="/member/inbox">inbox</a>
  <a href="/member/sendmessages">Send Messages</a>
  <b><a href="/member/messages" style="color:red">Messages (beta)</a></b>
  <a href="https://cybersecurity-capstone-project.ulyaoth.net/dbdump">Download DB</a>
  <a href="https://cybersecurity-capstone-project.ulyaoth.net/source">Download Source</a>
  <a href="/member/mysettings">My Settings</a>
  <a href="/logout">Logout</a>
</div>

<center>
  <br>
  Arrived messages: <br>
  <table border="1">
    <tr>
      <th>From User</th>
	  <th>Date</th>
	  <th>Message</th>
    </tr>
    % foreach my $row (@$rows) {
      <tr>
        % foreach my $text (@$row) {
          <td><%= $text %></td>
        % }
      </tr>
    % }
  </table>
</center>

<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/member/messages" method="post">
	  <input type="text" name="receiverusername" placeholder="Receivers Username"/>
      <textarea name="membermessage" rows="10" cols="30"></textarea>
	  <button>Send Message</button>
    </form>
  </div>
</div>
</body>

</html>

@@ inbox.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Inbox</title>
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

.sidenav {
    width: 250px;
    position: fixed;
    z-index: 1;
    top: 20px;
    left: 10px;
    background: #FFFFFF;
    overflow-x: hidden;
    padding: 8px 0;
}

.sidenav a {
    font-family: "Lato", sans-serif;
    padding: 6px 8px 6px 16px;
    text-decoration: none;
    font-size: 25px;
    color: #2196F3;
    display: block;
}

.sidenav a:hover {
    color: #064579;
}

.main {
    margin-left: 140px; /* Same width as the sidebar + left position in px */
    font-size: 28px; /* Increased text to enable scrolling */
    padding: 0px 10px;
}

@media screen and (max-height: 450px) {
    .sidenav {padding-top: 15px;}
    .sidenav a {font-size: 18px;}
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="sidenav">
  <a href="/member">Home</a>
  <b><a href="/member/inbox" style="color:red">inbox</a></b>
  <a href="/member/sendmessages">Send Messages</a>
  <a href="/member/messages">Messages (beta)</a>
  <a href="https://cybersecurity-capstone-project.ulyaoth.net/dbdump">Download DB</a>
  <a href="https://cybersecurity-capstone-project.ulyaoth.net/source">Download Source</a>
  <a href="/member/mysettings">My Settings</a>
  <a href="/logout">Logout</a>
</div>

<center>
  <br>
  <font size="6"><p style="color:white"><b>Your Inbox</b><p><font> <br>
  <table border="1">
    <tr>
      <th>From User</th>
	  <th>Date</th>
	  <th>Message</th>
    </tr>
    % foreach my $row (@$rows) {
      <tr>
        % foreach my $text (@$row) {
          <td><%= $text %></td>
        % }
      </tr>
    % }
  </table>
</center>
</body>

</html>


@@ sendmessages.html.ep
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Cybersecurity Capstone Project - Send Messages</title>
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

.sidenav {
    width: 250px;
    position: fixed;
    z-index: 1;
    top: 20px;
    left: 10px;
    background: #FFFFFF;
    overflow-x: hidden;
    padding: 8px 0;
}

.sidenav a {
    font-family: "Lato", sans-serif;
    padding: 6px 8px 6px 16px;
    text-decoration: none;
    font-size: 25px;
    color: #2196F3;
    display: block;
}

.sidenav a:hover {
    color: #064579;
}

.main {
    margin-left: 140px; /* Same width as the sidebar + left position in px */
    font-size: 28px; /* Increased text to enable scrolling */
    padding: 0px 10px;
}

@media screen and (max-height: 450px) {
    .sidenav {padding-top: 15px;}
    .sidenav a {font-size: 18px;}
}
</style>
<script>
$('.message a').click(function(){
   $('form').animate({height: "toggle", opacity: "toggle"}, "slow");
});
</script>
</head>

<body>
<div class="sidenav">
  <a href="/member">Home</a>
  <a href="/member/inbox">inbox</a>
  <b><a href="/member/sendmessages" style="color:red">Send Messages</a></b>
  <a href="/member/messages">Messages (beta)</a>
  <a href="https://cybersecurity-capstone-project.ulyaoth.net/dbdump">Download DB</a>
  <a href="https://cybersecurity-capstone-project.ulyaoth.net/source">Download Source</a>
  <a href="/member/mysettings">My Settings</a>
  <a href="/logout">Logout</a>
</div>

<center><font size="6"><p style="color:white"><b>Send Messages</b><p><font></center>
<center><font size="4"><p style="color:red"><b><%= stash "myerror" %></b><p><font></center>
<div class="login-page">
  <div class="form">
    <form class="login-form" action="/member/sendmessages" method="post">
	  <input type="text" name="receiverusername" placeholder="Receivers Username"/>
      <textarea name="membermessage" rows="10" cols="30"></textarea>
	  <button>Send Message</button>
    </form>
  </div>
</div>
</body>

</html>