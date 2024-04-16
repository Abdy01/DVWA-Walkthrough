# Brute Force

## About

> Password cracking is the process of recovering passwords from data that has been stored in or transmitted by a computer system. A common approach is to repeatedly try guesses for the password.<br/>
> Users often choose weak passwords. Examples of insecure choices include single words found in dictionaries, family names, any too short password (usually thought to be less than 6 or 7 characters), or predictable patterns (e.g. alternating vowels and consonants, which is known as leetspeak, so "password" becomes "p@55w0rd").<br/>
> Creating a targeted wordlists, which is generated towards the target, often gives the highest success rate. There are public tools out there that will create a dictionary based on a combination of company websites, personal social networks and other common information (such as birthdays or year of graduation).<br/>
> A last resort is to try every possible password, known as a brute force attack. In theory, if there is no limit to the number of attempts, a brute force attack will always be successful since the rules for acceptable passwords must be publicly known; but as the length of the password increases, so does the number of possible passwords making the attack time longer.

Source: DVWA Documentation

## Low Security
For this challenge we have a login form with username and password. Different tools can be used to brute-force a login form.<br/>
Hydra is a very common tool that people usually use, but for DVWA laboratory Hydra is creating a lot of issues. Because of this, we will use ffuf.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf1.png?raw=true">
</p>

First, we will make a login attemtp and then we will save the request in a file named request.txt. I used Burp Suite to see the request.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf2.png?raw=true">
</p>

We will change the password entered with the word `FFUF`, to let the tool know where to insert the password.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf3.png?raw=true">
</p>

The command:
`ffuf -request request.txt -request-proto http -w /usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt -fs 4290`

`-fs` is used to exclude all the responses with 4290 size. If we don't use this, we will get all the attempts printed in the console.<br/>
Using this flag, the tool will return the other attempts with different size, which should be the successful ones.

The password found is `password`. We already know that from the beginning, but let's try the other users.<br/>
We can enumerate them if we already exploited the SQL database, or we can check the path of the photo that can be found after a successfully login.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf4.png?raw=true">
</p>

So, after we login with admin:password, we have this photo, which can be found at: http://localhost/DVWA/hackable/users/admin.jpg. If we check /hackable/users we will get this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf5.png?raw=true">
</p>

Let's create a list with these usernames:
- admin
- 1337
- gordonb
- pablo
- smithy

We will edit again the request.txt and add `USERFUZZ` for username and `PASSFUZZ` for password.
`GET /DVWA/vulnerabilities/brute/?username=USERFUZZ&password=PASSFUZZ&Login=Login HTTP/1.1 ...`

Command:
`ffuf -request request.txt -request-proto http -mode clusterbomb -w /home/kali/users.txt:USERFUZZ -w /usr/share/wordlists/rockyou.txt:PASSFUZZ -fs 4290`

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf6.png?raw=true">
</p>

Source code:
```php
<?php

if( isset( $_GET[ 'Login' ] ) ) {
    // Get username
    $user = $_GET[ 'username' ];

    // Get password
    $pass = $_GET[ 'password' ];
    $pass = md5( $pass );

    // Check the database
    $query  = "SELECT * FROM `users` WHERE user = '$user' AND password = '$pass';";
    $result = mysqli_query($GLOBALS["___mysqli_ston"],  $query ) or die( '<pre>' . ((is_object($GLOBALS["___mysqli_ston"])) ? mysqli_error($GLOBALS["___mysqli_ston"]) : (($___mysqli_res = mysqli_connect_error()) ? $___mysqli_res : false)) . '</pre>' );

    if( $result && mysqli_num_rows( $result ) == 1 ) {
        // Get users details
        $row    = mysqli_fetch_assoc( $result );
        $avatar = $row["avatar"];

        // Login successful
        echo "<p>Welcome to the password protected area {$user}</p>";
        echo "<img src=\"{$avatar}\" />";
    }
    else {
        // Login failed
        echo "<pre><br />Username and/or password incorrect.</pre>";
    }

    ((is_null($___mysqli_res = mysqli_close($GLOBALS["___mysqli_ston"]))) ? false : $___mysqli_res);
}

?> 
```

## Medium Security
For Medium level we can see that we have to wait a few moments until the login attempt is made.<br/>
Checking the source code we can observe this:
```php
else {
      // Login failed
      sleep( 2 );
      echo "<pre><br />Username and/or password incorrect.</pre>";
    }
```

This is not really a security measure, will just increase the time of the brute-force process.<br/>
I will make the test for gordonb user with `500-worst-passwords.txt` from https://github.com/danielmiessler/SecLists/blob/master/Passwords/500-worst-passwords.txt.<br/>
To be sure that the application will not crash, I set the number of threads to be 1.

`ffuf -request request.txt -request-proto http -w /usr/share/wordlists/seclists/Passwords/500-worst-passwords.txt -fs 4290 -t 1`.<br/>

We can see that the process took longer.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf7.png?raw=true">
</p>

## High Security
For High level we have an anti Cross-Site Request Forgery (CSRF) token implemented, and when there is a failed login, the waiting time is a random amount of time between zero and three seconds, which will confuse any timing prediction. Sometimes we will get an error message immediately and sometimes after 3 seconds.<br/>
We will use Burp Suite for this challenge.<br/>
Now we have an user_token that is sent everytime with the login request. If the token is not the right one, we will get an error.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf8.png?raw=true">
</p>

The token is hidden in the login page and a new one is generated if the login is not valid.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf9.png?raw=true">
</p>

Ok, so in order to exploit this, we will send the request to Intruder.<br/>
Set as target the password and the user_token. Set the Attack Type to Pitchfork.<br/>
The first payload will be Simple list containing the list of passwords and the second one will be set to Recursive grep.<br/>
Go to Settings, clear Grep Match list, add Grep Extract and select the user_token value.<br/>
Redirections should be set to Always.<br/>
Now the attack can start.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf10.png?raw=true">
</p>

With the Pitchfork option we will go with one password and one user_token per request.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf11.png?raw=true">
</p>

If you didn't understand these steps very well, I recommend you to check CryptoCat DVWA walkthrough playlist on Youtube.

## Impossible Security
For this level a lock out feature was implemented. So after a few failed attempts, the account will be locked for 15 minutes.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Brute-Force/!images/bf12.png?raw=true">
</p>

In this case, the brute-force attack will take too long to succeed.<br/>
Another implementation is that after a certain number of failed attempts, the account is locked and even the right password will not work. The error message will be `Username or password is incorrect.`, so the attacker will not know that the account was locked.

## Bonus
The login form is also vulnerable to Blind SQL Injection. Try sqlmap for this.