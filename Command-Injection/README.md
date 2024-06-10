# Command Injection

## About

> The purpose of the command injection attack is to inject and execute commands specified by the attacker in the vulnerable application. In situation like this, the application, which executes unwanted system commands, is like a pseudo system shell, and the attacker may use it as any authorized system user. However, commands are executed with the same privileges and environment as the web service has.
> 
> Command injection attacks are possible in most cases because of lack of correct input data validation, which can be manipulated by the attacker (forms, cookies, HTTP headers etc.).
> 
> The syntax and commands may differ between the Operating Systems (OS), such as Linux and Windows, depending on their desired actions.
> 
> This attack may also be called "Remote Command Execution (RCE)".

Source: DVWA Documentation

## Low Security
For this challenge, we have a ping functionality inside the web application and we need to input an IP address.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Command-Injection/!images/ci1.png?raw=true">
</p>

So if it were on command line, it would probably looks like this: `ping -c 4 $adress`.<br/>
We know that we can execute more commands using `;` delimiter, so let's try something like this:
`ping -c 4 $adress;whoami`

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Command-Injection/!images/ci2.png?raw=true">
</p>

It worked! We can also use `&&` operator, to specify command1 && (AND) command2.

Source code:
```php
<?php

if( isset( $_POST[ 'Submit' ]  ) ) {
    // Get input
    $target = $_REQUEST[ 'ip' ];

    // Determine OS and execute the ping command.
    if( stristr( php_uname( 's' ), 'Windows NT' ) ) {
        // Windows
        $cmd = shell_exec( 'ping  ' . $target );
    }
    else {
        // *nix
        $cmd = shell_exec( 'ping  -c 4 ' . $target );
    }

    // Feedback for the end user
    echo "<pre>{$cmd}</pre>";
}

?> 
```
With this control over a server, we are also able to create a reverse shell in order to get a full connection.

## Medium Security
The same bypass will not work again because we have some filters implemented.<br/>

Source code:
```php
// Set blacklist
    $substitutions = array(
        '&&' => '',
        ';'  => '',
    );
```
But we can use other types of command injection payloads.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Command-Injection/!images/ci3.png?raw=true">
</p>

`|` (pipe) will take the output of the first command and uses it as the input for the second command.<br/>
A good resource for payloads can be found here: https://github.com/swisskyrepo/PayloadsAllTheThings <br/>
Another way of executing commands is to use `&`, which will background the ping command.

## High Security
For High level, more filters have been implemented.<br/>

```php
// Get input
$target = trim($_REQUEST[ 'ip' ]);

// Set blacklist
$substitutions = array(
    '&'  => '',
    ';'  => '',
    '| ' => '',
    '-'  => '',
    '$'  => '',
    '('  => '',
    ')'  => '',
    '`'  => '',
    '||' => '',
); 
```
The description of the High level is this:
> The developer has either made a slight typo with the filters and believes a certain PHP command will save them from this mistake.

We can see in the source code that `|` is containing a space, so developers used `trim()` function in order to remove all the spaces from beginning and end.<br/>
In this case, `127.0.0.1|whoami` will not be recognized.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Command-Injection/!images/ci4.png?raw=true">
</p>

## Impossible Security
Source code:
```php
// Check Anti-CSRF token
checkToken( $_REQUEST[ 'user_token' ], $_SESSION[ 'session_token' ], 'index.php' );

// Get input
$target = $_REQUEST[ 'ip' ];
$target = stripslashes( $target );

// Split the IP into 4 octects
$octet = explode( ".", $target );

// Check IF each octet is an integer
if( ( is_numeric( $octet[0] ) ) && ( is_numeric( $octet[1] ) ) && ( is_numeric( $octet[2] ) ) && ( is_numeric( $octet[3] ) ) && ( sizeof( $octet ) == 4 ) ) {
    // If all 4 octets are int's put the IP back together.
    $target = $octet[0] . '.' . $octet[1] . '.' . $octet[2] . '.' . $octet[3];
```
Instead of black-listing all the elements that can lead to an injection, is more efficient to white-list the input that you expect to receive.<br/>
In this scenario, a strict filter was implemented to be sure that only IP addresses are inserted.<br/>
Even if the typo from High level hadn't been made, maybe a payload still exist that can bypass the list from the previous one. I am not aware of it. However, filtering by the input that you expect is a better implementation.