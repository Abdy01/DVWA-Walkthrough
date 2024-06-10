# Authorisation Bypass

## About
> When developers have to build authorisation matrices into complex systems it is easy for them to miss adding the right checks in every place, especially those which are not directly accessible through a browser, for example API calls.
> 
> As a tester, you need to be looking at every call a system makes and then testing it using every level of user to ensure that the checks are being carried out correctly. This can often be a long and boring task, especially with a large matrix with lots of different user types, but it is critical that the testing is carried out as one missed check could lead to an attacker gaining access to confidential data or functions. 

Source: DVWA Documentation

## Low Security
On this page we can see and update some of the users' details. This page can be accessed only with the Admin account.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab1.png?raw=true">
</p>

The goal is to access and modify these details using other user. We will use gordonb for this.<br/>
First, we can see that Authorisation Bypass endpoint is not available in the menu for gordonb. But access it directly from the URL will let us enter.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab2.png?raw=true">
</p>

Furthermore, we can also update users' details.

Source code:
```php
if (dvwaCurrentUser() == "admin") {
			$menuBlocks[ 'vulnerabilities' ][] = array( 'id' => 'authbypass', 'name' => 'Authorisation Bypass', 'url' => 'vulnerabilities/authbypass/' );
		}
// This code can be found in other location.		
```

## Medium Security
Now, if we try to access again /authbypass/ we will get an Unauthorised message.<br/>
Let's check what other requests are made on this functionality.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab3.png?raw=true">
</p>

So, we have a "get_user_data.php" file and a POST request at "change_user_details.php".<br/>
If we try to access "get_user_data.php" directly, we will get this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab4.png?raw=true">
</p>

Great! We still have access on the data. This can also be visited in the browser.<br/>
What about the POST request?

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab5.png?raw=true">
</p>

We got a successfully response, cool! That means that only the access to /authbypass/ endpoint was restricted.<br/>
However, an attacker still needs to know about "get_user_data.php" and "change_user_details.php", in order to exploit this.<br/>
For example if the attacker find "change_user_details.php", the attacker still need to know the format of the POST request. However, this is not a problem in our case...

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab6.png?raw=true">
</p>

The HTTP response tells us everything we need to know. This is not a good security measure.

Source code:
```php
<?php
/*
Only the admin user is allowed to access this page.
Have a look at these two files for possible vulnerabilities: 

* vulnerabilities/authbypass/get_user_data.php
* vulnerabilities/authbypass/change_user_details.php
*/

if (dvwaCurrentUser() != "admin") {
    print "Unauthorised";
    http_response_code(403);
    exit;
}
?> 
```

## High Security
Now, we can no longer receive data.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/Authorisation-Bypass/!images/ab7.png?raw=true">
</p>

But only the GET request was restricted, the update functionality still work.

Another attack that you can use in other exercises would be to rewrite other user's information, such as password:
```json
{
	"id":5,"first_name":"Bob",
	"surname":"Smith",
	"password":"abc1234"
}
```

## Impossible Security
On this level all functions check authorisation before allowing access to the data.