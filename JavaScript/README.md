# JavaScript

## About
> The attacks in this section are designed to help you learn about how JavaScript is used in the browser and how it can be manipulated.
> 
> The attacks could be carried out by just analysing network traffic, but that isn't the point and it would also probably be a lot harder.

Source: DVWA Documentation

## Low Security
The objective of this challenge is to submit the phrase "success" to win.<br/>
We will need to analyse and to manipulate the JavaScript code to successfully pass the protections.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js1.png?raw=true">
</p>

Just typing "success" will return an "Invalid token" message.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js2.png?raw=true">
</p>

If we take a look at the request, we can see that a token is also used.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js3.png?raw=true">
</p>

This token is the same for every request, so let's examine the source code.<br/>
Using the Inspector we can see the value of the token that was sent in the request.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js4.png?raw=true">
</p>

In the source code we have the following functions:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js5.png?raw=true">
</p>

The first one is very long and obfuscated. This one seems to be a MD5 implementation.<br/>
Then we have an implementation for rot13 and a "generate_token" function, which is taking a "phrase" and creates the "token" with md5(rot13(phrase)).<br/>
We know that MD5 is a hashing method, so the final token is in MD5 format. What about rot13?<br/>
According to Wikipedia, Rot13 is a simple letter substitution cipher that replaces a letter with the 13th letter after it in the Latin alphabet.<br/>
Great, we have the functionality now. Let's use the Console to make some investigations.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js6.png?raw=true">
</p>

We can see that the token sent was generated on the initial value "ChangeMe".<br/>
Let's generate the token for "success" message.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js7.png?raw=true">
</p>

Now, modify the token in the request and send it.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js8.png?raw=true">
</p>

Well done!

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js9.png?raw=true">
</p>

We can also change the phrase in the input field, and then from the Console, just call "generate_token()" function which will update the token value.

## Medium Security
For this challenge we get the same message error. This time the token value is "XXeMegnahCXX".<br/>
Let's check the source code.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js10.png?raw=true">
</p>

We have a script at `../../vulnerabilities/javascript/source/medium.js` and is all in one line.<br/>
After we added some new lines and spaces, the code looks like this:

```js
function do_something(e){
  for(var t="",n=e.length-1;n>=0;n--)
    t+=e[n];
  return t
}

setTimeout(function(){
  do_elsesomething("XX")
},300);

function do_elsesomething(e){
  document.getElementById("token").value=do_something(e+document.getElementById("phrase").value+"XX")
}
```
The first function is taking a string "e" and iterates through it in a reverse order. The values are saved then in "t" variable.

The second one is calling the "do_elsesomething()" function with "XX" parameter after a 300ms delay.

The third function is "do_elsesomething()" which was called with "XX". So, the "e" is equal with "XX".<br/>
The token is created like this:
- "e" ("XX") +
- the first function with the "phrase" (so "ChangeMe" in reverse order) +
- "XX"
If we check the final token again, we can easily see the pattern "XXeMegnahCXX".

The new token will be: "XXsseccusXX".

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js11.png?raw=true">
</p>

In order to solve this challenge, I removed the "hidden" tag and changed the token directly in front-end.

## High Security

## Impossible Security