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
For this challenge we get the same error message. This time the token value is "XXeMegnahCXX".<br/>
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
The first function is taking a string "e" and iterates through it in a reverse order. The values are saved in "t" variable.

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
I have to admit that this level was challenging.<br/>
The script is now very long and obfuscated:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js12.png?raw=true">
</p>

We have an initial token set and another one that is sent in the request.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js13.png?raw=true">
</p>

The token from the request is alwasy the same.<br/>
I tried to call somehow the function, to generate the token based on the phrase required, but without success.<br/>
I tried to deobfuscate the script and I got something like this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js14.png?raw=true">
</p>

Still obfuscated...<br/>
After a while, I took a hint, and I found out that I really need to deobfuscate the file.<br/>
I tried other websites with different options and finally I got a better version:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js15.png?raw=true">
</p>

Website used: https://lelinhtinh.github.io/de4js/ <br/>
There are a lot of code, but on the last lines I found some interesting functions:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js16.png?raw=true">
</p>

At that moment I knew that this is the main functionality and the rest are probably junk functions or SHA256 implementation.<br/>
If we take part1 -> part2 -> part3 the token is created as follow:
- token = do_something("phrase") -> do_something("success") -> "sseccus"
- token = sha256("XX" + "sseccus") -> sha256("XXsseccus") -> "7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068a"<br/>
The function is called with "token_part_2("XX")", so "e" will get "XX" value instead of "YY". "YY" is used only if the function is called without a parameter.<br/>
- token = sha256(token + "ZZ") -> sha256("7f1bfaaf829f785ba5801d5bf68c1ecaf95ce04545462c8b8f311dfc9014068aZZ") ->
- final result = "ec7ef8687050b6fe803867ea696734c67b541dfafb286a0b1239f42ac5b0aa84"

For sha256 encryption I used:`echo -n "XXsseccus" | sha256sum`.<br/>
Now, if the request is sent with the new token:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js17.png?raw=true">
</p>

The challenge is done!<br/>

### Other approach
Another option is to host a server with the JavaScript file deobfuscated and to point the web application to this one.<br/>
This is also helping because now we can use Debugger to see how are the functions executed.

I said that the challenge was not easy because I didn't think the first time to take the functions in name order.<br/>
With a new deobfuscated JavaScript file and the Debugger, the functions are executed in a different order, something like this:<br/>
- "token_part_3()" (probably because is triggered in the line 463, when the "send" button is clicked)
- here, the sha256() function is executing the final token
- the request is sent
- debugger continues with the line 459 where the "phrase" gets an empty value
- setTimeout(300)
- addEventListener()
- token_part_1()
- do_something()
- executing other things
- comes back to "token_part_2()" an execute it.

I don't really understand this order, but something is clear, at some point the "phrase" value becomes empty.<br/>
If we simply add our word in the source code, the challenge will be solved.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js18.png?raw=true">
</p>

However, following the Debugger, I didn't manage to understand the order of the functions.<br/>
If you want to see how to change the JavaScript file and how to use Debugger, you can find a walkthrough video at CryptoCat:<br/>
https://www.youtube.com/watch?v=3IfHy97pog0

## Impossible Security
The impossible level does not really exist in this case.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/JavaScript/!images/js19.png?raw=true">
</p>