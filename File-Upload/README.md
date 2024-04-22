# File Upload

## About

> Uploaded files represent a significant risk to web applications. The first step in many attacks is to get some code to the system to be attacked. Then the attacker only needs to find a way to get the code executed. Using a file upload helps the attacker accomplish the first step.<br/>
> The consequences of unrestricted file upload can vary, including complete system takeover, an overloaded file system, forwarding attacks to backend systems, and simple defacement. It depends on what the application does with the uploaded file, including where it is stored.<br/>

Source: DVWA Documentation

## Low Security
In order to start this challenge, the directory `/var/www/html/DVWA/hackable/uploads` needs write permissions.

The challenge looks like this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu1.png?raw=true">
</p>

Normally some file extensions should be restricted, but in this case it seems that we can upload a .php file without any problem.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu2.png?raw=true">
</p>

Visiting the path mentioned, we can see that the `phpinfo()` function was successfully executed. (`http://localhost/DVWA/vulnerabilities/upload/../../hackable/uploads/php-test2.php`)

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu3.png?raw=true">
</p>

The file used `php-test2.php`:
```php
<?php
phpinfo();
?>
```

Source code:
```php
<?php

if( isset( $_POST[ 'Upload' ] ) ) {
    // Where are we going to be writing to?
    $target_path  = DVWA_WEB_PAGE_TO_ROOT . "hackable/uploads/";
    $target_path .= basename( $_FILES[ 'uploaded' ][ 'name' ] );

    // Can we move the file to the upload folder?
    if( !move_uploaded_file( $_FILES[ 'uploaded' ][ 'tmp_name' ], $target_path ) ) {
        // No
        echo '<pre>Your image was not uploaded.</pre>';
    }
    else {
        // Yes!
        echo "<pre>{$target_path} succesfully uploaded!</pre>";
    }
}

?> 
```

## Medium Security
For the Medium challenge, the following verifications can be found in the source code:
```php
 // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_type = $_FILES[ 'uploaded' ][ 'type' ];
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];

    // Is it an image?
    if( ( $uploaded_type == "image/jpeg" || $uploaded_type == "image/png" ) &&
        ( $uploaded_size < 100000 ) ) { 
```
We can see that the type and the size is verified. The size is not really a problem for a `phpinfo()` file, but how about the type?<br/>
Using Burp Suite we can intercept the request before being sent and modify the `Content-Type` as we wish.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu3.png?raw=true">
</p>

We have to replace `application/x-php` with `image/jpeg` or `image/png`, and the file will be uploaded on the server.

## High Security
This is a harder challenge where the following code is implemented:
```php
 // File information
    $uploaded_name = $_FILES[ 'uploaded' ][ 'name' ];
    $uploaded_ext  = substr( $uploaded_name, strrpos( $uploaded_name, '.' ) + 1);
    $uploaded_size = $_FILES[ 'uploaded' ][ 'size' ];
    $uploaded_tmp  = $_FILES[ 'uploaded' ][ 'tmp_name' ];

    // Is it an image?
    if( ( strtolower( $uploaded_ext ) == "jpg" || strtolower( $uploaded_ext ) == "jpeg" || strtolower( $uploaded_ext ) == "png" ) &&
        ( $uploaded_size < 100000 ) &&
        getimagesize( $uploaded_tmp ) ) { 
```
So, the checks are made on the extension and on the size, the content-type is not verified anymore.<br/>
After the file is uploaded, a `getimagesize()` function is executed in order to verify that the file is an image.<br/>
The solution is to upload a real image, and to add some php code inside. The file will be saved as `.php.jpg`. In this case the file is considered to be an image, but has php code in it.<br/>
The main problem here is that the verification for the extension is made with `strrpos` which is verifying the string from the last dot. If this function was not used, we could easily named the file as `file.jpg.php`, but now the `.jpg` must be the last.<br/>
Maybe in older PHP versions the null byte attack is working. We name a file as `file.php%00.jpg` and all after the `.php` will not be considered.<br/>

The only solution that is also mentioned in the Help section of the challenge, is to chain this vulnerability with the File Inclusion one. I didn't find other method, so please visit the File Inclusion section to better understand this exercise.<br/>
In this case, we upload the file as I mentioned and we use the File Inclusion vulnerability to include the file in the page in order to execute the php code.

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu4.png?raw=true">
</p>

Just copy and paste the php code. Now if we want to visit the path, we will see this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu5.png?raw=true">
</p>

But using File Inclusion we will get this:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu6.png?raw=true">
</p>

I hid the solution for those who doesn't want to get spoilers for File Inclusion exercises, so please check File Inclusion - High Level if you want to know the URL path to the file.<br/>
I hope is clear that executing php files through a File Upload vulnerability can allow us to upload a reverse shell and to get a connection back to the server.

## Impossible Security
For Impossible level, we will find the checks from all levels plus the re-encoding of the image. ("This will make a new image, therefor stripping any "non-image" code (including metadata).")<br/>
A nice security measure is to encode the name of the file such that only you will know the path to the file. This is also implemented for this level and can be found below:

<p align="center">
  <img src="https://github.com/Abdy01/DVWA-Walkthrough/blob/main/File-Upload/!images/fu7.png?raw=true">
</p>