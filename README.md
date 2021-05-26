# Secure E-Voucher System

Url: https://comp3334.herokuapp.com/
Remark: Please be patient because the website loading may take some time.
(Heroku: If an app has a free web dyno, and that dyno receives no web traffic in a 30-minute period, it will sleep. 
In addition to the web dyno sleeping, the worker dyno (if present) will also sleep.)

# Features:

1. XSS-Prevention: 
  autoescaping is enabled for all templates ending in .html, .htm, .xml as well as .xhtml when using render_template().
  
2. CSRF-Prevention:
  provide a valid CSRF token so the server can verify the source of the request for CSRF protectioN.

3. SQL-injection Prevention:
  If you have any "special" characters (such as semicolons or apostrophes) in your data, they will be automatically quoted for you by the SQLEngine object.

4. HTTPS:
  Automatically redirect all requests to HTTPS by SSLify.

5. DDoS (Denial of Service) mitigation:
  Heroku's infrastructure provides DDoS mitigation techniques including TCP Syn cookies and connection rate limiting. 

6. How to store data in database:
  - Hash data with random salt
  - Encrypt hashed data

7. Login,PIN, HKID Authenication:
  - Rsa2048 encryption, sha256 hashing
  - HKID Authenication
    ~ The data is encrypted by using 3des in database
    ~ Only have 10 limited attempts
    
8. Coupon:
  - Advanced Encryption Standard(AES): Concealment of the coupon information
  - Authenticated Encryption(AE): Assure the confidentiality and authenticity of data
