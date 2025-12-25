For the JWT Secret, use OpenSSL to generate a random Base64 String:

openssl rand -base64 32


For the keystore. Follow the instructions below:

Using Java keytool.exe found in "C:\Program Files\Java\jdk-**\bin\keytool.exe", create a keystore of cryptographic keys, X.509 certificate chains, and trusted certificates.
Run the command below to generate the keystore on your Desktop. Note that you should be inside the directory of keytool.exe.


.\keytool.exe -genkeypair -alias springboot -keyalg RSA -keysize 2048 -storetype PKCS12 -keystore C:\Users\<enter-user>\Desktop\keystore.p12 -validity 365


It will ask for:

1. Keystore password
2. First and Last Name
3. Organizational Unit
4. Organization
5. City
6. Province
7. Country Code i.e., ZM

It will then ask for you to confirm the details. Simply enter "y", and press Enter.

A .p12 file will be generated. Copy it to your project's directory "\src\main\resources" directory
In the application.properties, fill in the properties with the details you used to create the keystore:


server.ssl.key-store-password=
server.ssl.key-store-type=
server.ssl.key-alias=


Run the application. Any requests made should be made on https and port 8443 and 8080