# Protocol Documentation

## Registration

1. Alice (client) exchanges keys with the Bob/Jay (server)
![register1](register_kx.png)

2. Alice generates the ciphertext based on this formula
<...>
The token needs to be saved for later usage!

3. Alice sends the ciphertext to Jay and Bob responds
![register2](register_ct.png)

## Login

1. Alice generates a key (random bytes) and exchanges keys with Jay
![login1](login_kx.png)

2. Alice generates the ciphertext based on this formula
<...>
Keys need to be saved for later usage!

3. Alice sends the ciphertext to Jay and Bob respondes
![login1](login_ct.png)

## UART
If all above succeeds, Alice is given rights to access the UART service.

Using the keys generated in step 2 of the login Alice can now encode UART commands based on this formula:
<...>
