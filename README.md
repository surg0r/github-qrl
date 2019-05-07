# github-qrl
delegated qrl signing of github commits plugin

Proof-of-concept only..this is not production code but feel free to tinker/adapt as required..

Usage: python3 githubqrl.py

External dependencies: pyqrllib, pickledb, grpc, pygithub

The code is threaded to serve an http/api which exchanges a valid qrl address for a delegated xmss public key. The qrl chain is scanned for confirmed message transactions containing valid github encoding. Finally, github itself is monitored for proof-of-gist and then to sign new open pull requests from the delegated xmss tree automatically.

User/service process:
1. register valid qrl address with http api, delegated xmss public key returned by service.
2. user sends a message transaction from their webwallet which contains: github encoding (see below), delegated public key, their github id.
3. user creates a gist on github containing: delegated public key, their qrl address
4. service identifies message transaction and gist to validate the qrl:github pairing and posts a comment under the gist..
5. user open pull requests created by github id are signed (SHA is) by service with delegated xmss tree and comment placed under pull request..

Github message format: initial 4 bytes, 0x0f0f0003, next 5 bytes are zero 0x0000000000, next 67 bytes are delegated public key, next 4 bytes are github id -  bigendian unsigned integer.
