# Bootproof #

<https://git.distrust.co/public/bootproof>

## About ##

A CLI/daemon for generating and verifying TPM 2.0 remote attestations.

## Uses ##
 * Generate signature proving what code is running on current system
 * Prove remote server is running the code you expect
 * Obtain TPM-certified key for securely communicating with remote machine
 * Run daemon for generating challenge/response bootproofs

## Build ##

```
make
```

## Develop ##

```
make shell
bootproof ...
```

## Usage ##

### Generate bootproof

```
bootproof generate > proof
```

### Verify bootproof

```
bootproof verify proof
```

### Remotely Attest bootproof daemon

#### Server
```
bootproofd
```

### Client
```
bootproof attest https://some.server:1234
```
