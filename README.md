# Pipe Client Impersonation Server

This tool creates a malicious named pipe server that impersonates connecting clients and executes arbitrary commands under their security context.

## Why?

This tool was created to assist in the creation of PoCs for insecure `CreateFile` and `ReadFile`/`WriteFile` calls, as well as exploit `Named Pipe Instance Creation Race Condition` and `Superfluous Pipe Connectivity` vulnerabilities.

C# was used for this implementation over C++ to allow easier customisation for AV evasion in INPT reviews.

## Prerequisets

Use of this tool requires access to a user with the `SeImpersonatePrivilege` privilege, such as a compromised service account.

## Usage

Run the server using the following command

```
ImpersonationPipeServer.exe {pipeName} {command}
```


