# nocscienceat.Aes256GcmRsaCryptoService

AES-256-GCM and RSA crypto service for .NET 8+  
Author: Klemens Urban, 0x4b55 Software Solutions

## Overview

`nocscienceat.Aes256GcmRsaCryptoService` is a .NET library providing secure encryption and decryption using AES-256-GCM for data confidentiality and RSA for key protection and digital signatures. It supports .NET 8, .NET 9, and .NET 10.

## Features

- AES-256-GCM symmetric encryption for fast, secure data protection.
- RSA encryption for secure key exchange and digital signatures.
- X.509 certificate-based key management.
- Easy integration with .NET dependency injection and configuration.
- The certificate used is referenced by its fingerprint and, depending on the Boolean parameter localMachine, can originate from either the LocalMachine or CurrentUser certificate store.
- AES256 key and nonce are randomly regenerated each time the Encrypt method is called.
- Can be used in the context of dependency injection and outside of dependency injection via static methods.

## Getting Started

### Installation

Add the NuGet package to your project:

dotnet add package nocscienceat.Aes256GcmRsaCryptoService

### Configuration for Dependency Injection

if using the the instance methodes add the following section to your `appsettings.json`:

"nocscienceat.Aes256GcmRsaCryptoService": { 
  "CertificateThumbprint": "<your-certificate-thumbprint>", 
  "LocalMachine": true/false
}


### Usage

#### Static Methods
using nocscienceat.Aes256GcmRsaCryptoService;
// Encrypt data: byte[] Encrypt(ReadOnlySpan<byte> plainTextSpan, string certificateThumbprint, bool localMachine)
// Decrypt data: byte[] Decrypt(ReadOnlySpan<byte> cipherTextSpan, string certificateThumbprint, bool localMachine)


#### Dependency Injection

services.AddSingleton<ICryptoService, CryptoService>(); // setup DI in program.cs

public class MyService 
{ 
  private readonly ICryptoService _cryptoService;

  public MyService(ICryptoService cryptoService)
  {
    _cryptoService = cryptoService;
  }

  public void DoCrypto()
  {
    byte[] encrypted = _cryptoService.Encrypt(ReadOnlySpan<byte> plainTextSpan);
    byte[] decrypted = _cryptoService.Decrypt(ReadOnlySpan<byte> cipherTextSpan);
  }
}
