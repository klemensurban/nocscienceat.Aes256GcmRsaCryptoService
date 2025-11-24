using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Configuration;
using nocscienceat.Aes256GcmRsaCryptoService.Models;

namespace nocscienceat.Aes256GcmRsaCryptoService;

public class CryptoService : ICryptoService
{
    // Prepared constants for sizes used by AES256-GCM 
    private const int AesKeySizeBytes = 32; // 256 bits
    private const int AesNonceSizeBytes = 12; // 96 bits
    private const int AesTagSizeBytes = 16; // 128 bits
    private const int KeyNonceTagSize = AesKeySizeBytes + AesNonceSizeBytes + AesTagSizeBytes;

    private readonly string? _encryptionCertificateThumbprint;
    private readonly string? _signingCertificateThumprint;

    private readonly bool _localMachine;

    // Constructor that reads settings from IConfiguration if used in DI context
    public CryptoService(IConfiguration configuration)
    {
        Settings? settings =configuration.GetSection("nocscienceat.Aes256GcmRsaCryptoService").Get<Settings>();
        if (settings == null)
        {
            throw new InvalidOperationException("Aes256GcmRsaCryptoService settings are missing in the configuration.");
        }
        _encryptionCertificateThumbprint = settings.EncryptionCertificateThumbprint;
        _signingCertificateThumprint = settings.SigningCertificateThumbprint;
        _localMachine = settings.LocalMachine;
    }

    // Encrypts data using AES256, then encrypts the AES key with RSA
    public static byte[] Encrypt(ReadOnlySpan<byte> plainTextSpan, string encryptionCertificateThumbprint, string signingCertificateThumprint, bool localMachine)
    {
        StoreLocation storeLocation = localMachine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        using X509Store certificateStore = new(storeLocation);
        certificateStore.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection foundEncryptionCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, encryptionCertificateThumbprint, false);
        if (foundEncryptionCertificates.Count == 0)
            throw new InvalidOperationException($"No certificate found with thumbprint '{encryptionCertificateThumbprint}' in store '{storeLocation}'.");

        using X509Certificate2 encryptionCertificate = foundEncryptionCertificates[0];
        using RSA? rsaEncryptionPublicKey = encryptionCertificate.GetRSAPublicKey();
        if (rsaEncryptionPublicKey is null)
            throw new InvalidOperationException("Could not get RSA public key from certificate");

        int rsaEncryptionPublicKeySizeBytes = rsaEncryptionPublicKey.KeySize / 8;

        // Load signing certificate
        X509Certificate2Collection foundSigningCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, signingCertificateThumprint, false);
        if (foundSigningCertificates.Count == 0)
            throw new InvalidOperationException($"No signing certificate found with thumbprint '{signingCertificateThumprint}' in store '{storeLocation}'.");
        using X509Certificate2 signingCertificate = foundSigningCertificates[0];
        using RSA? rsaSigningPrivateKey = signingCertificate.GetRSAPrivateKey();
        if (rsaSigningPrivateKey is null)
            throw new InvalidOperationException($"Could not get RSA private key from certificate {signingCertificateThumprint} ");

        int rsaSigningPrivateKeySizeBytes = rsaSigningPrivateKey.KeySize / 8;

        // Prepare cipherText output byte array: 2 RSA blocks for (1) encrypted AES key, nonce and tag, (2) signature of AES key, nonce and tag + AES encrypted data after these RSA blocks
        byte[] cipherText = new byte[rsaEncryptionPublicKeySizeBytes + rsaSigningPrivateKeySizeBytes + plainTextSpan.Length];
        // Define spans for different parts of cipherText
        Span<byte> rsaCipherSpan = cipherText.AsSpan(0, rsaEncryptionPublicKeySizeBytes);
        Span<byte> rsaSignatureSpan = cipherText.AsSpan(rsaEncryptionPublicKeySizeBytes, rsaSigningPrivateKeySizeBytes);
        Span<byte> cipherTextSpan = cipherText.AsSpan(rsaEncryptionPublicKeySizeBytes + rsaSigningPrivateKeySizeBytes);

        // Byte-Array to hold AES key, nonce, and tag
        byte[] keyNonceTag = new byte[KeyNonceTagSize];

        // Generate random AES key and nonce, Tag will be generated during encryption -> Span for key and nonce
        Span<byte> keyNonceSpan = keyNonceTag.AsSpan(0, AesKeySizeBytes + AesNonceSizeBytes);
        RandomNumberGenerator.Fill(keyNonceSpan);

        // Define spans for key, nonce, and tag
        ReadOnlySpan<byte> aesKeySpan = keyNonceTag.AsSpan(0, AesKeySizeBytes);
        ReadOnlySpan<byte> aesNonceSpan = keyNonceTag.AsSpan(AesKeySizeBytes, AesNonceSizeBytes);
        Span<byte> aesTagSpan = keyNonceTag.AsSpan(AesKeySizeBytes + AesNonceSizeBytes, AesTagSizeBytes);
        ReadOnlySpan<byte> keyNonceTagSpan = keyNonceTag.AsSpan();

        // Encrypt plaintext with AES-GCM
        using AesGcm aesGcm = new(aesKeySpan, AesTagSizeBytes);
        aesGcm.Encrypt(aesNonceSpan, plainTextSpan, cipherTextSpan, aesTagSpan);

        // Encrypt keyNonceTag with RSA public key and insert it into at position 0 of cipherText, length <rsaKeySizeBytes>
        if (rsaEncryptionPublicKey.Encrypt(keyNonceTagSpan, rsaCipherSpan, RSAEncryptionPadding.OaepSHA256) != rsaEncryptionPublicKeySizeBytes)
            throw new InvalidOperationException("RSA encryption did not produce expected ciphertext size");

        // Sign keyNonceTag with RSA private key and insert it into at position <rsaKeySizeBytes> of cipherText, length <rsaKeySizeBytes>
        if (rsaSigningPrivateKey.SignData(keyNonceTagSpan, rsaSignatureSpan, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) != rsaSigningPrivateKeySizeBytes)
            throw new InvalidOperationException("RSA signature did not produce expected size");

        return cipherText;
    }

    // Decrypts data: decrypts AES key with RSA, then decrypts data with AES256
    public static byte[] Decrypt(ReadOnlySpan<byte> cipherTextSpan, string encryptionCertificateThumbprint, string signingCertificateThumprint, bool localMachine)
    {
        StoreLocation storeLocation = localMachine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        using X509Store certificateStore = new(storeLocation);
        certificateStore.Open(OpenFlags.ReadOnly);
        X509Certificate2Collection foundEncryptionCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, encryptionCertificateThumbprint, false);
        if (foundEncryptionCertificates.Count == 0)
            throw new InvalidOperationException($"No certificate found with thumbprint '{encryptionCertificateThumbprint}' in store '{storeLocation}'.");

        using X509Certificate2 encryptionCertificate = foundEncryptionCertificates[0];
        using RSA? rsaEncryptionPrivateKey = encryptionCertificate.GetRSAPrivateKey();
        if (rsaEncryptionPrivateKey is null)
            throw new InvalidOperationException("Could not get RSA private key from certificate");

        int rsaEncryptionPrivateKeySizeBytes = rsaEncryptionPrivateKey.KeySize / 8;

        X509Certificate2Collection foundSigningCertificates = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, signingCertificateThumprint, false);
        if (foundSigningCertificates.Count == 0)
            throw new InvalidOperationException($"No signing certificate found with thumbprint '{signingCertificateThumprint}' in store '{storeLocation}'.");
        using X509Certificate2 signingCertificate = foundSigningCertificates[0];
        using RSA? rsaSigningPublicKey = signingCertificate.GetRSAPublicKey();
        if (rsaSigningPublicKey is null)
            throw new InvalidOperationException($"Could not get RSA private key from certificate {signingCertificateThumprint} ");

        int rsaSigningPublicKeySizeBytes = rsaSigningPublicKey.KeySize / 8;

        // Check minimum required size: 2 RSA blocks 
        int minRequiredSize = rsaEncryptionPrivateKeySizeBytes + rsaSigningPublicKeySizeBytes;
        if (cipherTextSpan.Length < minRequiredSize)
            throw new ArgumentException("encryptedData is too short for decryption", nameof(cipherTextSpan));

        // define Spans for the different parts of cipherText (1) encrypted AES key, nonce , tag (2) signature of AES key, nonce and tag + (3) AES encrypted data after these RSA blocks
        ReadOnlySpan<byte> rsaCipherSpan = cipherTextSpan.Slice(0, rsaEncryptionPrivateKeySizeBytes);
        ReadOnlySpan<byte> rsaSignatureSpan = cipherTextSpan.Slice(rsaEncryptionPrivateKeySizeBytes, rsaSigningPublicKeySizeBytes);
        ReadOnlySpan<byte> aesCipherTextSpan = cipherTextSpan[(rsaEncryptionPrivateKeySizeBytes + rsaSigningPublicKeySizeBytes)..];

        // Decrypt AES key, nonce, and tag with RSA private key
        byte[] keyNonceTag = rsaEncryptionPrivateKey.Decrypt(rsaCipherSpan, RSAEncryptionPadding.OaepSHA256);

        if (keyNonceTag.Length != KeyNonceTagSize)
            throw new InvalidOperationException("expected decrypted key/nonce/tag length does not match");

        // Verify RSA signature using public key

        ReadOnlySpan<byte> keyNonceTagSpan = keyNonceTag.AsSpan();

        bool isValidSignature = rsaSigningPublicKey.VerifyData(keyNonceTagSpan, rsaSignatureSpan, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

        if (!isValidSignature)
            throw new CryptographicException("RSA signature verification failed");

        // Define spans for key, nonce, and tag to be used in AES decryption
        ReadOnlySpan<byte> aesKeySpan = keyNonceTag.AsSpan(0, AesKeySizeBytes);
        ReadOnlySpan<byte> aesNonceSpan = keyNonceTag.AsSpan(AesKeySizeBytes, AesNonceSizeBytes);
        ReadOnlySpan<byte> aesTagSpan = keyNonceTag.AsSpan(AesKeySizeBytes + AesNonceSizeBytes, AesTagSizeBytes);

        using AesGcm aesGcm = new AesGcm(aesKeySpan, AesTagSizeBytes);
        byte[] plaintext = new byte[aesCipherTextSpan.Length];
        Span<byte> plaintextSpan = plaintext.AsSpan();
        aesGcm.Decrypt(aesNonceSpan, aesCipherTextSpan, aesTagSpan, plaintextSpan);

        return plaintext;
    }

    // Instance method to encrypt data using configured certificate; use in DI context
    public byte[] Encrypt(ReadOnlySpan<byte> plainTextSpan)
    {
        if (string.IsNullOrWhiteSpace(_encryptionCertificateThumbprint) ||
            _encryptionCertificateThumbprint.Length is not (40 or 64) ||
            !_encryptionCertificateThumbprint.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Certificate thumbprint must be a 40 or 64 character hexadecimal string.", nameof(_encryptionCertificateThumbprint));
        }
        if (string.IsNullOrWhiteSpace(_signingCertificateThumprint) ||
            _signingCertificateThumprint.Length is not (40 or 64) ||
            !_signingCertificateThumprint.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Certificate thumbprint must be a 40 or 64 character hexadecimal string.", nameof(_signingCertificateThumprint));
        }

        return Encrypt(plainTextSpan, _encryptionCertificateThumbprint, _signingCertificateThumprint, _localMachine);
    }

    // Instance method to decrypt data using configured certificate; use in DI context
    public byte[] Decrypt(ReadOnlySpan<byte> cipherTextSpan)
    {
        if (string.IsNullOrWhiteSpace(_encryptionCertificateThumbprint) ||
            _encryptionCertificateThumbprint.Length is not (40 or 64) ||
            !_encryptionCertificateThumbprint.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Certificate thumbprint must be a 40 or 64 character hexadecimal string.", nameof(_encryptionCertificateThumbprint));
        }
        if (string.IsNullOrWhiteSpace(_signingCertificateThumprint) ||
            _signingCertificateThumprint.Length is not (40 or 64) ||
            !_signingCertificateThumprint.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Certificate thumbprint must be a 40 or 64 character hexadecimal string.", nameof(_signingCertificateThumprint));
        }

        return Decrypt(cipherTextSpan, _encryptionCertificateThumbprint, _signingCertificateThumprint, _localMachine);
    }
}