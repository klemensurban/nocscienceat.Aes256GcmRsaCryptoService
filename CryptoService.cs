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

    private readonly string? _certificateThumbprint;
    private readonly bool _localMachine;

    // Constructor that reads settings from IConfiguration if used in DI context
    public CryptoService(IConfiguration configuration)
    {
        Settings? settings =configuration.GetSection("nocscienceat.Aes256GcmRsaCryptoService").Get<Settings>();
        if (settings == null)
        {
            throw new InvalidOperationException("Aes256GcmRsaCryptoService settings are missing in the configuration.");
        }
        _certificateThumbprint = settings.CertificateThumbprint;
        _localMachine = settings.LocalMachine;
    }

    // Encrypts data using AES256, then encrypts the AES key with RSA
    public static byte[] Encrypt(ReadOnlySpan<byte> plainTextSpan, string certificateThumbprint, bool localMachine)
    {
        StoreLocation storeLocation = localMachine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        using X509Store certificateStore = new(storeLocation);
        certificateStore.Open(OpenFlags.ReadOnly);
        using X509Certificate2 encCertificate = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false)[0];
        using RSA? rsaPublicKey = encCertificate.GetRSAPublicKey();
        if (rsaPublicKey is null)
            throw new InvalidOperationException("Could not get RSA public key from certificate");

        int rsaKeySizeBytes = rsaPublicKey.KeySize / 8;

        // Prepare cipherText output byte array: 2 RSA blocks for (1) encrypted AES key, nonce and tag, (2) signature of AES key, nonce and tag + AES encrypted data after these RSA blocks
        byte[] cipherText = new byte[2 * rsaKeySizeBytes + plainTextSpan.Length];
        // Define spans for different parts of cipherText
        Span<byte> rsaCipherSpan = cipherText.AsSpan(0, rsaKeySizeBytes);
        Span<byte> rsaSignatureSpan = cipherText.AsSpan(rsaKeySizeBytes, rsaKeySizeBytes);
        Span<byte> cipherTextSpan = cipherText.AsSpan(2 * rsaKeySizeBytes);

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
        if (rsaPublicKey.Encrypt(keyNonceTagSpan, rsaCipherSpan, RSAEncryptionPadding.OaepSHA256) != rsaKeySizeBytes)
            throw new InvalidOperationException("RSA encryption did not produce expected ciphertext size");

        using RSA? rsaPrivateKey = encCertificate.GetRSAPrivateKey();
        if (rsaPrivateKey is null)
            throw new InvalidOperationException("Could not get RSA private key from certificate");

        // Sign keyNonceTag with RSA private key and insert it into at position <rsaKeySizeBytes> of cipherText, length <rsaKeySizeBytes>
        if (rsaPrivateKey.SignData(keyNonceTagSpan, rsaSignatureSpan, HashAlgorithmName.SHA256, RSASignaturePadding.Pss) != rsaKeySizeBytes)
            throw new InvalidOperationException("RSA signature did not produce expected size");

        return cipherText;
    }

    // Decrypts data: decrypts AES key with RSA, then decrypts data with AES256
    public static byte[] Decrypt(ReadOnlySpan<byte> cipherTextSpan, string certificateThumbprint, bool localMachine)
    {
        StoreLocation storeLocation = localMachine ? StoreLocation.LocalMachine : StoreLocation.CurrentUser;
        using X509Store certificateStore = new(storeLocation);
        certificateStore.Open(OpenFlags.ReadOnly);
        using X509Certificate2 encCertificate = certificateStore.Certificates.Find(X509FindType.FindByThumbprint, certificateThumbprint, false)[0];
        using RSA? rsaPrivateKey = encCertificate.GetRSAPrivateKey();
        if (rsaPrivateKey is null)
            throw new InvalidOperationException("Could not get RSA private key from certificate");

        int rsaKeySizeBytes = rsaPrivateKey.KeySize / 8;

        // Check minimum required size: 2 RSA blocks 
        int minRequiredSize = 2 * rsaKeySizeBytes;
        if (cipherTextSpan.Length < minRequiredSize)
            throw new ArgumentException("encryptedData is too short for decryption", nameof(cipherTextSpan));

        // define Spans for the different parts of cipherText (1) encrypted AES key, nonce , tag (2) signature of AES key, nonce and tag + (3) AES encrypted data after these RSA blocks
        ReadOnlySpan<byte> rsaCipherSpan = cipherTextSpan.Slice(0, rsaKeySizeBytes);
        ReadOnlySpan<byte> rsaSignatureSpan = cipherTextSpan.Slice(rsaKeySizeBytes, rsaKeySizeBytes);
        ReadOnlySpan<byte> aesCipherTextSpan = cipherTextSpan[(2 * rsaKeySizeBytes)..];

        // Decrypt AES key, nonce, and tag with RSA private key
        byte[] keyNonceTag = rsaPrivateKey.Decrypt(rsaCipherSpan, RSAEncryptionPadding.OaepSHA256);

        if (keyNonceTag.Length != KeyNonceTagSize)
            throw new InvalidOperationException("expected decrypted key/nonce/tag length does not match");

        // Verify RSA signature using public key
        using RSA? rsaPublicKey = encCertificate.GetRSAPublicKey();
        if (rsaPublicKey is null)
            throw new InvalidOperationException("Could not get RSA public key from certificate");

        ReadOnlySpan<byte> keyNonceTagSpan = keyNonceTag.AsSpan();

        bool isValidSignature = rsaPublicKey.VerifyData(keyNonceTagSpan, rsaSignatureSpan, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

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
        if (string.IsNullOrWhiteSpace(_certificateThumbprint) ||
            _certificateThumbprint.Length is not (40 or 64) ||
            !_certificateThumbprint.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Certificate thumbprint must be a 40 or 64 character hexadecimal string.", nameof(_certificateThumbprint));
        }

        return Encrypt(plainTextSpan, _certificateThumbprint, _localMachine);
    }

    // Instance method to decrypt data using configured certificate; use in DI context
    public byte[] Decrypt(ReadOnlySpan<byte> cipherTextSpan)
    {
        if (string.IsNullOrWhiteSpace(_certificateThumbprint) ||
            _certificateThumbprint.Length is not (40 or 64) ||
            !_certificateThumbprint.All(Uri.IsHexDigit))
        {
            throw new ArgumentException("Certificate thumbprint must be a 40 or 64 character hexadecimal string.", nameof(_certificateThumbprint));
        }
        return Decrypt(cipherTextSpan, _certificateThumbprint, _localMachine);
    }
}