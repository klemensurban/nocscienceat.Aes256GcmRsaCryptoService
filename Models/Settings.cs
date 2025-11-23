namespace nocscienceat.Aes256GcmRsaCryptoService.Models;

internal class Settings
{
    public string CertificateThumbprint { get; set; } = string.Empty;
    public bool LocalMachine { get; set; } = true;
}