
Helper C# library for automating Nebula Network operations.

Certificate creating and manipulation:

```cs
public class CNebulaCert
{
      public static CNebulaCert? MakeCA(in string inName, in DateTime StartDate, in TimeSpan ValidityPeriod);
      public static CNebulaCert? MakeSignedCert(in CNebulaCert inCA, in string inName, in IPAddress inIP, in int inCidr, in DateTime StartDate, in TimeSpan ValidityPeriod);
      public static CNebulaCert? MakeFromPEM(in string? inCert, in string? inPrivateKey = null);
      public string? GetCertPEM();
      public string? GetPrivateKeyPem();
      public DateTime? GetStartDate();
      public DateTime? GetEndDate();
      public IPAddress? GetIPAdress();
      public IPAddress? GetIPMask();
      public bool IsExpired();
      public bool IsSignatureValid(CNebulaCert inSigner);
      public bool IsValidCA();
}
```
