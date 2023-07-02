[![Nuget](https://img.shields.io/nuget/v/NebulaNetworkAutomation)](https://www.nuget.org/packages/NebulaNetworkAutomation)

### Nebula Network Automation a helper C# library for automating Nebula Network operations.

----
### What is [Nebula](https://github.com/slackhq/nebula)?

Nebula is a scalable peer to peer virtual private network / overlay networking tool with a focus on performance, simplicity and security.
It lets you seamlessly connect computers anywhere in the world. Nebula is portable, and runs on Linux, OSX, Windows, iOS, and Android.
It can be used to connect a small number of computers, but is also able to connect tens of thousands of computers.

Nebula incorporates a number of existing concepts like encryption, security groups, certificates,
and tunneling, and each of those individual pieces existed before Nebula in various forms.
What makes Nebula different to existing offerings is that it brings all of these ideas together,
resulting in a sum that is greater than its individual parts.

Further documentation can be found [here](https://nebula.defined.net/docs/).

You can read more about Nebula [here](https://medium.com/p/884110a5579).

----

### Certificate creation and manipulation:

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
      public IPAddress? GetIPAddress();
      public IPAddress? GetIPMask();
      public bool IsExpired();
      public bool IsSignatureValid(CNebulaCert inSigner);
      public bool IsValidCA();
}
```
