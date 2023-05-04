// See https://aka.ms/new-console-template for more information
using System.Collections;
using System.Data;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using static System.Reflection.Metadata.BlobBuilder;
//using System.Web;
//using System.Web.UI.WebControls.WebParts;

public class PPPSecret
{

    public string Name { get; private set; }
    public string ID { get; private set; }
    public string Profile { get; private set; }
    public string Password { get; private set; }
    public bool Disabled { get; private set; }

    public PPPSecret(List<string> apiBlock)
    {
        foreach (var item in apiBlock)
        {
            if (item.StartsWith("=name"))
            {
                Name = item.Substring(6);
            }
            else if (item.StartsWith("=profile"))
            {
                Profile = item.Substring(9);
            }
            else if (item.StartsWith("=.id="))
            {
                ID = item.Substring(5);
            }
            else if (item.StartsWith("=password"))
            {
                Password = item.Substring(10);
            }
            else if (item.StartsWith("=disabled"))
            {
                Disabled = item.Substring(10) == "true";
            }
        }
    }

    public override string ToString()
    {
        return $"ID: {ID}, Name: {Name}, Profile: {Profile}, Password: {Password}, Disabled: {Disabled}";
    }
}

public class OVPNServer
{

    public string Certificate { get; private set; }
    public int Port { get; private set; }
    public bool RequireClientCertificate { get; private set; }
    public string Auth { get; private set; }
    public string Cipher { get; private set; }
    public bool Enabled { get; private set; }

    public OVPNServer(List<string> apiBlock)
    {
        foreach (var item in apiBlock)
        {
            if (item.StartsWith("=certificate"))
            {
                Certificate = item.Substring(13);
            }
            else if (item.StartsWith("=port"))
            {
                Port = int.Parse(item.Substring(6));
            }
            else if (item.StartsWith("=require-client-certificate"))
            {
                RequireClientCertificate = item.Substring(28) == "true";
            }
            else if (item.StartsWith("=auth"))
            {
                Auth = item.Substring(6);
            }
            else if (item.StartsWith("=cipher"))
            {
                Cipher = item.Substring(8);
            }
            else if (item.StartsWith("=enabled"))
            {
                Enabled = item.Substring(9) == "true";
            }
        }
    }

    public override string ToString()
    {
        return $"Certificate: {Certificate}, Port: {Port}, RequireClientCertificate: {RequireClientCertificate}, Cipher: {Cipher}, Enabled: {Enabled}";
    }
}

public class Certificate
{
    public string ID { get; private set; }
    public string Name { get; private set; }
    public string DigestAlgorithm { get; private set; }
    public string KeyType { get; private set; }
    public string Country { get; private set; }
    public string Organization { get; private set; }
    public string Unit { get; private set; }
    public string CommonName { get; private set; }
    public int KeySize { get; private set; }
    public string SubjectAltName { get; private set; }
    public int DaysValid { get; private set; }
    public bool Trusted { get; private set; }
    public string KeyUsage { get; private set; }
    public string CA { get; private set; }
    public string SerialNumber { get; private set; }
    public string Fingerprint { get; private set; }
    public string AKID { get; private set; }
    public string SKID { get; private set; }
    public string InvalidBefore { get; private set; }
    public string InvalidAfter { get; private set; }
    public string ExpiresAfter { get; private set; }
    public bool PrivateKey { get; private set; }
    public bool CRL { get; private set; }
    public bool Issued { get; private set; }

    public Certificate(List<string> apiBlock)
    {
        foreach (var item in apiBlock)
        {
            if (item.StartsWith("=.id="))
            {
                ID = item.Substring(5);
            }
            else if (item.StartsWith("=name"))
            {
                Name = item.Substring(6);
            }
            else if (item.StartsWith("=digest-algorithm"))
            {
                DigestAlgorithm = item.Substring(18);
            }
            else if (item.StartsWith("=key-type"))
            {
                KeyType = item.Substring(10);
            }
            else if (item.StartsWith("=country"))
            {
                Country = item.Substring(9);
            }
            else if (item.StartsWith("=organization"))
            {
                Organization = item.Substring(14);
            }
            else if (item.StartsWith("=unit"))
            {
                Unit = item.Substring(6);
            }
            else if (item.StartsWith("=common-name"))
            {
                CommonName = item.Substring(13).Trim();
            }
            else if (item.StartsWith("=key-size"))
            {
                KeySize = int.Parse(item.Substring(10));
            }
            else if (item.StartsWith("=subject-alt-name"))
            {
                SubjectAltName = item.Substring(18);
            }
            else if (item.StartsWith("=days-valid"))
            {
                DaysValid = int.Parse(item.Substring(12));
            }
            else if (item.StartsWith("=trusted"))
            {
                Trusted = item.Substring(9) == "true";
            }
            else if (item.StartsWith("=key-usage"))
            {
                KeyUsage = item.Substring(11);
            }
            else if (item.StartsWith("=ca"))
            {
                CA = item.Substring(4);
            }
            else if (item.StartsWith("=serial-number"))
            {
                SerialNumber = item.Substring(15);
            }
            else if (item.StartsWith("=fingerprint"))
            {
                Fingerprint = item.Substring(13);
            }
            else if (item.StartsWith("=akid"))
            {
                AKID = item.Substring(6);
            }
            else if (item.StartsWith("=skid"))
            {
                SKID = item.Substring(6);
            }
            else if (item.StartsWith("=invalid-before"))
            {
                InvalidBefore = item.Substring(16);
            }
            else if (item.StartsWith("=invalid-after"))
            {
                InvalidAfter = item.Substring(15);
            }
            else if (item.StartsWith("=expires-after"))
            {
                ExpiresAfter = item.Substring(15);
            }
            else if (item.StartsWith("=private-key"))
            {
                PrivateKey = item.Substring(13) == "true";
            }
            else if (item.StartsWith("=crl"))
            {
                CRL = item.Substring(5) == "true";
            }
            else if (item.StartsWith("=issued"))
            {
                Issued = item.Substring(8) == "true";
            }
        }
    }

    public override string ToString()
    {
        return $"ID: {ID}, Name: {Name}, KeyType: {KeyType}, Country: {Country}, Organization: {Organization}, Unit: {Unit}, CommonName: {CommonName}, KeySize: {KeySize}, SubjectAltName: {SubjectAltName}, DaysValid: {DaysValid}, Trusted: {Trusted}, KeyUsage: {KeyUsage}, AKID: {AKID}, SKID: {SKID}, CRL: {CRL}, Issued: {Issued}";
    }
}



public class File
{
    public string ID { get; private set; }
    public string Name { get; private set; }
    public string Type { get; private set; }
    public int Size { get; private set; }
    public string CreationTime { get; private set; }
    public string Contents { get; private set; }

    public File(List<string> apiBlock)
    {
        foreach (var item in apiBlock)
        {
            if (item.StartsWith("=.id="))
            {
                ID = item.Substring(5);
            }
            else if (item.StartsWith("=name"))
            {
                Name = item.Substring(6);
            }
            else if (item.StartsWith("=type"))
            {
                Type = item.Substring(6);
            }
            else if (item.StartsWith("=size"))
            {
                Size = int.Parse(item.Substring(6));
            }
            else if (item.StartsWith("=creation-time"))
            {
                CreationTime = item.Substring(15);
            }
            else if (item.StartsWith("=contents"))
            {
                Contents = item.Substring(10);
            }
        }
    }

    public override string ToString()
    {
        return $"ID: {ID}, Name: {Name}, Type: {Type}, Size: {Size}, CreationTime: {CreationTime}, Contents: '{Contents}'";
    }
}

public class OVPNConfigFile
{
    public Certificate CA { get; private set; }
    public Certificate Client { get; private set; }
    public PPPSecret Secret { get; private set; }
    public OVPNServer Server { get; private set; }

    public OVPNConfigFile(Certificate ca, Certificate client, PPPSecret secret, OVPNServer server)
    {
        CA = ca;
        Client = client;
        Secret = secret;
        Server = server;
    }
}

public static class MKH
{
    public static List<List<string>> ReadBlocks(MikrotikAPI mikrotik)
    {
        bool done = false;
        bool got_reply = false;

        List<List<string>> blocks = new List<List<string>>();

        List<string> block = new List<string>();
        while (!done)
        {
            var payloads = mikrotik.Receive();
            foreach (string h in payloads)
            {
                if (!got_reply && h == "!re")
                {
                    got_reply = true;
                }
                else if (got_reply)
                {
                    if (h == "!re")
                    {
                        // process block
                        blocks.Add(block);
                        block = new List<string>();
                    }
                    else if (h == "!done")
                    {
                        blocks.Add(block);
                        block = new List<string>();
                        done = true;
                        break;
                    }
                    else
                    {
                        block.Add(h);
                    }
                }
            }
        }

        return blocks;
    }

    public static List<PPPSecret> GetOvpnAnyPPPSecrets(MikrotikAPI api)
    {
        List<PPPSecret> ret = new List<PPPSecret>();
        api.Send("/ppp/secret/getall");
        api.Send("?service=ovpn");
        api.Send("?service=any");
        api.Send("?#|");
        api.Send(".tag=sss", true);
        var blocks = ReadBlocks(api);
        foreach (var block in blocks)
        {
            ret.Add(new PPPSecret(block));
        }

        return ret;
    }

    public static OVPNServer? GetOvpnServer(MikrotikAPI api)
    {
        api.Send("/interface/ovpn-server/server/print");
        api.Send(".tag=sss", true);
        var blocks = ReadBlocks(api);
        foreach (var block in blocks)
        {
            return new OVPNServer(block);
        }

        return null;
    }

    public static List<Certificate> GetCertificatesWithCommonName(MikrotikAPI api, string commonName)
    {
        List<Certificate> ret = new List<Certificate>();
        api.Send("/certificate/getall");
        api.Send("?common-name=" + commonName);
        api.Send(".tag=sss", true);
        var blocks = ReadBlocks(api);
        foreach (var block in blocks)
        {
            ret.Add(new Certificate(block));
        }

        return ret;
    }

    public static Certificate? GetCertificateWithName(MikrotikAPI api, string name)
    {
        api.Send("/certificate/getall");
        api.Send("?name=" + name);
        api.Send(".tag=sss", true);
        var blocks = ReadBlocks(api);
        foreach (var block in blocks)
        {
            return new Certificate(block);
        }

        return null;
    }

    public static File? ReadSmallFile(MikrotikAPI api, string file)
    {
        Thread.Sleep(500); // important

        api.Send("/file/getall");
        api.Send($"?name={file}");
        api.Send(".tag=sss", true);
        var blocks = ReadBlocks(api);

        foreach (var block in blocks)
        {
            return new File(block);
        }

        return null;
    }

    public static bool DeleteFile(MikrotikAPI api, string fileID)
    {
        api.Send("/file/remove");
        //mikrotik.Send("=.proplist=.id,size,name,type,contents");
        api.Send("=.id=" + fileID);
        api.Send(".tag=sss", true);
        // TODO: implement something to read status
        return true;
    }

    public static string? ExportCertificate(MikrotikAPI api, string certID)
    {
        var certname = $"temp-certificate-{certID}";
        api.Send($"/certificate/export-certificate");
        api.Send($"=.id={certID}");
        api.Send("=type=pem");
        api.Send($"=file-name={certname}", true);

        foreach (var item in api.Receive()) // TODO: implement something to read status
        {
            Console.WriteLine($"RET = {item}");
        }

        Thread.Sleep(500);

        var pub = ReadSmallFile(api, certname + ".crt");

        if (pub == null)
        {
            return null;
        }

        DeleteFile(api, pub.ID);

        return pub.Contents;
    }

    public static Tuple<string, string>? ExportCertificateWithPrivateKey(MikrotikAPI api, string certID, string passphrase)
    {
        var certname = $"temp-certificate-{certID}";
        api.Send($"/certificate/export-certificate");
        api.Send($"=.id={certID}");
        api.Send($"=export-passphrase={passphrase}");
        api.Send("=type=pem");
        api.Send($"=file-name={certname}", true);

        foreach (var item in api.Receive()) // TODO: implement something to read status
        {
            Console.WriteLine($"RET = {item}");
        }

        Thread.Sleep(500);

        var pub = ReadSmallFile(api, certname + ".crt");
        var key = ReadSmallFile(api, certname + ".key");

        if (pub == null || key == null)
        {
            return null;
        }

        DeleteFile(api, pub.ID);
        DeleteFile(api, key.ID);

        return new Tuple<string, string>(pub.Contents, key.Contents);
    }
}

public static class Program
{
    public static void Main(string[] args)
    {
        var server = "";
        Console.WriteLine("Enter Mikrotik server address or IP:");
        server = Console.ReadLine();
        if (server == null)
        {
            return;
        }

        var user = "";
        Console.WriteLine("Enter username:");
        user = Console.ReadLine();
        if (user == null)
        {
            return;
        }
        var password = "";
        Console.WriteLine("Enter password:");
        password = Console.ReadLine();
        if (password == null)
        {
            return;
        }

        var key_password = "";
        Console.WriteLine("Enter passphrase for the keys:");
        key_password = Console.ReadLine();
        if (key_password == null)
        {
            return;
        }

        Console.WriteLine($"Connecting to Mikrotik at {server}");
        MikrotikAPI mikrotik = new MikrotikAPI(server);
        string thing = "";
        mikrotik.Connect();
        if (!mikrotik.Login(user, password, out thing))
        {
            Console.WriteLine($"Could not log in, result {thing}");
            mikrotik.Disconnect();
            return;
        }

        var custom_routes = new List<Tuple<string, string>>();
        // TODO: use user's input for this
        //custom_routes.Add(new Tuple<string, string>("192.168.0.0", "255.255.255.0"));
        //custom_routes.Add(new Tuple<string, string>("192.168.2.0", "255.255.255.0"));

        var verb = 4;

        // read OVPN server config
        var ovpnserver = MKH.GetOvpnServer(mikrotik);
        if (ovpnserver == null)
        {
            Console.WriteLine($"Could not read OVPN server config");
            mikrotik.Disconnect();
            return;
        }

        if (ovpnserver.RequireClientCertificate)
        {
            Console.WriteLine($"OVPN Server requires client certificate!");
        }
        else
        {
            Console.WriteLine($"OVPN Server doesn't require client cert, NOT IMPLEMENTED!!!");
            mikrotik.Disconnect();
            return;
        }

        var ovpn_cipher = "";
        if (ovpnserver.Cipher.Contains("aes256"))
        {
            ovpn_cipher = "AES-256-CBC";
        }
        else if (ovpnserver.Cipher.Contains("aes192"))
        {
            ovpn_cipher = "AES-192-CBC"; // untested
        }
        else if (ovpnserver.Cipher.Contains("aes128"))
        {
            ovpn_cipher = "AES-128-CBC"; // untested
        }
        else
        {
            Console.WriteLine($"OVPN Server cipher {ovpnserver.Cipher} is not supported yet!");
            mikrotik.Disconnect();
            return;
        }

        var ovpn_auth = "";
        if (ovpnserver.Auth.Contains("sha1"))
        {
            ovpn_auth = "SHA1";
        }
        else if (ovpnserver.Cipher.Contains("md5"))
        {
            ovpn_auth = "MD5"; // untested
        }
        else
        {
            Console.WriteLine($"OVPN Server auth {ovpnserver.Auth} is not supported yet!");
            mikrotik.Disconnect();
            return;
        }

        // read PPP secrets that could work with OVPN
        var secrets = MKH.GetOvpnAnyPPPSecrets(mikrotik);

        // get server CA
        Console.WriteLine($"OVPN Server cert is '{ovpnserver.Certificate}', looking for it and its CA...");
        var server_cert = MKH.GetCertificateWithName(mikrotik, ovpnserver.Certificate);
        if (server_cert == null || server_cert.CA == null)
        {
            Console.WriteLine($"Could not read OVPN Server cert, or CA is null!");
            mikrotik.Disconnect();
            return;
        }

        if (server_cert.CommonName == null)
        {
            Console.WriteLine("OVPN Server cert doesn't have a CommonName (which is the remote address for OVPN), can't continue");
            mikrotik.Disconnect();
            return;
        }
        
        Console.WriteLine($"OVPN Server CA is {server_cert.CA}, reading it...");
        var server_ca = MKH.GetCertificateWithName(mikrotik, server_cert.CA);
        if (server_ca == null)
        {
            Console.WriteLine($"Could not read OVPN Server CA!");
            mikrotik.Disconnect();
            return;
        }

        var server_ca_cert = MKH.ExportCertificate(mikrotik, server_ca.ID);


        List<OVPNConfigFile> configs = new List<OVPNConfigFile>();

        foreach (var secret in secrets)
        {
            if (ovpnserver.RequireClientCertificate)
            {
                // look for client certificate
                var client_certs = MKH.GetCertificatesWithCommonName(mikrotik, secret.Name);
                if (client_certs == null || client_certs.Count == 0)
                {
                    Console.WriteLine($" WARNING: User {secret.Name} does not have a matching certificate, skipping...");
                    continue;
                }

                foreach (var cert in client_certs)
                {
                    if (cert.KeyUsage == "tls-client" && cert.Issued && cert.PrivateKey)
                    {
                        // TODO check if cert is valid and not expired
                        Console.WriteLine($" Got cert {cert.Name} for user {secret.Name}, adding to list...");

                        configs.Add(new OVPNConfigFile(server_ca, cert, secret, ovpnserver));
                        break;
                    }
                }
            }
        }

        Console.WriteLine($"==============");

        foreach (var config in configs)
        {
            Console.WriteLine($"Processing user {config.Secret.Name}...");

            var client_certs = MKH.ExportCertificateWithPrivateKey(mikrotik, config.Client.ID, key_password);
            if (client_certs == null)
            {
                Console.WriteLine($" Could not read client {config.Secret.Name} cert, skipping...");
                continue;
            }

            var cfg_contents = $"client\r\ndev tun\r\nproto tcp-client\r\npersist-key\r\npersist-tun\r\ntls-client\r\nremote-cert-tls server\r\nverb {verb}\r\nauth-nocache\r\nmute 10\r\nremote {server_cert.CommonName}\r\nport {config.Server.Port}\r\nauth {ovpn_auth}\r\ncipher {ovpn_cipher}\r\nredirect-gateway def1\r\nauth-user-pass\r\n";
            foreach (var route in custom_routes)
            {
                cfg_contents += $"route {route.Item1} {route.Item2}\r\n";
            }

            cfg_contents += "\r\n<ca>\r\n" + server_ca_cert + "\r\n</ca>";
            cfg_contents += "\r\n<cert>\r\n" + client_certs.Item1 + "\r\n</cert>";
            cfg_contents += "\r\n<key>\r\n" + client_certs.Item2 + "\r\n</key>";

            System.IO.File.WriteAllText(config.Secret.Name + ".ovpn", cfg_contents);
            Console.WriteLine($" OVPN file: " + config.Secret.Name + ".ovpn");
        }

        Console.WriteLine("Done\r\nPress any key to continue");
        Console.ReadKey();
    }
}

public class MikrotikAPI
{
    string _IPAddress;
    int _APIPort;
    bool _UseSSL;
    Stream _Stream;
    SslStream _SslStream;
    TcpClient _TcpClient;

    public MikrotikAPI(string IPAddress, bool UseSSL = false, int APIPort = 8728)
    {
        _IPAddress = IPAddress;
        _APIPort = APIPort;
        _UseSSL = UseSSL;
    }

    public static bool ValidateServerCertificate(
            object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
    {
        return true;
    }

    public void Connect()
    {
        if (_UseSSL && _APIPort == 8728) _APIPort = 8729;

        _TcpClient = new TcpClient();
        _TcpClient.Connect(_IPAddress, _APIPort);

        if (_UseSSL)
        {
            _SslStream = new SslStream(_TcpClient.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);
            _SslStream.AuthenticateAsClient(_IPAddress);
        }
        else
            _Stream = (Stream)_TcpClient.GetStream();
    }
    public void Disconnect()
    {
        if (_UseSSL)
            _Stream.Close();
        else
            _SslStream.Close();

        _TcpClient.Close();
    }

    public bool LoginDeprecated(string Username, string Password)
    {
        Send("/login", true);
        string hash = Receive()[0].Split(new string[] { "ret=" }, StringSplitOptions.None)[1];
        Send("/login");
        Send("=name=" + Username);
        Send("=response=00" + EncodePassword(Password, hash), true);
        List<string> ReceiveResult = Receive();
        if (ReceiveResult[0] == "!done")
        {
            return true;
        }
        else
        {
            return false;
        }
    }

    public bool Login(string Username, string Password, out string OutMessageDesc)
    {
        OutMessageDesc = "";

        Send("/login");
        Send("=name=" + Username);
        Send("=password=" + Password, true);
        List<string> ReceiveResult = Receive();
        if (ReceiveResult[0] == "!done")
        {
            return true;
        }
        else
        {
            OutMessageDesc = ReceiveResult[1];
            return false;
        }
    }

    public void Send(string DataToSend, bool EndofPacket = false)
    {
        if (_UseSSL)
            DoSendSSL(DataToSend, EndofPacket);
        else
            DoSend(DataToSend, EndofPacket);
    }

    private void DoSend(string DataToSend, bool EndofPacket = false)
    {
        byte[] DataToSendasByte = Encoding.ASCII.GetBytes(DataToSend.ToCharArray());
        byte[] SendSize = EncodeLength(DataToSendasByte.Length);
        _Stream.Write(SendSize, 0, SendSize.Length);
        _Stream.Write(DataToSendasByte, 0, DataToSendasByte.Length);
        if (EndofPacket) _Stream.WriteByte(0);
    }

    private void DoSendSSL(string DataToSend, bool EndofPacket = false)
    {
        byte[] DataToSendasByte = Encoding.ASCII.GetBytes(DataToSend.ToCharArray());
        byte[] SendSize = EncodeLength(DataToSendasByte.Length);
        _SslStream.Write(SendSize, 0, SendSize.Length);
        _SslStream.Write(DataToSendasByte, 0, DataToSendasByte.Length);
        if (EndofPacket) _SslStream.WriteByte(0);
    }

    public ArrayList ReceiveList()
    {
        List<string> ReceivedDataList;

        if (_UseSSL)
            ReceivedDataList = DoReceiveSSL();
        else
            ReceivedDataList = DoReceive();

        ArrayList DataList = new ArrayList();
        List<string> ReceivedData = new List<string>();
        foreach (string DataLine in ReceivedDataList)
        {
            if (DataLine == "!re" || DataLine == "!done" || DataLine == "!trap")
            {
                DataList.Add(ReceivedData);
                ReceivedData = new List<string>();
            }
            else
                ReceivedData.Add(DataLine);
        }
        if (DataList.Count > 1) DataList.RemoveAt(0);

        return DataList;
    }


    public List<string> Receive()
    {
        if (_UseSSL)
            return DoReceiveSSL();
        else
            return DoReceive();
    }

    private List<string> DoReceive()
    {
        List<string> OutputList = new List<string>();
        long TempReceiveSize;
        string TempString = "";
        long ReceiveSize = 0;
        while (true)
        {
            TempReceiveSize = (byte)_Stream.ReadByte();
            if (TempReceiveSize > 0)
            {
                if ((TempReceiveSize & 0x80) == 0)
                {
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xC0) == 0x80)
                {
                    TempReceiveSize &= ~0xC0;
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xE0) == 0xC0)
                {
                    TempReceiveSize &= ~0xE0;
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xF0) == 0xE0)
                {
                    TempReceiveSize &= ~0xF0;
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xF8) == 0xF0)
                {
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_Stream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
            }
            else
                ReceiveSize = TempReceiveSize;

            for (int i = 0; i < ReceiveSize; i++)
            {
                Char TempChar = (Char)_Stream.ReadByte();
                TempString += TempChar;
            }

            if (ReceiveSize > 0)
            {
                OutputList.Add(TempString);
                if (TempString == "!done") break;
                TempString = "";
            }
        }
        return OutputList;
    }

    private List<string> DoReceiveSSL()
    {
        List<string> OutputList = new List<string>();
        long TempReceiveSize;
        string TempString = "";
        long ReceiveSize = 0;
        while (true)
        {
            TempReceiveSize = (byte)_SslStream.ReadByte();
            if (TempReceiveSize > 0)
            {
                if ((TempReceiveSize & 0x80) == 0)
                {
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xC0) == 0x80)
                {
                    TempReceiveSize &= ~0xC0;
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xE0) == 0xC0)
                {
                    TempReceiveSize &= ~0xE0;
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xF0) == 0xE0)
                {
                    TempReceiveSize &= ~0xF0;
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
                else if ((TempReceiveSize & 0xF8) == 0xF0)
                {
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    TempReceiveSize <<= 8;
                    TempReceiveSize += (byte)_SslStream.ReadByte();
                    ReceiveSize = TempReceiveSize;
                }
            }
            else
                ReceiveSize = TempReceiveSize;

            for (int i = 0; i < ReceiveSize; i++)
            {
                Char TempChar = (Char)_SslStream.ReadByte();
                TempString += TempChar;
            }

            if (ReceiveSize > 0)
            {
                OutputList.Add(TempString);
                if (TempString == "!done") break;
                TempString = "";
            }
        }
        return OutputList;
    }

    private byte[] EncodeLength(int delka)
    {
        if (delka < 0x80)
        {
            byte[] tmp = BitConverter.GetBytes(delka);
            return new byte[1] { tmp[0] };
        }
        if (delka < 0x4000)
        {
            byte[] tmp = BitConverter.GetBytes(delka | 0x8000);
            return new byte[2] { tmp[1], tmp[0] };
        }
        if (delka < 0x200000)
        {
            byte[] tmp = BitConverter.GetBytes(delka | 0xC00000);
            return new byte[3] { tmp[2], tmp[1], tmp[0] };
        }
        if (delka < 0x10000000)
        {
            byte[] tmp = BitConverter.GetBytes(delka | 0xE0000000);
            return new byte[4] { tmp[3], tmp[2], tmp[1], tmp[0] };
        }
        else
        {
            byte[] tmp = BitConverter.GetBytes(delka);
            return new byte[5] { 0xF0, tmp[3], tmp[2], tmp[1], tmp[0] };
        }
    }

    private string EncodePassword(string Password, string hash)
    {
        byte[] hash_byte = new byte[hash.Length / 2];
        for (int i = 0; i <= hash.Length - 2; i += 2)
        {
            hash_byte[i / 2] = Byte.Parse(hash.Substring(i, 2), System.Globalization.NumberStyles.HexNumber);
        }
        byte[] heslo = new byte[1 + Password.Length + hash_byte.Length];
        heslo[0] = 0;
        Encoding.ASCII.GetBytes(Password.ToCharArray()).CopyTo(heslo, 1);
        hash_byte.CopyTo(heslo, 1 + Password.Length);

        Byte[] hotovo;
        System.Security.Cryptography.MD5 md5;

        md5 = new System.Security.Cryptography.MD5CryptoServiceProvider();

        hotovo = md5.ComputeHash(heslo);

        //Convert encoded bytes back to a 'readable' string
        string navrat = "";
        foreach (byte h in hotovo)
        {
            navrat += h.ToString("x2");
        }
        return navrat;
    }

}