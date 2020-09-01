using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Security.Cryptography;
using System.IO;

namespace SecureMessageBroadcastApplicationServer
{
    public partial class server : Form
    {
        private struct Information
        {
            private Socket socket;
            private byte[] sessionKey;
            private byte[] messageKey;
            private byte[] iv;
            public Information(Socket s, byte[] sk, byte[] mk, byte[] ch)
            {
                socket = s;
                sessionKey = sk;
                messageKey = mk;
                iv = ch;
            }
            public Socket GetSocket()
            {
                return socket;
            }
            public byte[] GetSessionKey()
            {
                return sessionKey;
            }
            public byte[] GetMessageKey()
            {
                return messageKey;
            }
            public byte[] GetIV()
            {
                return iv;
            }
            public override bool Equals(object obj)
            {
                if (!(obj is Information)) return false;
                return this == (Information)obj;
            }
            public override int GetHashCode()
            {
                return base.GetHashCode();
            }
            public override string ToString()
            {
                return "Session Key: " + generateHexStringFromByteArray(sessionKey) + "\nMessage Key: " + generateHexStringFromByteArray(messageKey) + "\nChallange: " + generateHexStringFromByteArray(iv);
            }
            public static bool operator ==(Information lhs, Information rhs)
            {
                if (Encoding.Default.GetString(lhs.GetSessionKey()) == Encoding.Default.GetString(rhs.GetSessionKey()) &&
                    Encoding.Default.GetString(lhs.GetMessageKey()) == Encoding.Default.GetString(rhs.GetMessageKey()))
                    return true;
                else return false;
            }
            public static bool operator !=(Information lhs, Information rhs)
            {
                if (Encoding.Default.GetString(lhs.GetSessionKey()) == Encoding.Default.GetString(rhs.GetSessionKey()) &&
                    Encoding.Default.GetString(lhs.GetMessageKey()) == Encoding.Default.GetString(rhs.GetMessageKey()))
                    return false;
                else return true;
            }
        }
        private struct Constants
        {
            public const string PU_PR_ENC_DEC_PATH = "\\encrypted_server_enc_dec_pub_prv.txt";
            public const string PU_PR_SIG_VER_PATH = "\\encrypted_server_signing_verification_pub_prv.txt";
            public const string CLIENT_DATABASE_PATH = "\\client_password_database.txt";
        }
        private struct Packet
        {
            private byte[] command;
            private byte[] content;
            private byte[] fullPacket;
            public Packet(byte[] i, string cmd)
            {
                command = Encoding.Default.GetBytes(cmd);
                content = i;
                byte[] size = Encoding.Default.GetBytes((7 + content.Length).ToString("D5"));
                byte[] packet = new byte[7 + content.Length];
                Array.Copy(content, 0, packet, 7, content.Length);
                Array.Copy(command, 0, packet, 5, 2);
                Array.Copy(size, 0, packet, 0, 5);
                fullPacket = packet;
            }
            public byte[] Full()
            {
                return fullPacket;
            }
            public static string GetCommand(byte[] b)
            {
                byte[] r = new byte[2];
                Array.Copy(b, 0, r, 0, 2);
                return Encoding.Default.GetString(r);
            }
            public static byte[] GetContent(byte[] b)
            {
                byte[] r = new byte[b.Length - 2];
                Array.Copy(b, 2, r, 0, b.Length - 2);
                return r;
            }
        }
        private struct ActiveClients
        {
            private List<Socket> connectedClients;
            private Dictionary<string, Information> clients;
            public ActiveClients(Dictionary<string, Information> d, List<Socket> c)
            {
                clients = d;
                connectedClients = c;
            }
            public void AddClient(string username, Socket socket, byte[] sessionKey, byte[] messageKey, byte[] challange)
            {
                try
                {
                    if (clients.ContainsKey(username)) UpdateClient(username, socket, sessionKey, messageKey, challange);
                    else clients.Add(username, new Information(socket, sessionKey, messageKey, challange));
                }
                catch (Exception e)
                {
                    throw e;
                }
            }
            public void AddConnectedClient(Socket socket)
            {
                connectedClients.Add(socket);
            }
            private void UpdateClient(string username, Socket socket, byte[] sessionKey, byte[] messageKey, byte[] challange)
            {
                try
                {
                    if (IsSocketConnected(clients[username].GetSocket())) throw new Exception("Client is already connected");
                    else
                    {
                        clients.Remove(username);
                        clients.Add(username, new Information(socket, sessionKey, messageKey, challange));
                    }
                }
                catch (Exception e)
                {
                    throw e;
                }
            }
            public bool IsUserConnected(string username)
            {
                if (clients.ContainsKey(username)) return IsSocketConnected(clients[username].GetSocket());
                else return false;
            }
            private bool IsSocketConnected(Socket s)
            {
                try
                {
                    return !((s.Poll(1000, SelectMode.SelectRead) && (s.Available == 0)) || !s.Connected);
                }
                catch { return false; }
            }
            public void TerminateAllSockets()
            {
                foreach (Information s in clients.Values)
                {
                    try
                    {
                        s.GetSocket().Send(new Packet(Encoding.Default.GetBytes("MANUAL_SHUTDOWN"), "00").Full());
                        s.GetSocket().Shutdown(SocketShutdown.Both);
                        s.GetSocket().Close();
                        s.GetSocket().Dispose();
                    }
                    catch { }
                }
                clients.Clear();
                foreach (Socket s in connectedClients)
                {
                    try
                    {
                        // s.Shutdown(SocketShutdown.Both);
                        s.Close();
                        s.Dispose();
                    }
                    catch { }
                }
                connectedClients.Clear();
            }
            public void DisconnectClient(string username, bool forced)
            {
                try
                {
                    if (forced) clients[username].GetSocket().Send(new Packet(Encoding.Default.GetBytes("MANUAL_SHUTDOWN"), "00").Full());
                    //clients[username].getSocket().Shutdown(SocketShutdown.Both);
                    clients[username].GetSocket().Close();
                    clients[username].GetSocket().Dispose();
                    clients.Remove(username);
                }
                catch { }
            }
            public void DisconnectSocket(Socket s)
            {
                try
                {
                    // s.Shutdown(SocketShutdown.Both);
                    s.Close();
                    s.Dispose();
                    connectedClients.Remove(s);
                }
                catch { }
            }
            public void CheckAndUpdateAllSocket()
            {
                foreach (string username in clients.Keys.ToList())
                {
                    try
                    {
                        if (!IsSocketConnected(clients[username].GetSocket())) clients.Remove(username);
                    }
                    catch { }
                }
                foreach (Socket s in connectedClients.ToList())
                {
                    try
                    {
                        if (!IsSocketConnected(s)) connectedClients.Remove(s);
                    }
                    catch { }
                }
            }
            public Information GetInformation(string username)
            {
                return clients[username];
            }
            public List<string> NameListOfActiveClients()
            {
                List<string> actives = new List<string>();
                foreach (string username in clients.Keys.ToList())
                {
                    try
                    {
                        if (IsUserConnected(username)) actives.Add(username);
                    }
                    catch { }
                }
                return actives;
            }
            public List<Socket> SocketListOfActiveClientsBut(Socket sender)
            {
                List<Socket> actives = new List<Socket>();
                foreach (Information s in clients.Values.ToList())
                {
                    try
                    {
                        if (IsSocketConnected(s.GetSocket()) && s.GetSocket() != sender) actives.Add(s.GetSocket());
                    }
                    catch { }
                }
                return actives;
            }
            public List<Information> InformationListOfActiveClientsBut(Information info)
            {
                List<Information> actives = new List<Information>();
                foreach (Information s in clients.Values.ToList())
                {
                    try
                    {
                        if (IsSocketConnected(s.GetSocket()) && s != info) actives.Add(s);
                    }
                    catch { }
                }
                return actives;
            }
        }
        private struct Database
        {
            public static byte[] ReturnHash(string username)
            {
                Initialize();
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.CLIENT_DATABASE_PATH))
                {
                    string line = null;
                    while ((line = fileReader.ReadLine()) != null)
                    {
                        int index = 0;
                        foreach (char c in line.ToCharArray())
                        {
                            if (c == '\t')
                            {
                                if (username == line.Substring(0, index))
                                {
                                    return hexStringToByteArray(line.Substring(index + 1, line.Length - index - 1));
                                }
                                else break;
                            }
                            index++;
                        }
                    }
                }
                return null;
            }
            public static bool Contains(string username)
            {
                try
                {
                    Initialize();
                    using (System.IO.StreamReader fileReader =
                    new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.CLIENT_DATABASE_PATH))
                    {
                        string line = null;
                        while ((line = fileReader.ReadLine()) != null)
                        {
                            int index = 0;
                            foreach (char c in line.ToCharArray())
                            {
                                if (c == '\t')
                                {
                                    if (username == line.Substring(0, index)) return true;
                                    else break;
                                }
                                index++;
                            }
                        }
                    }
                }
                catch (Exception e)
                {
                    throw e;
                }
                return false;
            }
            public static void Add(string username, byte[] hash)
            {
                string path = System.IO.Directory.GetCurrentDirectory() + Constants.CLIENT_DATABASE_PATH;
                if (File.Exists(path))
                {
                    using (StreamWriter sw = File.AppendText(path))
                    {
                        sw.WriteLine(username + '\t' + generateHexStringFromByteArray(hash));
                    }
                }
                else
                {
                    Initialize();
                    Add(username, hash);
                }
            }
            private static void Initialize()
            {
                string path = System.IO.Directory.GetCurrentDirectory() + Constants.CLIENT_DATABASE_PATH;
                if (!File.Exists(path))
                {
                    File.CreateText(path).Close();
                }
            }
        }

        private Socket serverSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);          // server socket
        private ActiveClients clients = new ActiveClients(new Dictionary<string, Information>(), new List<Socket>());       // stores authenticated and connected clients

        private bool listening = false;         // viable to listening port
        private bool terminating = false;       // manually pressed termination button
        private bool detailed_mode = false;     // to show details such as keys 

        private RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();    // secure random number generator
        private byte[] serverPassword;  

        public server()
        {
            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(server_FormClosing);

            InitializeComponent();

            input_port.Enabled = true;
            input_password.Enabled = true;
            button_start.Enabled = true;
            button_terminate.Enabled = false;
            button_show_online.Enabled = false;
            button_change_password.Enabled = false;
        }
        private void server_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            clients.TerminateAllSockets();
            Environment.Exit(0);
        }
        private void listenPort()
        {
            while (listening && !terminating)
            {
                try
                {
                    Socket socket = serverSocket.Accept();  // accepts the incoming connection
                    updateRichTextBox(logTextBox, socket.RemoteEndPoint.ToString() + " is connected\n");
                    clients.AddConnectedClient(socket);
                    Thread listenClientThread = new Thread(() => listenClient(socket)); // starting thread with parameters
                    listenClientThread.Start();
                }
                catch { }
            }
        }
        private void listenClient(Socket socket)
        {
            bool authenticated = false;
            string username = null;

            while (listening && !terminating)
            {
                try
                {
                    byte[] packet = derivePacketViaRecv(socket);        // gets packet but its size part
                    string cmd = Packet.GetCommand(packet);             // gets command part
                    byte[] content = Packet.GetContent(packet);         // gets the remaining aka "content"

                    if (listening && !terminating && !authenticated && cmd == "10")   // ENROLLMENT
                    {
                        try
                        {
                            byte[] passwordBytes = new byte[16];    // hashed password is always 16 bytes
                            byte[] encrypted = decryptWithRSA(Encoding.Default.GetString(content), 3072, Encoding.Default.GetString(keyEncDecRSA()));
                            byte[] usernameBytes = new byte[encrypted.Length - 16];                 // remaining contains the username

                            Array.Copy(encrypted, 0, passwordBytes, 0, 16);                         // derives passwordBytes
                            Array.Copy(encrypted, 16, usernameBytes, 0, encrypted.Length - 16);     // derives usernameBytes

                            username = Encoding.Default.GetString(usernameBytes);


                            if (!isUsernameValid(username)) throw new Exception("Username violates rules.");

                            if (!Database.Contains(username))
                            {
                                updateRichTextBox(logTextBox, "\"" + username + "\" Enrollment has been completed.\n");

                                byte[] sign = signWithRSA("ENROLLMENT_SUCCESS", 3072, Encoding.Default.GetString(keySignVerRSA()));

                                Database.Add(username, passwordBytes);

                                if (detailed_mode) updateRichTextBox(logTextBox, "\"" + username + "\" Digital Signature for Message \"ENROLLMENT_SUCCESS\"\n" + generateHexStringFromByteArray(sign) + "\n");

                                socket.Send(new Packet(Encoding.Default.GetBytes("ENROLLMENT_SUCCESS"), "18").Full());      // MESSAGE COMMAND FOR ENROLLMENT RESULT
                                socket.Send(new Packet(sign, "19").Full());                                                 // SIGNATURE COMMAND WITH SIGNATURE OF ENROLLMENT RESULT
                            }
                            else
                            {
                                updateRichTextBox(logTextBox, "\"" + username + "\" Enrollment has been rejected.\n");

                                byte[] sign = signWithRSA("ENROLLMENT_FAILURE", 3072, Encoding.Default.GetString(keySignVerRSA()));

                                if (detailed_mode) updateRichTextBox(logTextBox, "\"" + username + "\" Digital Signature for Message: \"ENROLLMENT_FAILURE\"\n" + generateHexStringFromByteArray(sign) + "\n");

                                socket.Send(new Packet(Encoding.Default.GetBytes("ENROLLMENT_FAILURE"), "18").Full());  // MESSAGE COMMAND FOR ENROLLMENT RESULT
                                socket.Send(new Packet(sign, "19").Full());                                             // SIGNATURE COMMAND WITH SIGNATURE OF ENROLLMENT RESULT
                            }
                        }
                        catch (Exception exception)
                        {
                            if (username != null) updateRichTextBox(logTextBox, "\"" + username + "\" Enrollment has not been completed. " + exception.Message + "\n");
                            else updateRichTextBox(logTextBox, "Client with wrong public key detected.\n");
                            username = null;
                            socket.Send(new Packet(Encoding.Default.GetBytes("FAILURE"), "99").Full());
                        }
                    }
                    else if (listening && !terminating && !authenticated && cmd == "20")  // AUTHENTICATION
                    {
                        try
                        {
                            username = Encoding.Default.GetString(content);

                            if (!Database.Contains(username))   throw new Exception("There is no such user in database.");
                            if (clients.IsUserConnected(username))  throw new Exception("Client is already active in server.");

                            else
                            {
                                byte[] rndBytes = new byte[128 / 8];        // 128 bits long byte array
                                rngCsp.GetBytes(rndBytes);                  // filling with random bytes

                                if (detailed_mode) updateRichTextBox(logTextBox, "\"" + username + "\" initiates authentication, Random challange: " + generateHexStringFromByteArray(rndBytes) + "\n");
                                else updateRichTextBox(logTextBox, "\"" + username + "\" initiates authentication, Random challange.\n");

                                socket.Send(new Packet(rndBytes, "21").Full()); // sends challange

                                byte[] HMACBytes = derivePacketViaRecv(socket); // receives HMAC of challange

                                if (Packet.GetCommand(HMACBytes) == "00") throw new Exception("Client manually disconnected during authentication.");
                                else if (Packet.GetCommand(HMACBytes) == "22")
                                {
                                    if (Encoding.Default.GetString(Packet.GetContent(HMACBytes)) == Encoding.Default.GetString(applyHMACwithSHA256(Encoding.Default.GetString(rndBytes), Database.ReturnHash(username))))
                                    {
                                        if (detailed_mode) updateRichTextBox(logTextBox, "\"" + username + "\" HMAC of challange: " + generateHexStringFromByteArray(HMACBytes) + "\n");

                                        byte[] random1 = new byte[128 / 8];        // 128 bits long byte array, will be used for symmetric encryption and decryption
                                        rngCsp.GetBytes(random1);                  // filling with random bytes

                                        byte[] random2 = new byte[128 / 8];        // 128 bits long byte array, wiil be used for message authentication
                                        rngCsp.GetBytes(random2);                  // filling with random bytes

                                        byte[] aes_iv = new byte[16];                       // AES initial vector
                                        byte[] aes_key = new byte[16];                      // AES key

                                        Array.Copy(Database.ReturnHash(username), 0, aes_key, 0, 16);
                                        Array.Copy(rndBytes, 0, aes_iv, 0, 16);

                                        byte[] encrypted1 = encryptWithAES128(Encoding.Default.GetString(random1), aes_key, aes_iv);    // encrypted session key
                                        byte[] encrypted2 = encryptWithAES128(Encoding.Default.GetString(random2), aes_key, aes_iv);    // encrypted message key
                                        
                                        string total = "AUTH_SUCCESS" + Encoding.Default.GetString(encrypted1) + Encoding.Default.GetString(encrypted2);    // full content that will be sent
                                        byte[] sign = signWithRSA(total, 3072, Encoding.Default.GetString(keySignVerRSA()));    // signature of full content

                                        socket.Send(new Packet(Encoding.Default.GetBytes(total), "28").Full());
                                        socket.Send(new Packet(sign, "29").Full());

                                        clients.AddClient(username, socket, random1, random2, Database.ReturnHash(username));   // adds this client to active clients

                                        if (detailed_mode)
                                        {
                                            updateRichTextBox(logTextBox, "\"" + username + "\" Session Key: " + generateHexStringFromByteArray(random1) + "\n");
                                            updateRichTextBox(logTextBox, "\"" + username + "\" Message Key: " + generateHexStringFromByteArray(random2) + "\n");
                                        }
                                        updateRichTextBox(logTextBox, "\"" + username + "\" Authentication has been succesful.\n");
                                        authenticated = true;
                                    }
                                    else
                                    {
                                        byte[] sign = signWithRSA("AUTH_FAILURE", 3072, Encoding.Default.GetString(keySignVerRSA()));
                                        if (detailed_mode) updateRichTextBox(logTextBox, "\"" + username + "\" Digital Signature for Message: \"AUTH_FAILURE\"\n" + generateHexStringFromByteArray(sign) + "\n");
                                        updateRichTextBox(logTextBox, "\"" + username + "\" Authentication has been rejected\n");

                                        username = null;

                                        socket.Send(new Packet(Encoding.Default.GetBytes("AUTH_FAILURE"), "28").Full());
                                        socket.Send(new Packet(sign, "29").Full());
                                    }
                                }
                                else throw new Exception("Authentication has been rejected.");
                            }
                        }
                        catch (Exception exception)
                        {
                            if (username != null) updateRichTextBox(logTextBox, "\"" + username + "\" is denied. " + exception.Message + "\n");
                            username = null;
                            authenticated = false;
                            socket.Send(new Packet(Encoding.Default.GetBytes("FAILURE"), "99").Full());
                        }
                    }
                    else if (listening && !terminating && authenticated && cmd == "30")  // CHATTING
                    {
                        try
                        {
                            byte[] encrypted = new byte[content.Length - 32 - 16];   // encrypted chat message
                            byte[] hmac = new byte[32];     // hmac of encrypted
                            byte[] received_iv = new byte[16];  // client's random iv

                            Array.Copy(content, 0, encrypted, 0, encrypted.Length);
                            Array.Copy(content, encrypted.Length, hmac, 0, 32);
                            Array.Copy(content, encrypted.Length + hmac.Length, received_iv, 0, 16);
                            
                            byte[] message = decryptWithAES128(Encoding.Default.GetString(encrypted), clients.GetInformation(username).GetSessionKey(), received_iv);  // chat message
                            byte[] check = applyHMACwithSHA256(Encoding.Default.GetString(encrypted), clients.GetInformation(username).GetMessageKey());

                            if (Encoding.Default.GetString(hmac) == Encoding.Default.GetString(check))
                            {
                                // if verified
                                if (detailed_mode) updateRichTextBox(logTextBox, "\"" + username + "\" HMAC of chat message: " + generateHexStringFromByteArray(hmac) + "\n");
                                updateRichTextBox(messageTextBox, username + ": " + Encoding.Default.GetString(message) + "\n");

                                // Sending to other online clients
                                foreach (Information i in clients.InformationListOfActiveClientsBut(clients.GetInformation(username)))
                                {
                                    try
                                    {
                                        byte[] random_iv = new byte[16];
                                        rngCsp.GetBytes(random_iv);

                                        string broadcastMessage = username + '\t' + Encoding.Default.GetString(message);    // (sender username // chat message)
                                        byte[] broadcastEncrypted = encryptWithAES128(broadcastMessage, i.GetSessionKey(), random_iv);  // encrypted (sender username // chat message)
                                        byte[] broadcastHmac = applyHMACwithSHA256(Encoding.Default.GetString(broadcastEncrypted), i.GetMessageKey());  // hmac of encrypted
                                        byte[] broadcastPacket = new byte[broadcastEncrypted.Length + broadcastHmac.Length + 16];    // full packet (encrypted // hmac)

                                        Array.Copy(broadcastEncrypted, 0, broadcastPacket, 0, broadcastEncrypted.Length);
                                        Array.Copy(broadcastHmac, 0, broadcastPacket, broadcastEncrypted.Length, broadcastHmac.Length);
                                        Array.Copy(random_iv, 0, broadcastPacket, broadcastEncrypted.Length + broadcastHmac.Length, 16);

                                        i.GetSocket().Send(new Packet(broadcastPacket, "31").Full());
                                    }
                                    catch { }
                                }
                            }
                            else
                            {
                                throw new Exception("Anomaly detected while verifying.");
                                // if not verified discarded
                            }
                        }
                        catch (Exception exception)
                        {
                            username = null;
                            authenticated = false;
                            throw exception;
                        }
                    }
                    else if (listening && !terminating && authenticated && cmd == "00")  // MANUAL DISCONNECT AFTER AUTHENTICATION
                    {
                        throw new Exception("Manual termination of connection.");
                    }
                    else if (listening && !terminating && cmd == "00")  // MANUAL DISCONNECT BEFORE AUTHENTICATION
                    {
                        throw new Exception("Manual termination of connection.");
                    }
                    else // INVALID PACKET
                    {
                        throw new Exception("Anomaly detected, forcing disconnection,");
                    }
                }
                catch (Exception exception)
                {
                    try
                    {
                        if (username != null)
                        {
                            updateRichTextBox(logTextBox, "\"" + username + "\" " + socket.RemoteEndPoint.ToString() + " is disconnected. " + exception.Message + "\n");
                            clients.DisconnectClient(username, false);
                        }
                        else
                        {
                            updateRichTextBox(logTextBox, socket.RemoteEndPoint.ToString() + " is disconnected. " + exception.Message + "\n");
                            clients.DisconnectSocket(socket);
                        }
                    }
                    catch { }
                    return;
                }
            }
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Crypto Functions ///////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////
        private byte[] keyEncDecRSA()
        {
            // reading RSA-3072 public-private key pair for encryption/decryption which are encrypted with AES 128 with CFB mode
            try
            {
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH))
                {
                    // byte[] hashedPassword = hashWithSHA256(serverPassword);
                    byte[] aes_iv = new byte[16];                       // AES initial vector
                    byte[] aes_key = new byte[16];                      // AES key
                    Array.Copy(serverPassword, 0, aes_iv, 0, 16);       // the least significant half 0-15
                    Array.Copy(serverPassword, 16, aes_key, 0, 16);     // the most significant half 16-31
                    return decryptWithAES128(Encoding.Default.GetString(hexStringToByteArray(fileReader.ReadLine())), aes_key, aes_iv);
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        private byte[] keySignVerRSA()
        {
            // reading RSA-3072 public-private key pair for signing/verification which are encrypted with AES 128 with CFB mode
            try
            {
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH))
                {
                    // byte[] hashedPassword = hashWithSHA256(serverPassword);
                    byte[] aes_iv = new byte[16];                       // AES initial vector
                    byte[] aes_key = new byte[16];                      // AES key
                    Array.Copy(serverPassword, 0, aes_iv, 0, 16);       // the least significant half 0-15
                    Array.Copy(serverPassword, 16, aes_key, 0, 16);     // the most significant half 16-31
                    return decryptWithAES128(Encoding.Default.GetString(hexStringToByteArray(fileReader.ReadLine())), aes_key, aes_iv);                       // true original form
                }
            }
            catch (Exception e)
            {
                throw e;
            }
        }
        static byte[] signWithRSA(string input, int algoLength, string xmlString)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            byte[] result = null;

            try
            {
                result = rsaObject.SignData(byteInput, "SHA256");
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        static bool verifyWithRSA(string input, int algoLength, string xmlString, byte[] signature)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlString);
            bool result = false;

            try
            {
                result = rsaObject.VerifyData(byteInput, "SHA256", signature);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;

            try
            {
                //true flag is set to perform direct RSA encryption using OAEP padding
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            return result;
        }
        static byte[] decryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create RSA object from System.Security.Cryptography
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            // set RSA object with xml string
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;
            try
            {
                result = rsaObject.Decrypt(byteInput, true);
            }
            catch (Exception e)
            {
                throw e;
                //throw new Exception("RSA Decryption failed");
            }
            return result;
        }
        static byte[] hashWithSHA256(string input)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create a hasher object from System.Security.Cryptography
            SHA256CryptoServiceProvider sha256Hasher = new SHA256CryptoServiceProvider();
            // hash and save the resulting byte array
            byte[] result = sha256Hasher.ComputeHash(byteInput);
            return result;
        }
        static byte[] encryptWithAES128(string input, byte[] key, byte[] IV)
        {
            byte[] byteInput = Encoding.Default.GetBytes(input);
            RijndaelManaged aesObject = new RijndaelManaged();
            aesObject.KeySize = 128;
            aesObject.BlockSize = 128;
            aesObject.Mode = CipherMode.CFB;
            aesObject.FeedbackSize = 128;
            aesObject.Key = key;
            aesObject.IV = IV;
            ICryptoTransform encryptor = aesObject.CreateEncryptor();
            byte[] result = null;
            try
            {
                result = encryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch
            {
                throw new Exception("Encryption failed");
            }
            return result;
        }
        static byte[] decryptWithAES128(string input, byte[] key, byte[] IV)
        {
            byte[] byteInput = Encoding.Default.GetBytes(input);
            RijndaelManaged aesObject = new RijndaelManaged();
            aesObject.KeySize = 128;
            aesObject.BlockSize = 128;
            aesObject.Mode = CipherMode.CFB;
            aesObject.FeedbackSize = 128;
            aesObject.Key = key;
            aesObject.IV = IV;
            ICryptoTransform decryptor = aesObject.CreateDecryptor();
            byte[] result = null;
            try
            {
                result = decryptor.TransformFinalBlock(byteInput, 0, byteInput.Length);
            }
            catch  // if encryption fails
            {
                throw new Exception("Decryption failed");
            }
            return result;
        }
        static byte[] applyHMACwithSHA256(string input, byte[] key)
        {
            // convert input string to byte array
            byte[] byteInput = Encoding.Default.GetBytes(input);
            // create HMAC applier object from System.Security.Cryptography
            HMACSHA256 hmacSHA256 = new HMACSHA256(key);
            // get the result of HMAC operation
            byte[] result = hmacSHA256.ComputeHash(byteInput);

            return result;
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Misc Functions /////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////
        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }
        static byte[] hexStringToByteArray(string hex)
        {
            int numberChars = hex.Length;
            byte[] bytes = new byte[numberChars / 2];
            for (int i = 0; i < numberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        private void updateRichTextBox(RichTextBox textBox, string msg)
        {   // will be used to update richTextBox.Text within multiple different threads
            if (terminating) return;
            Action append = () => textBox.AppendText("(" + DateTime.Now.ToString("MM/dd/yyyy HH:mm:ss") + ") " + msg);
            if (textBox.InvokeRequired)
                textBox.BeginInvoke(append);
            else
                append();
        }
        private byte[] derivePacketViaRecv(Socket s)
        {
            byte[] sizePart = new byte[5];                                                              // will hold the size of whole packet
            s.Receive(sizePart);                                                                        // receives the first 5 bytes which determines the size of 
            byte[] remaining = new byte[Convert.ToInt32(Encoding.Default.GetString(sizePart)) - 5];     // will hold the remaining where size will be sizePart - 5
            s.Receive(remaining);                                                                       // receives the remaining whole content 
            return remaining;
        }
        private bool isUsernameValid(string s)
        {
            List<char> username = s.ToList();

            if (!(username.Count >= 6 && username.Count <= 20)) return false;

            foreach (char c in username)
            {
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) return false;
            }
            return true;
        }
        private bool isPasswordValid(string s)
        {
            List<char> password = s.ToList();

            if (!(password.Count >= 8 && password.Count <= 20)) return false;

            bool spottedUppercase = false;
            bool spottedNumber = false;

            foreach (char c in password)
            {
                if (!((c >= 'a' && c <= 'Z') || (c >= '0' && c <= '9'))) return false;
                if (!spottedUppercase && c >= 'A' && c <= 'Z') spottedUppercase = true;
                if (!spottedNumber && c >= '0' && c <= '9') spottedNumber = true;
            }
            if (spottedNumber && spottedUppercase) return true;
            else return false;
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Form Functions /////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////
        private void server_Load(object sender, EventArgs e)
        {

        }
        private void button_start_Click(object sender, EventArgs e)
        {
            updateRichTextBox(logTextBox, "Server initiation protocol is started\n");
            try
            {
                if (input_port.Text == "" || input_password.Text == "") throw new Exception("There must be no empty inputs");

                byte[] hashedPassword = hashWithSHA256(input_password.Text);
                byte[] iv = new byte[16];
                byte[] key = new byte[16];
                Array.Copy(hashedPassword, 0, iv, 0, 16);       // the least significant half 0-15
                Array.Copy(hashedPassword, 16, key, 0, 16);     // the most significant half 16-31

                if (detailed_mode)
                {
                    updateRichTextBox(logTextBox, "AES KEY: " + generateHexStringFromByteArray(key) + "\n");
                    updateRichTextBox(logTextBox, "AES IV: " + generateHexStringFromByteArray(iv) + "\n");
                }

                // reading RSA-3072 public-private key pair for encryption/decryption which are encrypted with AES 128 with CFB mode
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH))
                {
                    string hex1 = fileReader.ReadLine();                                     // decrypted in HEX format
                    byte[] encryptedRSA1 = hexStringToByteArray(hex1);                       // decrpyted in Bytes
                    string normal1 = Encoding.Default.GetString(encryptedRSA1);              // decrypted in normal string
                    byte[] decryptedAES128_1 = decryptWithAES128(normal1, key, iv);          // true original form

                    if (detailed_mode)
                    {
                        updateRichTextBox(logTextBox, "Encrypted RSA public-private pair for encryption-decryption:\n" + hex1 + "\n");
                        updateRichTextBox(logTextBox, "Decrypted RSA public-private pair for encryption-decryption:\n" + generateHexStringFromByteArray(decryptedAES128_1) + "\n");
                    }
                }

                // reading RSA-3072 public-private key pair for signing/verification which are encrypted with AES 128 with CFB mode
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH))
                {
                    string hex2 = fileReader.ReadLine();                                     // decrypted in HEX format
                    byte[] encryptedRSA2 = hexStringToByteArray(hex2);                       // decrpyted in Bytes
                    string normal2 = Encoding.Default.GetString(encryptedRSA2);              // decrypted in normal string
                    byte[] decryptedAES128_2 = decryptWithAES128(normal2, key, iv);          // true original form

                    if (detailed_mode)
                    {
                        updateRichTextBox(logTextBox, "Encrypted RSA public-private pair for signing-verification:\n" + hex2 + "\n");
                        updateRichTextBox(logTextBox, "Decrypted RSA public-private pair for signing-verification:\n" + generateHexStringFromByteArray(decryptedAES128_2) + "\n");
                    }
                }

                serverPassword = hashWithSHA256(input_password.Text);
                input_password.Text = "";

                IPEndPoint endPoint = new IPEndPoint(IPAddress.Any, int.Parse(input_port.Text));
                serverSocket.Bind(endPoint);
                serverSocket.Listen(3);

                updateRichTextBox(logTextBox, "Server initiation protocol is succesfully done\n");
                updateRichTextBox(logTextBox, "Server started listening the port\n");

                input_port.Enabled = false;
                input_password.Enabled = false;
                button_start.Enabled = false;
                button_terminate.Enabled = true;
                button_show_online.Enabled = true;
                button_change_password.Enabled = true;

                Thread listenPortThread = new Thread(new ThreadStart(this.listenPort));
                listening = true;
                listenPortThread.Start();
            }
            catch (Exception exception)
            {
                updateRichTextBox(logTextBox, "ERROR: " + exception.Message + ", Server initiation protocol is terminated\n");
            }
        }
        private void button_terminate_Click(object sender, EventArgs e)
        {
            listening = false; terminating = true;
            try
            {
                button_terminate.Enabled = false;
                button_show_online.Enabled = false;
                button_change_password.Enabled = false;
                button_start.Enabled = false;
                check_detailed.Enabled = false;

                try { clients.TerminateAllSockets(); } catch { }
                try
                {
                    // serverSocket.Shutdown(SocketShutdown.Both);
                    serverSocket.Close();
                    serverSocket.Dispose();
                }
                catch { }
            }
            catch { }
            updateRichTextBox(logTextBox, "Server Manual Shutdown\n");
        }
        private void button_change_password_Click(object sender, EventArgs e)
        {
            try
            {
                byte[] newPassword = changePassword.executeChangePassword(serverPassword);
                if (newPassword == null) return;

                byte[] encrypted1;
                byte[] encrypted2;

                // PUBLIC PRIVATE KEY FOR ENC AND DEC
                if (File.Exists(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH))
                {
                    using (System.IO.StreamReader fileReader =
                    new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH))
                    {
                        byte[] aes_iv = new byte[16];                       // AES initial vector
                        byte[] aes_key = new byte[16];                      // AES key
                        Array.Copy(serverPassword, 0, aes_iv, 0, 16);       // the least significant half 0-15
                        Array.Copy(serverPassword, 16, aes_key, 0, 16);     // the most significant half 16-31
                        byte[] decrypted = decryptWithAES128(Encoding.Default.GetString(hexStringToByteArray(fileReader.ReadLine())), aes_key, aes_iv);

                        byte[] new_aes_iv = new byte[16];
                        byte[] new_aes_key = new byte[16];
                        Array.Copy(newPassword, 0, new_aes_iv, 0, 16);
                        Array.Copy(newPassword, 16, new_aes_key, 0, 16);
                        encrypted1 = encryptWithAES128(Encoding.Default.GetString(decrypted), new_aes_key, new_aes_iv);
                    }
                }
                else
                {
                    throw new Exception(Constants.PU_PR_ENC_DEC_PATH + " is not found");
                }

                // PUBLIC PRIVATE KEY FOR SIG AND VER
                if (File.Exists(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH))
                {
                    using (System.IO.StreamReader fileReader =
                    new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH))
                    {
                        byte[] aes_iv = new byte[16];                       // AES initial vector
                        byte[] aes_key = new byte[16];                      // AES key
                        Array.Copy(serverPassword, 0, aes_iv, 0, 16);       // the least significant half 0-15
                        Array.Copy(serverPassword, 16, aes_key, 0, 16);     // the most significant half 16-31
                        byte[] decrypted = decryptWithAES128(Encoding.Default.GetString(hexStringToByteArray(fileReader.ReadLine())), aes_key, aes_iv);

                        byte[] new_aes_iv = new byte[16];
                        byte[] new_aes_key = new byte[16];
                        Array.Copy(newPassword, 0, new_aes_iv, 0, 16);
                        Array.Copy(newPassword, 16, new_aes_key, 0, 16);
                        encrypted2 = encryptWithAES128(Encoding.Default.GetString(decrypted), new_aes_key, new_aes_iv);
                    }
                }
                else
                {
                    throw new Exception(Constants.PU_PR_SIG_VER_PATH + " is not found");
                }

                serverPassword = newPassword;

                File.Delete(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH);
                File.Create(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH).Close();

                using (System.IO.StreamWriter file =
                new System.IO.StreamWriter(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_ENC_DEC_PATH))
                {
                    file.WriteLine(generateHexStringFromByteArray(encrypted1));
                }

                File.Delete(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH);
                File.Create(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH).Close();

                using (System.IO.StreamWriter file =
                new System.IO.StreamWriter(System.IO.Directory.GetCurrentDirectory() + Constants.PU_PR_SIG_VER_PATH))
                {
                    file.WriteLine(generateHexStringFromByteArray(encrypted2));
                }

                updateRichTextBox(logTextBox, "Changed server password successfully.\n");
            }
            catch (Exception exception)
            {
                updateRichTextBox(logTextBox, "ERROR: " + exception.Message + ", could not change the password\n");
            }
        }
        private void button_show_online_Click(object sender, EventArgs e)
        {
            clients.CheckAndUpdateAllSocket();
            string result = String.Join(", ", clients.NameListOfActiveClients());
            updateRichTextBox(logTextBox, "Online client(s): " + result + "\n");
        }
        private void check_detailed_CheckedChanged(object sender, EventArgs e)
        {
            detailed_mode = !detailed_mode;
        }
    }
}
