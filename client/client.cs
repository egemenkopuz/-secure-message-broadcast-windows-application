using System;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.Threading;
using System.Collections.Generic;
using System.Linq;

namespace SecureMessageBroadcastApplication
{
    public struct Constants
    {
        public const string PU_ENC_DEC_PATH = "\\server_enc_dec_pub.txt";
        public const string PU_SIG_VER_PATH = "\\server_signing_verification_pub.txt";
    }
    public struct Packet
    {
        private byte[] size;
        private byte[] command;
        private byte[] content;
        private byte[] fullPacket;
        public Packet(byte[] i, string cmd)
        {
            command = Encoding.Default.GetBytes(cmd);
            content = i;
            size = Encoding.Default.GetBytes((7 + content.Length).ToString("D5"));
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
    public struct Session
    {
        private byte[] sessionKey;
        private byte[] messageKey;
        public Session(byte[] s, byte[] m)
        {
            sessionKey = s;
            messageKey = m;
        }
        public void Set(byte[] s, byte[] m)
        {
            sessionKey = s;
            messageKey = m;
        }
        public byte[] GetSessionKey() { return sessionKey; }
        public byte[] GetMessageKey() { return messageKey; }
    }
    public partial class client : Form
    {
        private byte[] publicRSA1;    // stored public RSA key for encryption and decryption
        private byte[] publicRSA2;    // stored public RSA key for signing and verification

        private Socket clientSocket;
        private Session session = new Session(null, null);    // holds session key, message key and challange per session
        private RNGCryptoServiceProvider rngCsp = new RNGCryptoServiceProvider();    // secure random number generator

        private bool connected = false;         // boolean to determine whether connection between client and server is maintained
        private bool terminating = false;       // if manual termination is started
        private bool detailed_mode = false;     // to show details such as keys 

        public client()
        {
            try
            {
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_ENC_DEC_PATH))
                {
                    publicRSA1 = Encoding.Default.GetBytes(fileReader.ReadLine());
                }
                using (System.IO.StreamReader fileReader =
                new System.IO.StreamReader(System.IO.Directory.GetCurrentDirectory() + Constants.PU_SIG_VER_PATH))
                {
                    publicRSA2 = Encoding.Default.GetBytes(fileReader.ReadLine());
                }
            }
            catch { MessageBox.Show("Could not find " + Constants.PU_ENC_DEC_PATH + " or " + Constants.PU_SIG_VER_PATH); Environment.Exit(0); }

            Control.CheckForIllegalCrossThreadCalls = false;
            this.FormClosing += new FormClosingEventHandler(client_FormClosing);

            InitializeComponent();

            button_signup.Enabled = false;
            button_login.Enabled = false;
            button_connect.Visible = true;
            input_username.Enabled = false;
            input_password.Enabled = false;
            logTextBox.ReadOnly = true;
            messageTextBox.ReadOnly = true;
            button_send.Enabled = false;
            button_disconnect.Visible = false;

            tooltip_password.SetToolTip(input_password, "Password length must be minimum 8 and maximum 20,\nshould include latin character(s) and number(s).");
            tooltip_username.SetToolTip(input_username, "Username length must be minimum 4 and maximum 12,\nonly latin character(s) and number(s) are allowed,\ninital character cannot be a number.");
        }
        private void client_FormClosing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            terminating = true;
            connected = false;

            try { clientSocket.Send(new Packet(Encoding.Default.GetBytes("DISCONNECT"), "00").Full()); } catch { }

            try
            {
                clientSocket.Close();
                clientSocket.Shutdown(SocketShutdown.Both);
                clientSocket.Dispose();
            }
            catch { }
            Environment.Exit(0);
        }
        private void listenServer(object sender, EventArgs e)
        {
            try
            {
                modifyUiObjects(false, true, false, false, true, false, false, false, false, false);
                updateRichTextBox(logTextBox, "You are autharized, you can now chat\n");

                while (connected && !terminating)
                {
                    byte[] packet = derivedContentViaRecv(clientSocket);
                    string cmd = Packet.GetCommand(packet);

                    if (cmd == "00")    // SERVER SHUTDOWN
                    {
                        throw new SocketException();
                    }
                    else if (cmd == "31")   // MESSAGE FROM OTHER CLIENTS
                    {
                        byte[] content = Packet.GetContent(packet);                 // whole packet includes encrypted message and hmac
                        byte[] encrypted = new byte[content.Length - 32 - 16];      // encryption of (sender//message)
                        byte[] hmac = new byte[32];                                 // 32 bytes long hmac to verify
                        byte[] randomIV = new byte[16];                             // random iv created by server

                        Array.Copy(content, 0, encrypted, 0, encrypted.Length);
                        Array.Copy(content, encrypted.Length, hmac, 0, 32);
                        Array.Copy(content, encrypted.Length + hmac.Length, randomIV, 0, 16);

                        byte[] decrypted = decryptWithAES128(Encoding.Default.GetString(encrypted), session.GetSessionKey(), randomIV);   // (sender//message)
                        byte[] check = applyHMACwithSHA256(Encoding.Default.GetString(encrypted), session.GetMessageKey());    // HMAC of encrypted message

                        if (Encoding.Default.GetString(hmac) == Encoding.Default.GetString(check))   // verification
                        {
                            // if verified
                            if (detailed_mode)
                            {
                                updateRichTextBox(logTextBox, "Random IV: " + generateHexStringFromByteArray(randomIV) + "\n");
                                updateRichTextBox(logTextBox, "HMAC of message: " + generateHexStringFromByteArray(hmac) + "\n");
                            }
                            string full = Encoding.Default.GetString(decrypted);
                            string messageSender = full.Substring(0, full.IndexOf('\t'));
                            string message = full.Substring(full.IndexOf('\t') + 1, full.Length - messageSender.Length - 1);
                            updateRichTextBox(logTextBox, "@" + messageSender + ": " + message + "\n");
                        }
                        else  // if not verified discarded
                        {
                            throw new Exception("Verifying incoming message has failed");
                        }
                    }
                    else    // INVALID PACKET
                    {
                        throw new Exception("Anormal packet has arrived");
                    }
                }
            }
            catch (SocketException)
            {
                if (connected && !terminating) button_disconnect_Click(sender, e);
                updateRichTextBox(logTextBox, "Connection is lost\n");
            }
            catch (Exception exception)
            {
                if (connected && !terminating) button_disconnect_Click(sender, e);
                updateRichTextBox(logTextBox, "Forced disconnection due to: " + exception.Message + "\n");
            }
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Crypto Functions ///////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////
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
        static byte[] encryptWithRSA(string input, int algoLength, string xmlStringKey)
        {
            byte[] byteInput = Encoding.Default.GetBytes(input);
            RSACryptoServiceProvider rsaObject = new RSACryptoServiceProvider(algoLength);
            rsaObject.FromXmlString(xmlStringKey);
            byte[] result = null;
            try
            {
                result = rsaObject.Encrypt(byteInput, true);
            }
            catch
            {
                throw new Exception("RSA Encryption failed");
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
            Action append = () => textBox.AppendText("(" + DateTime.Now.ToString("HH:mm:ss") + ") " + msg);
            if (textBox.InvokeRequired)
                textBox.BeginInvoke(append);
            else
                append();
        }
        private byte[] derivedContentViaRecv(Socket s)
        {
            byte[] sizePart = new byte[5];                                                              // will hold the size of whole packet
            s.Receive(sizePart);                                                                        // receives the first 5 bytes which determines the size of 
            byte[] remaining = new byte[Convert.ToInt32(Encoding.Default.GetString(sizePart)) - 5];     // will hold the remaining where size will be sizePart - 5
            s.Receive(remaining);                                                                       // receives the remaining whole content 
            return remaining;
        }
        private bool isUsernameValid(string s)
        {
            if (s == null || s == "") return false;

            List<char> username = s.ToList();

            if (username[0] >= '0' && username[0] <= '9') return false;
            if (!(username.Count >= 4 && username.Count <= 12)) return false;

            foreach (char c in username)
            {
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) return false;
            }
            return true;
        }
        private bool isPasswordValid(string s)
        {
            if (s == null || s == "") return false;

            List<char> password = s.ToList();

            if (!(password.Count >= 8 && password.Count <= 20)) return false;

            bool spottedUppercase = false;
            bool spottedNumber = false;

            foreach (char c in password)
            {
                if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z'))) return false;
                if (!spottedUppercase && c >= 'A' && c <= 'Z') spottedUppercase = true;
                if (!spottedNumber && c >= '0' && c <= '9') spottedNumber = true;
            }
            if (spottedNumber && spottedUppercase) return true;
            else return false;
        }
        ///////////////////////////////////////////////////////////////////////////////
        // Form Functions /////////////////////////////////////////////////////////////
        ///////////////////////////////////////////////////////////////////////////////
        private void modifyUiObjects(bool buttonconnect, bool buttondisconnect, bool buttonsignup, bool buttonlogin, bool buttonsend, bool messagebox, bool address, bool port, bool username, bool password)
        {
            // Modifies windows form objects to save coding space and make codes clearer
            try
            {
                input_address.Invoke(new Action(() => input_address.Enabled = address));
                input_port.Invoke(new Action(() => input_port.Enabled = port));
                input_username.Invoke(new Action(() => input_username.Enabled = username));
                input_password.Invoke(new Action(() => input_password.Enabled = password));
                button_signup.Invoke(new Action(() => button_signup.Enabled = buttonsignup));
                button_login.Invoke(new Action(() => button_login.Enabled = buttonlogin));
                button_connect.Invoke(new Action(() => button_connect.Visible = buttonconnect));
                messageTextBox.Invoke(new Action(() => messageTextBox.ReadOnly = messagebox));
                button_disconnect.Invoke(new Action(() => button_disconnect.Visible = buttondisconnect));
                button_send.Invoke(new Action(() => button_send.Enabled = buttonsend));
            }
            catch { }
        }
        private void button_signup_Click(object sender, EventArgs e)
        {
            try
            {
                modifyUiObjects(false, true, false, false, false, true, false, false, false, false);

                if (detailed_mode) updateRichTextBox(logTextBox, "Initiated enrollment.\n");

                if (!(isUsernameValid(input_username.Text) && isPasswordValid(input_password.Text)))
                    throw new Exception("Invalid username or password.");

                byte[] hashedPassword = hashWithSHA256(input_password.Text);            // hashes password for security
                input_password.Text = "";                                               // password cannot be stored, deleted from memory

                // concatenating significant half of the hashedPassword with username string then encryts it
                byte[] hashedConUser = new byte[(hashedPassword.Length / 2) + input_username.Text.Length];    // 16 from most significant half
                Array.Copy(hashedPassword, 16, hashedConUser, 0, 16);
                Array.Copy(Encoding.Default.GetBytes(input_username.Text), 0, hashedConUser, 16, input_username.Text.Length);

                if (detailed_mode) updateRichTextBox(logTextBox, "Hash of password: " + generateHexStringFromByteArray(hashedPassword) + "\n");

                try
                {
                    byte[] encryptedHashedConUser = encryptWithRSA(Encoding.Default.GetString(hashedConUser), 3072, Encoding.Default.GetString(publicRSA1));
                    clientSocket.Send(new Packet(encryptedHashedConUser, "10").Full());   // sends command "10" with encrypted message to start enrollment
                    if (detailed_mode) updateRichTextBox(logTextBox, "Sent encrypted enrollment packet:\n" + generateHexStringFromByteArray(encryptedHashedConUser) + "\n");
                }
                catch { throw new Exception("Encryption has failed, reason might be invalid key."); }

                byte[] response1 = derivedContentViaRecv(clientSocket); // message
                string cmd1 = Packet.GetCommand(response1);
                if (cmd1 == "00") throw new SocketException();
                else if (cmd1 == "99") throw new Exception("Enrollment has been rejected.");

                byte[] response2 = derivedContentViaRecv(clientSocket); // signature of message
                string cmd2 = Packet.GetCommand(response2);
                if (cmd2 == "00") throw new SocketException();
                else if (cmd2 == "99") throw new Exception("Enrollment has been rejected.");

                if (detailed_mode)
                {
                    updateRichTextBox(logTextBox, "Received enrollment response: " + generateHexStringFromByteArray(response1) + "\n");
                    updateRichTextBox(logTextBox, "Received signature of response: " + generateHexStringFromByteArray(response2) + "\n");
                }

                if (cmd1 == "18" && cmd2 == "19" && verifyWithRSA(Encoding.Default.GetString(Packet.GetContent(response1)), 3072, Encoding.Default.GetString(publicRSA2), Packet.GetContent(response2)))
                {
                    if (Encoding.Default.GetString(Packet.GetContent(response1)) == "ENROLLMENT_SUCCESS")
                    {
                        modifyUiObjects(false, true, true, true, false, true, false, false, true, true);
                        updateRichTextBox(logTextBox, "Enrollment has been completed.\n");
                    }
                    else throw new Exception("Enrollment has been rejected.");
                }
                else { updateRichTextBox(logTextBox, "Verifying has failed, reason might be invalid key, forcing disconnection.\n"); throw new SocketException(); }
            }
            catch (SocketException)
            {
                if (connected && !terminating) button_disconnect_Click(sender, e);
                updateRichTextBox(logTextBox, "Connection is lost\n");
            }
            catch (Exception exception)
            {
                modifyUiObjects(false, true, true, true, false, true, false, false, true, true);
                updateRichTextBox(logTextBox, "ERROR: " + exception.Message + "\n");
            }
        }
        private void button_login_Click(object sender, EventArgs e)
        {
            try
            {
                modifyUiObjects(false, false, false, false, false, true, false, false, false, false);

                if (detailed_mode) updateRichTextBox(logTextBox, "Initiated authentication.\n");

                if (input_username.Text == "" || input_password.Text == "") throw new Exception("Username or password cannot be empty.");

                byte[] hashedPassword = hashWithSHA256(input_password.Text);    // hashes user's password
                input_password.Text = "";                                       // password cannot be stored

                if (detailed_mode) updateRichTextBox(logTextBox, "Hash of password: " + generateHexStringFromByteArray(hashedPassword) + "\n");

                clientSocket.Send(new Packet(Encoding.Default.GetBytes(input_username.Text), "20").Full());     // sends server "20" authentication request along with username

                byte[] response = derivedContentViaRecv(clientSocket);  // gets the server response
                if (Packet.GetCommand(response) == "00") throw new SocketException();    // manual shutdown by server
                else if (Packet.GetCommand(response) == "99") throw new Exception("Authentication has been rejected");   // failure on server's side, key can be problematic
                else if (Packet.GetCommand(response) == "21")
                {
                    byte[] significantHashedPassword = new byte[16];    // takes significant part of hash (last 16 bytes)
                    Array.Copy(hashedPassword, 16, significantHashedPassword, 0, 16);

                    byte[] hmac = applyHMACwithSHA256(Encoding.Default.GetString(Packet.GetContent(response)), significantHashedPassword);  // applied HMAC to challange with significant part of hash 
                    
                    clientSocket.Send(new Packet(hmac, "22").Full());   // sends HMAC

                    if (detailed_mode) updateRichTextBox(logTextBox, "Sent HMAC of challange: " + generateHexStringFromByteArray(hmac) + "\n");

                    byte[] response1 = derivedContentViaRecv(clientSocket); // authentication message
                    string cmd1 = Packet.GetCommand(response1);
                    if (cmd1 == "00") throw new SocketException(); 
                    else if (cmd1 == "99") throw new Exception("Authentication has been rejected");

                    byte[] response2 = derivedContentViaRecv(clientSocket); // signature of authentication message
                    string cmd2 = Packet.GetCommand(response2);
                    if (cmd2 == "00") throw new SocketException();
                    else if (cmd2 == "99") throw new Exception("Authentication has been rejected");

                    else if (cmd1 == "28" && cmd2 == "29" && verifyWithRSA(Encoding.Default.GetString(Packet.GetContent(response1)), 3072, Encoding.Default.GetString(publicRSA2), Packet.GetContent(response2)))
                    {
                        if (detailed_mode)
                        {
                            updateRichTextBox(logTextBox, "Received authentication response: " + generateHexStringFromByteArray(response1) + "\n");
                            updateRichTextBox(logTextBox, "Received signature of response: " + generateHexStringFromByteArray(response2) + "\n");
                        }

                        byte[] result = new byte[12];
                        Array.Copy(Packet.GetContent(response1), 0, result, 0, 12);
                        // if verified process continoues to establish stable connection between server
                        if (Encoding.Default.GetString(result) == "AUTH_SUCCESS")
                        {
                            byte[] encryptedSessionKey = new byte[32];  // encrypted session key sent by server, will be used for encryption
                            byte[] encryptedMessageKey = new byte[32];  // encrypted message key sent by server, will be used for hmac

                            Array.Copy(response1, 14, encryptedSessionKey, 0, 32);
                            Array.Copy(response1, 46, encryptedMessageKey, 0, 32);

                            byte[] sessionKey = decryptWithAES128(Encoding.Default.GetString(encryptedSessionKey), significantHashedPassword, Packet.GetContent(response));
                            byte[] messageKey = decryptWithAES128(Encoding.Default.GetString(encryptedMessageKey), significantHashedPassword, Packet.GetContent(response));

                            if (detailed_mode)
                            {
                                updateRichTextBox(logTextBox, "Received session key: " + generateHexStringFromByteArray(sessionKey) + "\n");
                                updateRichTextBox(logTextBox, "Received message key: " + generateHexStringFromByteArray(messageKey) + "\n");
                            }
                            session.Set(sessionKey, messageKey);

                            Thread chattingThread = new Thread(() => listenServer(sender, e));
                            chattingThread.Start();

                        }
                        else throw new Exception("Authentication has been rejected");
                    }
                    else { updateRichTextBox(logTextBox, "Verifying has failed, reason might be invalid key, forcing disconnection.\n"); throw new SocketException(); }
                }
                else throw new Exception("Authentication has failed");
            }
            catch (SocketException)
            {
                if (connected && !terminating) button_disconnect_Click(sender, e);
                updateRichTextBox(logTextBox, "Connection is lost\n");
            }
            catch (Exception exception)
            {
                modifyUiObjects(false, true, true, true, false, true, false, false, true, true);
                updateRichTextBox(logTextBox, "ERROR: " + exception.Message + "\n");
            }
        }
        private void button_disconnect_Click(object sender, EventArgs e)
        {
            try
            {
                connected = false;

                try { clientSocket.Send(new Packet(Encoding.Default.GetBytes("DISCONNECT"), "00").Full()); } catch { }

                try
                {
                    clientSocket.Close();
                    clientSocket.Shutdown(SocketShutdown.Both);
                    clientSocket.Dispose();
                }
                catch { }
                session.Set(null, null);
            }
            catch { }
            modifyUiObjects(true, false, false, false, false, true, true, true, false, false);
        }
        private void button_send_Click(object sender, EventArgs e)
        {
            try
            {
                if (messageTextBox.Text == "") throw new Exception("You cannot send empty message");
                else
                {
                    if (session.GetSessionKey() == null || session.GetMessageKey() == null) throw new Exception("There is no session");

                    byte[] randomIV = new byte[16];
                    rngCsp.GetBytes(randomIV);

                    byte[] encryptedMessage = encryptWithAES128(messageTextBox.Text, session.GetSessionKey(), randomIV);
                    byte[] HMACofEncryptedMessage = applyHMACwithSHA256(Encoding.Default.GetString(encryptedMessage), session.GetMessageKey());

                    clientSocket.Send(new Packet(Encoding.Default.GetBytes(Encoding.Default.GetString(encryptedMessage) + Encoding.Default.GetString(HMACofEncryptedMessage) + Encoding.Default.GetString(randomIV)), "30").Full());

                    if (detailed_mode) updateRichTextBox(logTextBox, "Sent HMAC of message: " + generateHexStringFromByteArray(HMACofEncryptedMessage) + "\n");

                    updateRichTextBox(logTextBox, "You: " + messageTextBox.Text + "\n");
                    messageTextBox.Text = "";
                }
            }
            catch (Exception exception)
            {
                updateRichTextBox(logTextBox, "ERROR: " + exception.Message + "\n");
            }
        }
        private void button_connect_Click(object sender, EventArgs e)
        {
            try
            {
                modifyUiObjects(false, false, false, false, false, true, false, false, false, false);
                if (input_address.Text == "" || input_port.Text == "")
                    throw new Exception("There must be no empty inputs");

                clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);     // refreshes socket so that client can connect again    
                clientSocket.Connect(input_address.Text, int.Parse(input_port.Text));
                connected = true;

                modifyUiObjects(false, true, true, true, false, true, false, false, true, true);
                updateRichTextBox(logTextBox, "Connected to " + input_address.Text + "/" + input_port.Text + "\n");

            }
            catch (Exception exception)
            {
                connected = false;
                modifyUiObjects(true, false, false, false, false, true, true, true, false, false);
                updateRichTextBox(logTextBox, "ERROR: " + exception.Message + "\n");
            }
        }
        private void check_detailed_CheckedChanged(object sender, EventArgs e)
        {
            detailed_mode = !detailed_mode;
        }
    }
}
