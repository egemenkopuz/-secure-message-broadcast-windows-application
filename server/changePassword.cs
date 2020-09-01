using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SecureMessageBroadcastApplicationServer
{
    public partial class changePassword : Form
    {
        private byte[] changed = null;
        private byte[] ps = null;
        public changePassword(byte[] password)
        {
            InitializeComponent();
            ps = password;
        }
        public static byte[] executeChangePassword(byte[] password)
        {
            changePassword form = new changePassword(password);
            form.ShowDialog();
            return form.changed;
        }
        private void button_apply_Click(object sender, EventArgs e)
        {
            if (input_old.Text == "" || input_new.Text == "") MessageBox.Show("No empty inputs!");
            else
            {
                if (generateHexStringFromByteArray(hashWithSHA256(input_old.Text)) != generateHexStringFromByteArray(ps)) MessageBox.Show("Wrong old password");
                else
                {
                    changed = hashWithSHA256(input_new.Text);
                    Close();
                }
            }
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
        static string generateHexStringFromByteArray(byte[] input)
        {
            string hexString = BitConverter.ToString(input);
            return hexString.Replace("-", "");
        }
    }
}
