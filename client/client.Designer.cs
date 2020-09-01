namespace SecureMessageBroadcastApplication
{
    partial class client
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.button_login = new System.Windows.Forms.Button();
            this.input_password = new System.Windows.Forms.TextBox();
            this.label_password = new System.Windows.Forms.Label();
            this.button_send = new System.Windows.Forms.Button();
            this.messageTextBox = new System.Windows.Forms.RichTextBox();
            this.button_disconnect = new System.Windows.Forms.Button();
            this.button_signup = new System.Windows.Forms.Button();
            this.input_username = new System.Windows.Forms.TextBox();
            this.label_username = new System.Windows.Forms.Label();
            this.input_port = new System.Windows.Forms.TextBox();
            this.label_port = new System.Windows.Forms.Label();
            this.input_address = new System.Windows.Forms.TextBox();
            this.label_address = new System.Windows.Forms.Label();
            this.logTextBox = new System.Windows.Forms.RichTextBox();
            this.button_connect = new System.Windows.Forms.Button();
            this.tooltip_username = new System.Windows.Forms.ToolTip(this.components);
            this.tooltip_password = new System.Windows.Forms.ToolTip(this.components);
            this.check_detailed = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // button_login
            // 
            this.button_login.Location = new System.Drawing.Point(356, 39);
            this.button_login.Margin = new System.Windows.Forms.Padding(2);
            this.button_login.Name = "button_login";
            this.button_login.Size = new System.Drawing.Size(75, 31);
            this.button_login.TabIndex = 6;
            this.button_login.Text = "Log in";
            this.button_login.UseVisualStyleBackColor = true;
            this.button_login.Click += new System.EventHandler(this.button_login_Click);
            // 
            // input_password
            // 
            this.input_password.Location = new System.Drawing.Point(242, 26);
            this.input_password.Margin = new System.Windows.Forms.Padding(2);
            this.input_password.Name = "input_password";
            this.input_password.PasswordChar = '*';
            this.input_password.Size = new System.Drawing.Size(76, 20);
            this.input_password.TabIndex = 4;
            // 
            // label_password
            // 
            this.label_password.AutoSize = true;
            this.label_password.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.label_password.Location = new System.Drawing.Point(167, 26);
            this.label_password.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label_password.Name = "label_password";
            this.label_password.Size = new System.Drawing.Size(64, 15);
            this.label_password.TabIndex = 26;
            this.label_password.Text = "Password:";
            // 
            // button_send
            // 
            this.button_send.Location = new System.Drawing.Point(359, 109);
            this.button_send.Margin = new System.Windows.Forms.Padding(2);
            this.button_send.Name = "button_send";
            this.button_send.Size = new System.Drawing.Size(71, 38);
            this.button_send.TabIndex = 8;
            this.button_send.Text = "Send";
            this.button_send.UseVisualStyleBackColor = true;
            this.button_send.Click += new System.EventHandler(this.button_send_Click);
            // 
            // messageTextBox
            // 
            this.messageTextBox.Location = new System.Drawing.Point(8, 109);
            this.messageTextBox.Margin = new System.Windows.Forms.Padding(2);
            this.messageTextBox.Name = "messageTextBox";
            this.messageTextBox.ReadOnly = true;
            this.messageTextBox.Size = new System.Drawing.Size(348, 39);
            this.messageTextBox.TabIndex = 24;
            this.messageTextBox.TabStop = false;
            this.messageTextBox.Text = "";
            // 
            // button_disconnect
            // 
            this.button_disconnect.Location = new System.Drawing.Point(9, 73);
            this.button_disconnect.Margin = new System.Windows.Forms.Padding(2);
            this.button_disconnect.Name = "button_disconnect";
            this.button_disconnect.Size = new System.Drawing.Size(75, 31);
            this.button_disconnect.TabIndex = 7;
            this.button_disconnect.Text = "Disconnect";
            this.button_disconnect.UseVisualStyleBackColor = true;
            this.button_disconnect.Click += new System.EventHandler(this.button_disconnect_Click);
            // 
            // button_signup
            // 
            this.button_signup.Location = new System.Drawing.Point(356, 3);
            this.button_signup.Margin = new System.Windows.Forms.Padding(2);
            this.button_signup.Name = "button_signup";
            this.button_signup.Size = new System.Drawing.Size(75, 31);
            this.button_signup.TabIndex = 5;
            this.button_signup.Text = "Sign up";
            this.button_signup.UseVisualStyleBackColor = true;
            this.button_signup.Click += new System.EventHandler(this.button_signup_Click);
            // 
            // input_username
            // 
            this.input_username.Location = new System.Drawing.Point(242, 3);
            this.input_username.Margin = new System.Windows.Forms.Padding(2);
            this.input_username.Name = "input_username";
            this.input_username.Size = new System.Drawing.Size(76, 20);
            this.input_username.TabIndex = 3;
            // 
            // label_username
            // 
            this.label_username.AutoSize = true;
            this.label_username.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.label_username.Location = new System.Drawing.Point(166, 4);
            this.label_username.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label_username.Name = "label_username";
            this.label_username.Size = new System.Drawing.Size(68, 15);
            this.label_username.TabIndex = 20;
            this.label_username.Text = "Username:";
            // 
            // input_port
            // 
            this.input_port.Location = new System.Drawing.Point(81, 26);
            this.input_port.Margin = new System.Windows.Forms.Padding(2);
            this.input_port.Name = "input_port";
            this.input_port.Size = new System.Drawing.Size(76, 20);
            this.input_port.TabIndex = 2;
            // 
            // label_port
            // 
            this.label_port.AutoSize = true;
            this.label_port.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.label_port.Location = new System.Drawing.Point(6, 27);
            this.label_port.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label_port.Name = "label_port";
            this.label_port.Size = new System.Drawing.Size(32, 15);
            this.label_port.TabIndex = 18;
            this.label_port.Text = "Port:";
            // 
            // input_address
            // 
            this.input_address.Location = new System.Drawing.Point(81, 3);
            this.input_address.Margin = new System.Windows.Forms.Padding(2);
            this.input_address.Name = "input_address";
            this.input_address.Size = new System.Drawing.Size(76, 20);
            this.input_address.TabIndex = 1;
            // 
            // label_address
            // 
            this.label_address.AutoSize = true;
            this.label_address.Font = new System.Drawing.Font("Microsoft Sans Serif", 9F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(162)));
            this.label_address.Location = new System.Drawing.Point(6, 4);
            this.label_address.Margin = new System.Windows.Forms.Padding(2, 0, 2, 0);
            this.label_address.Name = "label_address";
            this.label_address.Size = new System.Drawing.Size(54, 15);
            this.label_address.TabIndex = 16;
            this.label_address.Text = "Address:";
            // 
            // logTextBox
            // 
            this.logTextBox.Location = new System.Drawing.Point(9, 152);
            this.logTextBox.Margin = new System.Windows.Forms.Padding(2);
            this.logTextBox.Name = "logTextBox";
            this.logTextBox.ReadOnly = true;
            this.logTextBox.Size = new System.Drawing.Size(422, 377);
            this.logTextBox.TabIndex = 15;
            this.logTextBox.TabStop = false;
            this.logTextBox.Text = "";
            // 
            // button_connect
            // 
            this.button_connect.Location = new System.Drawing.Point(8, 73);
            this.button_connect.Margin = new System.Windows.Forms.Padding(2);
            this.button_connect.Name = "button_connect";
            this.button_connect.Size = new System.Drawing.Size(75, 31);
            this.button_connect.TabIndex = 27;
            this.button_connect.Text = "Connect";
            this.button_connect.UseVisualStyleBackColor = true;
            this.button_connect.Click += new System.EventHandler(this.button_connect_Click);
            // 
            // tooltip_username
            // 
            this.tooltip_username.ToolTipIcon = System.Windows.Forms.ToolTipIcon.Warning;
            // 
            // tooltip_password
            // 
            this.tooltip_password.Tag = "";
            this.tooltip_password.ToolTipIcon = System.Windows.Forms.ToolTipIcon.Warning;
            // 
            // check_detailed
            // 
            this.check_detailed.AutoSize = true;
            this.check_detailed.Location = new System.Drawing.Point(359, 81);
            this.check_detailed.Margin = new System.Windows.Forms.Padding(2);
            this.check_detailed.Name = "check_detailed";
            this.check_detailed.Size = new System.Drawing.Size(65, 17);
            this.check_detailed.TabIndex = 28;
            this.check_detailed.TabStop = false;
            this.check_detailed.Text = "Detailed";
            this.check_detailed.UseVisualStyleBackColor = true;
            this.check_detailed.CheckedChanged += new System.EventHandler(this.check_detailed_CheckedChanged);
            // 
            // client
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(442, 538);
            this.Controls.Add(this.check_detailed);
            this.Controls.Add(this.button_connect);
            this.Controls.Add(this.button_login);
            this.Controls.Add(this.input_password);
            this.Controls.Add(this.label_password);
            this.Controls.Add(this.button_send);
            this.Controls.Add(this.messageTextBox);
            this.Controls.Add(this.button_disconnect);
            this.Controls.Add(this.button_signup);
            this.Controls.Add(this.input_username);
            this.Controls.Add(this.label_username);
            this.Controls.Add(this.input_port);
            this.Controls.Add(this.label_port);
            this.Controls.Add(this.input_address);
            this.Controls.Add(this.label_address);
            this.Controls.Add(this.logTextBox);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Margin = new System.Windows.Forms.Padding(2);
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "client";
            this.ShowIcon = false;
            this.Text = "Secure Message Broadcast Application";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button button_login;
        private System.Windows.Forms.TextBox input_password;
        private System.Windows.Forms.Label label_password;
        private System.Windows.Forms.Button button_send;
        private System.Windows.Forms.RichTextBox messageTextBox;
        private System.Windows.Forms.Button button_disconnect;
        private System.Windows.Forms.Button button_signup;
        private System.Windows.Forms.TextBox input_username;
        private System.Windows.Forms.Label label_username;
        private System.Windows.Forms.TextBox input_port;
        private System.Windows.Forms.Label label_port;
        private System.Windows.Forms.TextBox input_address;
        private System.Windows.Forms.Label label_address;
        private System.Windows.Forms.RichTextBox logTextBox;
        private System.Windows.Forms.Button button_connect;
        private System.Windows.Forms.ToolTip tooltip_username;
        private System.Windows.Forms.ToolTip tooltip_password;
        private System.Windows.Forms.CheckBox check_detailed;
    }
}

