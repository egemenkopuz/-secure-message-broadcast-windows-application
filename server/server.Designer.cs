namespace SecureMessageBroadcastApplicationServer
{
    partial class server
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
            this.logTextBox = new System.Windows.Forms.RichTextBox();
            this.messageTextBox = new System.Windows.Forms.RichTextBox();
            this.label_port = new System.Windows.Forms.Label();
            this.input_port = new System.Windows.Forms.TextBox();
            this.label_password = new System.Windows.Forms.Label();
            this.input_password = new System.Windows.Forms.TextBox();
            this.button_start = new System.Windows.Forms.Button();
            this.button_show_online = new System.Windows.Forms.Button();
            this.button_terminate = new System.Windows.Forms.Button();
            this.button_change_password = new System.Windows.Forms.Button();
            this.check_detailed = new System.Windows.Forms.CheckBox();
            this.SuspendLayout();
            // 
            // logTextBox
            // 
            this.logTextBox.Location = new System.Drawing.Point(12, 12);
            this.logTextBox.Name = "logTextBox";
            this.logTextBox.ReadOnly = true;
            this.logTextBox.Size = new System.Drawing.Size(664, 767);
            this.logTextBox.TabIndex = 0;
            this.logTextBox.TabStop = false;
            this.logTextBox.Text = "";
            // 
            // messageTextBox
            // 
            this.messageTextBox.Location = new System.Drawing.Point(682, 12);
            this.messageTextBox.Name = "messageTextBox";
            this.messageTextBox.ReadOnly = true;
            this.messageTextBox.Size = new System.Drawing.Size(312, 767);
            this.messageTextBox.TabIndex = 0;
            this.messageTextBox.TabStop = false;
            this.messageTextBox.Text = "";
            // 
            // label_port
            // 
            this.label_port.AutoSize = true;
            this.label_port.Location = new System.Drawing.Point(12, 793);
            this.label_port.Name = "label_port";
            this.label_port.Size = new System.Drawing.Size(38, 17);
            this.label_port.TabIndex = 2;
            this.label_port.Text = "Port:";
            // 
            // input_port
            // 
            this.input_port.Location = new System.Drawing.Point(56, 788);
            this.input_port.Name = "input_port";
            this.input_port.Size = new System.Drawing.Size(100, 22);
            this.input_port.TabIndex = 1;
            // 
            // label_password
            // 
            this.label_password.AutoSize = true;
            this.label_password.Location = new System.Drawing.Point(166, 793);
            this.label_password.Name = "label_password";
            this.label_password.Size = new System.Drawing.Size(73, 17);
            this.label_password.TabIndex = 4;
            this.label_password.Text = "Password:";
            // 
            // input_password
            // 
            this.input_password.Location = new System.Drawing.Point(245, 788);
            this.input_password.Name = "input_password";
            this.input_password.Size = new System.Drawing.Size(100, 22);
            this.input_password.TabIndex = 2;
            // 
            // button_start
            // 
            this.button_start.Location = new System.Drawing.Point(363, 787);
            this.button_start.Name = "button_start";
            this.button_start.Size = new System.Drawing.Size(100, 25);
            this.button_start.TabIndex = 3;
            this.button_start.Text = "Start";
            this.button_start.UseVisualStyleBackColor = true;
            this.button_start.Click += new System.EventHandler(this.button_start_Click);
            // 
            // button_show_online
            // 
            this.button_show_online.Location = new System.Drawing.Point(843, 785);
            this.button_show_online.Name = "button_show_online";
            this.button_show_online.Size = new System.Drawing.Size(150, 27);
            this.button_show_online.TabIndex = 6;
            this.button_show_online.Text = "Show Online Clients";
            this.button_show_online.UseVisualStyleBackColor = true;
            this.button_show_online.Click += new System.EventHandler(this.button_show_online_Click);
            // 
            // button_terminate
            // 
            this.button_terminate.Location = new System.Drawing.Point(469, 787);
            this.button_terminate.Name = "button_terminate";
            this.button_terminate.Size = new System.Drawing.Size(100, 25);
            this.button_terminate.TabIndex = 4;
            this.button_terminate.Text = "Terminate";
            this.button_terminate.UseVisualStyleBackColor = true;
            this.button_terminate.Click += new System.EventHandler(this.button_terminate_Click);
            // 
            // button_change_password
            // 
            this.button_change_password.Location = new System.Drawing.Point(687, 785);
            this.button_change_password.Name = "button_change_password";
            this.button_change_password.Size = new System.Drawing.Size(150, 27);
            this.button_change_password.TabIndex = 5;
            this.button_change_password.Text = "Change Password";
            this.button_change_password.UseVisualStyleBackColor = true;
            this.button_change_password.Click += new System.EventHandler(this.button_change_password_Click);
            // 
            // check_detailed
            // 
            this.check_detailed.AutoSize = true;
            this.check_detailed.Location = new System.Drawing.Point(584, 789);
            this.check_detailed.Name = "check_detailed";
            this.check_detailed.Size = new System.Drawing.Size(82, 21);
            this.check_detailed.TabIndex = 7;
            this.check_detailed.TabStop = false;
            this.check_detailed.Text = "Detailed";
            this.check_detailed.UseVisualStyleBackColor = true;
            this.check_detailed.CheckedChanged += new System.EventHandler(this.check_detailed_CheckedChanged);
            // 
            // server
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1006, 822);
            this.Controls.Add(this.check_detailed);
            this.Controls.Add(this.button_change_password);
            this.Controls.Add(this.button_terminate);
            this.Controls.Add(this.button_show_online);
            this.Controls.Add(this.button_start);
            this.Controls.Add(this.input_password);
            this.Controls.Add(this.label_password);
            this.Controls.Add(this.input_port);
            this.Controls.Add(this.label_port);
            this.Controls.Add(this.messageTextBox);
            this.Controls.Add(this.logTextBox);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "server";
            this.ShowIcon = false;
            this.Text = "Secure Message Broadcast Application Server";
            this.Load += new System.EventHandler(this.server_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.RichTextBox logTextBox;
        private System.Windows.Forms.RichTextBox messageTextBox;
        private System.Windows.Forms.Label label_port;
        private System.Windows.Forms.TextBox input_port;
        private System.Windows.Forms.Label label_password;
        private System.Windows.Forms.TextBox input_password;
        private System.Windows.Forms.Button button_start;
        private System.Windows.Forms.Button button_show_online;
        private System.Windows.Forms.Button button_terminate;
        private System.Windows.Forms.Button button_change_password;
        private System.Windows.Forms.CheckBox check_detailed;
    }
}

