namespace SecureMessageBroadcastApplicationServer
{
    partial class changePassword
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
            this.label_old = new System.Windows.Forms.Label();
            this.label_new1 = new System.Windows.Forms.Label();
            this.input_old = new System.Windows.Forms.TextBox();
            this.input_new = new System.Windows.Forms.TextBox();
            this.button_apply = new System.Windows.Forms.Button();
            this.SuspendLayout();
            // 
            // label_old
            // 
            this.label_old.AutoSize = true;
            this.label_old.Location = new System.Drawing.Point(16, 9);
            this.label_old.Name = "label_old";
            this.label_old.Size = new System.Drawing.Size(99, 17);
            this.label_old.TabIndex = 0;
            this.label_old.Text = "Old Password:";
            // 
            // label_new1
            // 
            this.label_new1.AutoSize = true;
            this.label_new1.Location = new System.Drawing.Point(11, 35);
            this.label_new1.Name = "label_new1";
            this.label_new1.Size = new System.Drawing.Size(104, 17);
            this.label_new1.TabIndex = 1;
            this.label_new1.Text = "New Password:";
            // 
            // input_old
            // 
            this.input_old.Location = new System.Drawing.Point(155, 6);
            this.input_old.Name = "input_old";
            this.input_old.Size = new System.Drawing.Size(100, 22);
            this.input_old.TabIndex = 2;
            // 
            // input_new
            // 
            this.input_new.Location = new System.Drawing.Point(155, 35);
            this.input_new.Name = "input_new";
            this.input_new.Size = new System.Drawing.Size(100, 22);
            this.input_new.TabIndex = 3;
            // 
            // button_apply
            // 
            this.button_apply.Location = new System.Drawing.Point(155, 63);
            this.button_apply.Name = "button_apply";
            this.button_apply.Size = new System.Drawing.Size(100, 29);
            this.button_apply.TabIndex = 4;
            this.button_apply.Text = "Apply";
            this.button_apply.UseVisualStyleBackColor = true;
            this.button_apply.Click += new System.EventHandler(this.button_apply_Click);
            // 
            // changePassword
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(267, 102);
            this.Controls.Add(this.button_apply);
            this.Controls.Add(this.input_new);
            this.Controls.Add(this.input_old);
            this.Controls.Add(this.label_new1);
            this.Controls.Add(this.label_old);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedDialog;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "changePassword";
            this.Text = "Changing Server Password";
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Label label_old;
        private System.Windows.Forms.Label label_new1;
        private System.Windows.Forms.TextBox input_old;
        private System.Windows.Forms.TextBox input_new;
        private System.Windows.Forms.Button button_apply;
    }
}