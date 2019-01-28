// Author: Toomas Kaljus
// http://www.digigrupp.com

namespace packet
{
	public class Application
	{
		public static int Main(string[] args)
		{
			try {
				MainForm AppForm = new MainForm();
				if (args.Length != 0) AppForm.SelectIP.Text = args[0];
				System.Windows.Forms.Application.Run(AppForm);
			} catch {
				return 1;
			}
			return 0;
		}
	}

	public class MainForm : System.Windows.Forms.Form
	{
		System.Windows.Forms.Label SelectIPLabel = new System.Windows.Forms.Label();
		public System.Windows.Forms.ComboBox SelectIP = new System.Windows.Forms.ComboBox();
		System.Windows.Forms.Button StartButton = new System.Windows.Forms.Button(), StopButton  = new System.Windows.Forms.Button();
		System.Windows.Forms.CheckBox DnsResolve = new System.Windows.Forms.CheckBox();
		System.Windows.Forms.CheckBox LooseQueue = new System.Windows.Forms.CheckBox();
		System.Windows.Forms.Button SaveButton = new System.Windows.Forms.Button(), ResetButton = new System.Windows.Forms.Button();
		System.Windows.Forms.ListBox ResultBox = new System.Windows.Forms.ListBox();
		System.Threading.Thread Sniffer;
		System.Net.Sockets.Socket Socket;
		const int PacketBufferSize = 65536;
		byte[] PacketBuffer = new byte[PacketBufferSize];
		System.Collections.Specialized.NameValueCollection DNSCache = new System.Collections.Specialized.NameValueCollection();
		
		internal MainForm() : base()
		{
			Text = "Sniffer";
			Width = 400;
			Controls.Add(SelectIPLabel);
			SelectIPLabel.Top = 4;
			SelectIPLabel.Left = 4;
			SelectIPLabel.Text = "Select IP address:";
			Controls.Add(SelectIP);
			SelectIP.Top = 4;
			SelectIP.Left = 104;

	#if NET20
			System.Net.IPAddress[] IPAddress = System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName());
			if(IPAddress.Length > 0)
				for (int i=0; i<IPAddress.Length; i++)
					SelectIP.Items.Add(IPAddress[i].ToString());
	#else
			System.Net.IPHostEntry HostEntry = System.Net.Dns.Resolve(System.Net.Dns.GetHostName());
			if(HostEntry.AddressList.Length > 0)
				for (int i=0; i<HostEntry.AddressList.Length; i++)
					SelectIP.Items.Add(HostEntry.AddressList[i].ToString());
	#endif

			Controls.Add(StartButton);
			StartButton.Top = 4;
			StartButton.Left = 230;
			StartButton.Text = "Start";
			StartButton.Click += new System.EventHandler(StartButton_Click);
			Controls.Add(StopButton);
			StopButton.Top = 4;
			StopButton.Left = 310;
			StopButton.Text = "Stop";
			StopButton.Click += new System.EventHandler(StopButton_Click);
			StopButton.Enabled = false;
			Controls.Add(DnsResolve);
			DnsResolve.Top = 28;
			DnsResolve.Left = 4;
			DnsResolve.Width = 130;
			DnsResolve.Text = "Resolve Host Names";
			Controls.Add(LooseQueue);
			LooseQueue.Top = 28;
			LooseQueue.Left = 134;
			LooseQueue.Width = 96;
			LooseQueue.Text = "Loose Queue";
			Controls.Add(SaveButton);
			SaveButton.Top = 28;
			SaveButton.Left = 230;
			SaveButton.Text = "Save";
			SaveButton.Click += new System.EventHandler(SaveButton_Click);
			Controls.Add(ResetButton);
			ResetButton.Top = 28;
			ResetButton.Left = 310;
			ResetButton.Text = "Reset";
			ResetButton.Click += new System.EventHandler(ResetButton_Click);
			Controls.Add(ResultBox);
			ResultBox.Top = 54;
			ResultBox.Left = 4;
			ResultBox.Width = 384;
			ResultBox.Height = 224;
			ResultBox.Anchor = (System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right | System.Windows.Forms.AnchorStyles.Top);
		}

		private void StartButton_Click(object Sender, System.EventArgs e)
		{
			if (SelectIP.Text == "") {
				System.Windows.Forms.MessageBox.Show("Please select IP!");
				return;
			}
            selectip = SelectIP.Text;
			StartButton.Enabled = false;
			Sniffer = new System.Threading.Thread(new System.Threading.ThreadStart(RunReceiver));
			Sniffer.Start();
		}

		private void StopButton_Click(object Sender, System.EventArgs e)
		{
			StopButton.Enabled = false;
		}

		private void SaveButton_Click(object Sender, System.EventArgs e)
		{
			using (System.IO.StreamWriter sw = new System.IO.StreamWriter(System.IO.Path.GetDirectoryName(System.Windows.Forms.Application.ExecutablePath) + "\\iplog.txt")) {
				for (int i=0; i<ResultBox.Items.Count; i++) sw.WriteLine(System.DateTime.Now + " " + ResultBox.Items[i].ToString());
			}
		}

		private void ResetButton_Click(object Sender, System.EventArgs e)
		{
			ResultBox.Items.Clear();
		}

		protected override void Dispose(bool disposing)
		{
			if (StopButton.Enabled) StopButton_Click(null, null);
			while (StopButton.Enabled) System.Threading.Thread.Sleep(1);
			base.Dispose(disposing);
		}
        private delegate void setButtonEnable(System.Windows.Forms.Button btn,bool en);
        private void setButton(System.Windows.Forms.Button btn, bool en)
        {
            btn.Enabled = en;
        }
        string selectip = "";
		private void RunReceiver()
		{
            //StopButton.BeginInvoke(new setButtonEnable(setButton), new object[] {StopButton, true });
			try {
				try {
					Socket = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Raw, System.Net.Sockets.ProtocolType.IP);
					try {
                        Socket.Bind(new System.Net.IPEndPoint(System.Net.IPAddress.Parse(selectip), 0));
						Socket.SetSocketOption(System.Net.Sockets.SocketOptionLevel.IP, System.Net.Sockets.SocketOptionName.HeaderIncluded, 1);
						Socket.IOControl(unchecked((int)0x98000001), new byte[4]{1, 0, 0, 0}, new byte[4]);
						while (StopButton.Enabled) {
							System.IAsyncResult ar = Socket.BeginReceive(PacketBuffer, 0, PacketBufferSize, System.Net.Sockets.SocketFlags.None, new System.AsyncCallback(CallReceive), this);
							while (Socket.Available == 0) {
								System.Threading.Thread.Sleep(1);
								if (!StopButton.Enabled) break;
							}
							if (!StopButton.Enabled) break;
							int Size = Socket.EndReceive(ar);
							if (!LooseQueue.Checked) ExtractBuffer();
						}
					} finally {
						if (Socket != null) {
							Socket.Shutdown(System.Net.Sockets.SocketShutdown.Both);
							Socket.Close();
						}
					}
				} finally {
                    //StopButton.Enabled = false;
                    //StartButton.Enabled = true;
                    StartButton.BeginInvoke(new setButtonEnable(setButton), new object[] { StartButton, true });
                    StopButton.BeginInvoke(new setButtonEnable(setButton), new object[] { StopButton, true });
				}
			} catch (System.Threading.ThreadAbortException) {
			} catch (System.Exception E) {
				System.Windows.Forms.MessageBox.Show(E.ToString());
			}
            //StartButton.BeginInvoke(new setButtonEnable(setButton), new object[] { StartButton, true });
			//StartButton.Enabled = true;
		}

		public virtual void CallReceive(System.IAsyncResult ar)
		{
			if (LooseQueue.Checked) ExtractBuffer();
		}
        private delegate void insertItem(System.Windows.Forms.ListBox lb, string item);
        private void insertIT(System.Windows.Forms.ListBox lb, string item)
        {
            lb.Items.Insert(0, item);
        }
		protected void ExtractBuffer()
		{
			IPPacket IP = new IPPacket(ref PacketBuffer);

			string SourceAddress = IP.SourceAddress.ToString();
			string DestinationAddress = IP.DestinationAddress.ToString();

			if (DnsResolve.Checked) {
				string HostName = DNSCache[SourceAddress];
				if (HostName == null) {
					DNSCache[SourceAddress] = "";
	#if NET20
	try {
					HostName = System.Net.Dns.GetHostEntry(SourceAddress).HostName;
	} catch {
					HostName = "";
	}
	#else
					HostName = System.Net.Dns.Resolve(SourceAddress).HostName;
	#endif
					DNSCache[SourceAddress] = HostName;
				}
				if (HostName != SourceAddress) SourceAddress += " " + HostName;
				HostName = DNSCache[DestinationAddress];
				if (HostName == null) {
					DNSCache[DestinationAddress] = "";
	#if NET20
	try {
					HostName = System.Net.Dns.GetHostEntry(SourceAddress).HostName;
	} catch {
					HostName = "";
	}
	#else
					HostName = System.Net.Dns.Resolve(SourceAddress).HostName;
	#endif
					DNSCache[DestinationAddress] = HostName;
				}
				if (HostName != DestinationAddress) DestinationAddress += " " + HostName;
			}

			if (IP.TCP != null) {
				string Data = System.Text.RegularExpressions.Regex.Replace(System.Text.Encoding.ASCII.GetString(IP.TCP.PacketData), @"[^a-zA-Z_0-9\.\@\- ]", "");
                ResultBox.BeginInvoke(new insertItem(insertIT), new object[] { "TCP " + SourceAddress + ":" + IP.TCP.SourcePort + " --> " + DestinationAddress + ":" + IP.TCP.DestinationPort + " " + Data });
				//ResultBox.Items.Insert(0, "TCP " + SourceAddress + ":" + IP.TCP.SourcePort + " --> " + DestinationAddress + ":" + IP.TCP.DestinationPort + " " + Data);

			} else
			if (IP.UDP != null) {
				string Data = System.Text.RegularExpressions.Regex.Replace(System.Text.Encoding.ASCII.GetString(IP.UDP.PacketData), @"[^a-zA-Z_0-9\.\@\- ]", "");
                ResultBox.BeginInvoke(new insertItem(insertIT), new object[] { "UDP " + SourceAddress + ":" + IP.UDP.SourcePort + " --> " + DestinationAddress + ":" + IP.UDP.DestinationPort + " " + Data });
				//ResultBox.Items.Insert(0, "UDP " + SourceAddress + ":" + IP.UDP.SourcePort + " --> " + DestinationAddress + ":" + IP.UDP.DestinationPort + " " + Data);

			} else
			if (IP.ICMP != null) {
				string Data = System.Text.RegularExpressions.Regex.Replace(System.Text.Encoding.ASCII.GetString(IP.ICMP.PacketData), @"[^a-zA-Z_0-9\.\@\- ]", "");
                ResultBox.BeginInvoke(new insertItem(insertIT), new object[] { "ICMP " + SourceAddress + " --> " + DestinationAddress + " " + IP.ICMP.Message + " " + Data });
				//ResultBox.Items.Insert(0, "ICMP " + SourceAddress + " --> " + DestinationAddress + " " + IP.ICMP.Message + " " + Data);

			} else
                ResultBox.BeginInvoke(new insertItem(insertIT), new object[] { IP.Protocol + " " + SourceAddress + " --> " + DestinationAddress });
			//ResultBox.Items.Insert(0, IP.Protocol + " " + SourceAddress + " --> " + DestinationAddress);
		}
	}
}