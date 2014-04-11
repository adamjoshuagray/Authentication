using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using Channels;

namespace Authentication
{
    public delegate bool ValidationCallback(string username, string passwordhash, string appidstr);
    public class AuthenticationHandshake : IDisposable
    {
        private const string _USERNAME_ATTRIBUTE = "#";
        private const string _PWD_HASH_ATTRIBUTE = "$";
        private const string _RESULT_ATTRIBUTE = "%";
        private const string _APP_ID_STR_ATTRIBUTE = "~";
        private const byte _SUCCESS_BYTE = 17;
        private const byte _FAILURE_BYTE = 119;
        private bool _LocalAuthState = false;
        private bool _RemoteAuthState = false;
        private string _RemoteUsername = "";
        private SecureChannel _SecureChannel;
        private AutoResetEvent _AreHandshake;
        private AutoResetEvent _AreEventSync;
        private Thread _WaitCompleteThread;
        private Timer _PingTimer;
        private ValidationCallback _ValidationCallback;
        private bool _RemoteState;
        private bool _LocalState;
        private string _Username;
        private string _PasswordHash;
        private string _ApplicationIdentificationString;

        public event EventHandler<AuthenticationHandshakeEventArgs> AuthenticationComplete;

        public void Dispose()
        {
            _AreHandshake.Set();
            _AreHandshake.Set();
            _SecureChannel.Errored -= new EventHandler<SecureChannelErrorEventArgs>(schannel_Errored);
            _SecureChannel.MessageReceived -= new EventHandler<SecureChannelMessageReceivedEventArgs>(schannel_MessageReceived); ;
            Disposed = true;
        }

        public bool Disposed
        {
            get;
            private set;
        }

        public AuthenticationHandshake(SecureChannel schannel, string username, string passwordhash, 
            string appidstring, ValidationCallback valcallback)
        {
            _ApplicationIdentificationString = appidstring;
            _Username = username;
            _PasswordHash = passwordhash;
            _AreEventSync = new AutoResetEvent(false);
            _AreHandshake = new AutoResetEvent(false);
            _RemoteState = false;
            _LocalState = false;
            Disposed = false;
            _SecureChannel = schannel;
            if (valcallback == null)
            {
                throw new ArgumentNullException("valcallback", "valcallback can't be null");
            }
            _WaitCompleteThread = new Thread(new ThreadStart(_WaitComplete));
            _ValidationCallback = valcallback;
            schannel.Errored += new EventHandler<SecureChannelErrorEventArgs>(schannel_Errored);
            schannel.MessageReceived += new EventHandler<SecureChannelMessageReceivedEventArgs>(schannel_MessageReceived);
        }

        public void StartHandshake()
        {
            _WaitCompleteThread.Start();
        }
        

        private void _WaitComplete()
        {
            Dictionary<string, byte[]> attribs = new Dictionary<string, byte[]>();
            attribs.Add(_USERNAME_ATTRIBUTE, ASCIIEncoding.ASCII.GetBytes(_Username));
            attribs.Add(_PWD_HASH_ATTRIBUTE, ASCIIEncoding.ASCII.GetBytes(_PasswordHash));
            attribs.Add(_APP_ID_STR_ATTRIBUTE, ASCIIEncoding.ASCII.GetBytes(_ApplicationIdentificationString));
            _SecureChannel.SendMessage(attribs);
            _AreHandshake.WaitOne();
            _AreEventSync.Set();
            _AreHandshake.WaitOne();
            bool result = (_RemoteState && _LocalState);
            if (AuthenticationComplete != null)
            {
                AuthenticationComplete(this, new AuthenticationHandshakeEventArgs(result, _RemoteUsername, _SecureChannel));
            }
            _AreEventSync.Set();

        }

        private void _SendResult(bool result)
        {
            Dictionary<string, byte[]> attribs = new Dictionary<string, byte[]>();
            byte[] resbyte;
            if (result)
            {
                resbyte = new byte[] { _SUCCESS_BYTE };
            }
            else
            {
                resbyte = new byte[] { _FAILURE_BYTE };
            }
            attribs.Add(_RESULT_ATTRIBUTE, resbyte);
            _SecureChannel.SendMessage(attribs);
        }

        void schannel_MessageReceived(object sender, SecureChannelMessageReceivedEventArgs e)
        {
            if (e.Attributes.Count == 3 &&
                e.Attributes.ContainsKey(_PWD_HASH_ATTRIBUTE) &&
                e.Attributes.ContainsKey(_USERNAME_ATTRIBUTE) &&
                e.Attributes.ContainsKey(_APP_ID_STR_ATTRIBUTE))
            {
                string appidstr = ASCIIEncoding.ASCII.GetString(e.Attributes[_APP_ID_STR_ATTRIBUTE]);
                string username = ASCIIEncoding.ASCII.GetString(e.Attributes[_USERNAME_ATTRIBUTE]);
                string passwordhash = ASCIIEncoding.ASCII.GetString(e.Attributes[_PWD_HASH_ATTRIBUTE]);

                _RemoteUsername = username;
                bool success = _ValidationCallback(username, passwordhash, appidstr);
                _RemoteState = success;
                _SendResult(success);
                _AreHandshake.Set();
                _AreEventSync.WaitOne();
            }
            else if (e.Attributes.Count == 1 &&
                e.Attributes.ContainsKey(_RESULT_ATTRIBUTE) &&
                e.Attributes[_RESULT_ATTRIBUTE].Length == 1)
            {
                if (e.Attributes[_RESULT_ATTRIBUTE][0] == _SUCCESS_BYTE)
                {
                    _LocalState = true;
                }
                else if (e.Attributes[_RESULT_ATTRIBUTE][0] == _FAILURE_BYTE)
                {
                    _LocalState = false;
                }
                else
                {
                    _LocalState = false;
                }
                _AreHandshake.Set();
                _AreEventSync.WaitOne();

            }
        }

        void schannel_Errored(object sender, SecureChannelErrorEventArgs e)
        {

        }
    }
}
