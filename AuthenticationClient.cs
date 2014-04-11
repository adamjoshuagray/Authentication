using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Channels;

namespace Authentication
{
    public class  AuthenticationClient
    {
        private string _Username;
        private string _Password;
        private string _RemoteAppIDStr;
        private string _LocalAppIDStr;
        private UserDatabase _Database;
        private SecureHandshaker _SecureHandshaker;

        public event EventHandler<AuthenticationSuccessEventArgs> Authenticated;
        public event EventHandler<AuthenticationErrorEventArgs> AuthenticationErrored;

        public AuthenticationClient(MessageChannel channel,
            string username, 
            string password, 
            string localappidstr, 
            string remoteappidstr,
            UserDatabase database)
        {
            _Username = username;
            _Password = password;
            _RemoteAppIDStr = remoteappidstr;
            _LocalAppIDStr = localappidstr;
            _Database = database;
            _SecureHandshaker = new SecureHandshaker(channel);
            _SecureHandshaker.HandshakeCompleted += new EventHandler<SecureHandshakeCompleteEventArgs>(sh_HandshakeCompleted);
            _SecureHandshaker.HandshakeErrored += new EventHandler<SecureHandshakeErrorEventArgs>(sh_HandshakeErrored);
        }

        public void StartAuthentication()
        {
            _SecureHandshaker.SendHandshake();
        }

        void sh_HandshakeErrored(object sender, SecureHandshakeErrorEventArgs e)
        {
            if (AuthenticationErrored != null)
            {
                AuthenticationErrored(this, new AuthenticationErrorEventArgs(AuthenticationFailureReason.ChannelError,
                    SecureChannelErrorType.Unknown,
                    "", ""));
            }
        }

        void sh_HandshakeCompleted(object sender, SecureHandshakeCompleteEventArgs e)
        {
            AuthenticationHandshake ah = new AuthenticationHandshake(e.SecuredChannel,
                _Username,
                UserDatabase.HashPassword(_Password),
                _LocalAppIDStr,
                new ValidationCallback(_Validate));
            ah.AuthenticationComplete += new EventHandler<AuthenticationHandshakeEventArgs>(ah_AuthenticationComplete);
            ah.StartHandshake();
        }

        void ah_AuthenticationComplete(object sender, AuthenticationHandshakeEventArgs e)
        {
            if (e.Success)
            {
                if (Authenticated != null)
                {
                    Authenticated(this, new AuthenticationSuccessEventArgs(e.Username, e.Channel));
                }
            }
            else
            {
                if (AuthenticationErrored != null)
                {
                    AuthenticationErrored(this, new AuthenticationErrorEventArgs(AuthenticationFailureReason.WrongDetails, 
                        SecureChannelErrorType.Unknown,
                        "",
                        e.Username));
                }
            }
        }

        private bool _Validate(string username, string passwordhash, string appidstr)
        {
            bool valid = false;
            _Database.ValidateUser(username, passwordhash, out valid);
            valid &= (appidstr == _RemoteAppIDStr);
            return valid;

        }
    }
}
