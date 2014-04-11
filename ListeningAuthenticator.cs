using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Channels;

namespace Authentication
{
    public class ListeningAuthenticator
    {
        private string _Username;
        private string _Password;
        private ChannelListener _Listener;
        private UserDatabase _Database;
        private string _LocalAppIdStr;
        private string _RemoteAppIdStr;


        public event EventHandler<AuthenticationSuccessEventArgs> Authenticated;
        public event EventHandler<AuthenticationErrorEventArgs> AuthenticationError;

        public ListeningAuthenticator(ChannelListener listener, UserDatabase database,
            string username, string password, string localappidstr, string remoteappidstr)
        {
            _Listener = listener;
            _Listener.Connected += new EventHandler<ChannelListenerConnectedEventArgs>(listener_Connected);
            _Database = database;
            _Username = username;
            _Password = password;
            _RemoteAppIdStr = remoteappidstr;
            _LocalAppIdStr = localappidstr;
        }

        void listener_Connected(object sender, ChannelListenerConnectedEventArgs e)
        {
            SecureHandshaker sh = new SecureHandshaker(e.Channel);
            sh.HandshakeCompleted += new EventHandler<SecureHandshakeCompleteEventArgs>(sh_HandshakeCompleted);
            sh.HandshakeErrored += new EventHandler<SecureHandshakeErrorEventArgs>(sh_HandshakeErrored);
            sh.SendHandshake();
        }

        void sh_HandshakeErrored(object sender, SecureHandshakeErrorEventArgs e)
        {
            if (AuthenticationError != null)
            {
                AuthenticationError(this, new AuthenticationErrorEventArgs(AuthenticationFailureReason.ChannelError, SecureChannelErrorType.CryptographyError,
                    "", ""));
            }


        }

        void sh_HandshakeCompleted(object sender, SecureHandshakeCompleteEventArgs e)
        {
            SecureHandshaker sh = sender as SecureHandshaker;
            sh.Dispose();
            AuthenticationHandshake ah = new AuthenticationHandshake(e.SecuredChannel, _Username, UserDatabase.HashPassword(_Password),
                _LocalAppIdStr, new ValidationCallback(_Validate));
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
                if (AuthenticationError != null)
                {
                    AuthenticationError(this, new AuthenticationErrorEventArgs(AuthenticationFailureReason.WrongDetails,
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
            valid &= (appidstr == _RemoteAppIdStr);
            return valid;
        }
    }
}
