using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Channels;

namespace Authentication
{
    public class AuthenticationHandshakeEventArgs : EventArgs
    {
        public bool Success
        {
            get;
            private set;
        }
        public string Username
        {
            get;
            private set;
        }
        public SecureChannel Channel
        {
            get;
            private set;
        }
        public AuthenticationHandshakeEventArgs(bool success, string username, SecureChannel channel)
        {
            Username = username;
            Success = success;
            Channel = channel;
        }
    }
}
