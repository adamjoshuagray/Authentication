using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using Channels;

namespace Authentication
{
    public enum AuthenticationFailureReason
    {
        None = 0,
        WrongDetails = 1,
        ChannelError = 2
    }
    public class AuthenticationErrorEventArgs : EventArgs
    {
        public string Username
        {
            get;
            private set;
        }
        public SecureChannelErrorType SecureChannelErrorType
        {
            get;
            private set;
        }
        public string SecureChannelErrorReason
        {
            get;
            private set;
        }
        public AuthenticationFailureReason Reason
        {
            get;
            private set;
        }
        public AuthenticationErrorEventArgs(AuthenticationFailureReason reason,
            SecureChannelErrorType schannelerrortype, string schannelerrorreason, string username)
        {
            Reason = reason;
            SecureChannelErrorType = schannelerrortype;
            SecureChannelErrorReason = schannelerrorreason;
            Username = username;
        }
    }
}
