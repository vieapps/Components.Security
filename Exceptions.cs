using System;
using System.Runtime.Serialization;

using net.vieapps.Components.Utility;

namespace net.vieapps.Components.Security
{
	[Serializable]
	public class InvalidSessionException : AppException
	{
		public InvalidSessionException() : base("Session is invalid") { }

		public InvalidSessionException(string message) : base(message) { }

		public InvalidSessionException(Exception innerException) : base("Session is invalid", innerException) { }

		public InvalidSessionException(string message, Exception innerException) : base(message, innerException) { }

		public InvalidSessionException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class SessionNotFoundException : AppException
	{
		public SessionNotFoundException() : base("Session is not found") { }

		public SessionNotFoundException(string message) : base(message) { }

		public SessionNotFoundException(string message, Exception innerException) : base (message, innerException) { }

		public SessionNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class SessionInformationRequiredException : AppException
	{
		public SessionInformationRequiredException() : base("Required information of the session is not found") { }

		public SessionInformationRequiredException(string message) : base(message) { }

		public SessionInformationRequiredException(Exception innerException) : base("Required information of the session is not found", innerException) { }

		public SessionInformationRequiredException(string message, Exception innerException) : base(message, innerException) { }

		public SessionInformationRequiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class SessionExpiredException : AppException
	{
		public SessionExpiredException() : base("Session is expired") { }

		public SessionExpiredException(string message) : base(message) { }

		public SessionExpiredException(string message, Exception innerException) : base (message, innerException) { }

		public SessionExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class InvalidTokenException : AppException
	{
		public InvalidTokenException() : base("Token is invalid") { }

		public InvalidTokenException(string message) : base(message) { }

		public InvalidTokenException(Exception innerException) : base("Token is invalid", innerException) { }

		public InvalidTokenException(string message, Exception innerException) : base(message, innerException) { }

		public InvalidTokenException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class TokenNotFoundException : AppException
	{
		public TokenNotFoundException() : base("Token is not found") { }

		public TokenNotFoundException(string message) : base(message) { }

		public TokenNotFoundException(string message, Exception innerException) : base (message, innerException) { }

		public TokenNotFoundException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class TokenExpiredException : AppException
	{
		public TokenExpiredException() : base("Token is expired") { }

		public TokenExpiredException(string message) : base(message) { }

		public TokenExpiredException(string message, Exception innerException) : base (message, innerException) { }

		public TokenExpiredException(Exception innerException) : base("Token is expired", innerException) { }

		public TokenExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class TokenRevokedException : AppException
	{
		public TokenRevokedException() : base("The access token has been revoked") { }

		public TokenRevokedException(string message) : base(message) { }

		public TokenRevokedException(string message, Exception innerException) : base(message, innerException) { }

		public TokenRevokedException(Exception innerException) : base("The access token has been revoked", innerException) { }

		public TokenRevokedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class InvalidTokenSignatureException : AppException
	{
		public InvalidTokenSignatureException() : base("Token signature is invalid") { }

		public InvalidTokenSignatureException(string message) : base(message) { }

		public InvalidTokenSignatureException(Exception innerException) : base("Token signature is invalid", innerException) { }

		public InvalidTokenSignatureException(string message, Exception innerException) : base(message, innerException) { }

		public InvalidTokenSignatureException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class UnauthorizedException : AppException
	{
		public UnauthorizedException() : base("Unauthorized. Sign-in please!") { }

		public UnauthorizedException(string message) : base(message) { }

		public UnauthorizedException(string message, Exception innerException) : base(message, innerException) { }

		public UnauthorizedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class AccessDeniedException : AppException
	{
		public AccessDeniedException() : base("Sorry! You don't have enough permission to complete this request!") { }

		public AccessDeniedException(string message) : base(message) { }

		public AccessDeniedException(string message, Exception innerException) : base(message, innerException) { }

		public AccessDeniedException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class WrongAccountException : AppException
	{
		public WrongAccountException() : base("Wrong account or password") { }

		public WrongAccountException(string message) : base(message) { }

		public WrongAccountException(Exception innerException) : base("Wrong account or password", innerException) { }

		public WrongAccountException(string message, Exception innerException) : base(message, innerException) { }

		public WrongAccountException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class InvalidActivateInformationException : AppException
	{
		public InvalidActivateInformationException() : base("The information for activating is invalid") { }

		public InvalidActivateInformationException(string message) : base(message) { }

		public InvalidActivateInformationException(Exception innerException) : base("The information for activating is invalid", innerException) { }

		public InvalidActivateInformationException(string message, Exception innerException) : base(message, innerException) { }

		public InvalidActivateInformationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

	[Serializable]
	public class ActivateInformationExpiredException : AppException
	{
		public ActivateInformationExpiredException() : base("The information for activating is expired") { }

		public ActivateInformationExpiredException(string message) : base(message) { }

		public ActivateInformationExpiredException(Exception innerException) : base("The information for activating is expired", innerException) { }

		public ActivateInformationExpiredException(string message, Exception innerException) : base(message, innerException) { }

		public ActivateInformationExpiredException(SerializationInfo info, StreamingContext context) : base(info, context) { }
	}

}