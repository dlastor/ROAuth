\name{OAuthCredentials-class}
\Rdversion{1.1}
\docType{class}
\alias{OAuthCredentials-class}
\alias{oauth}
\alias{$,OAuthCredentials-method}

\title{Class \code{"OAuthCredentials"}}
\description{
  This is class that provides the application's/consumer's key and secret
  and the URLs  to start an OAuth negotiation and will also be filled in with the
  actual key and secret for making authorized requests.
}
\section{Objects from the Class}{
  Objects can be created by calls to \code{oauth}
  or  \code{new("OAuthCredentials", ...)}.
  This class is intended to be sub-classed for particular Web services.
  The intent is that the class identifies the service so that there
  is no confusion in using it in the wrong context.

  Having obtained the OAuth key and secret with which to make requests,
  this object can be passed to \code{OAuthRequest}.
  Additionally, operations can be invoked using the form
  \code{credential$op(url, ...)}
  where \code{op} is one of the HTTP methods such as 
  get, post, put, delete.
}
\section{Slots}{
  \describe{
    \item{\code{consumerKey}:}{Object of class \code{"character"} the
      consumer's key }
    \item{\code{consumerSecret}:}{Object of class \code{"character"} the
    consumer's secret.}
    \item{\code{oauthKey}:}{Object of class \code{"character"} this is
      omitted when the object is created and computed via the
    \code{handshake} operation that negotiates the key and secret for
    actual invocations}
    \item{\code{oauthSecret}:}{Object of class \code{"character"} same
      as \code{oauthKey} above, but the secret part of the negotiated token. }
    \item{\code{requestURL}:}{Object of class \code{"character"} the URL
    for requesting the initial unauthorized token that starts the exchange.}
    \item{\code{authURL}:}{Object of class \code{"character"}. This is
  the URL that we pass the initial unauthorized key and secret so that
  the user can explicitly grant authorization for this application.}
\item{\code{accessURL}:}{Object of class \code{"character"}
    This is the URL that we use to exchange the initial unauthorized tokens 
   to get the actual key and secret we can use in subsequent calls.}
    \item{\code{signMethod}:}{Object of class \code{"character"}
      the name of the method used to sign requests. This is typically 'HMAC'. }
  }
}
\section{Methods}{
  \describe{
    \item{$}{\code{signature(x = "OAuthCredentials")}:  this allows us
      to invoke requests in the form \code{cred$operation(url, ...)}
      where \code{operation} is one of the HTTP methods such as
      \code{get}, \code{post}, \code{put}, \code{delete}.
    }
   }
}
%\references{}
\author{
Duncan Temple Lang
}

\seealso{
 \code{\link{oauth}} for creating objects of this class.
 \code{\link{handshake}} for negotiating the actual key and secrets we
 will use.
}
\examples{

  setClass("DropboxCredentials", contains = "OAuthCredentials")

  cred = oauth("myKey", "mySecret",
               requestURL = "https://api.dropbox.com/1/oauth/request_token",
               authURL = "https://www.dropbox.com/1/oauth/authorize",
               accessURL = "https://api.dropbox.com/1/oauth/access_token/",
               obj = new("DropboxCredentials"))

\dontrun{
   cred = handshake(cred)
}
}
\keyword{classes}
