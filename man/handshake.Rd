\name{handshake}
\alias{handshake}
\alias{authorize}
\title{Negotiate obtaining the tokens needed to make API requests}
\description{
  This function communicates with a Web server and requests
  the necessary tokens and secrets to be able to make
  authenticated requests of the Web service's API methods.
  This exchanges the application's/consumer's key and secret
  for tokens that can be used to sign requests in a secure manner.
  The handshake exchange sends the consumer key and secret,
  and then typically  prompts the user to grant authorization
  for the application. When this is done, the next step is
  to use this authorization PIN/code to obtain 
}
\usage{
handshake(cred, post = TRUE, signMethod = "HMAC", curl = getCurlHandle(), verify = TRUE, ...)
}
\arguments{
  \item{cred}{an object of class \code{OAuthCredentials} that provides
    the consumer key and secret and the URLs for negotiating access to
    the authorization keys we need.}
  \item{post}{a logical value that controls whether we use a \code{GET}
    or \code{POST} request to communicate with the Web server.}
  \item{signMethod}{a character string that identifies the algorithm we
    use to sign the requests to ensure they are secure.  }
  \item{curl}{a CURL handle that can be used across different requests, typically
    to the same server. This can be supplied to provide continuity
    across calls and reduce the overhead of establishing the connection.
    It can also be used to customize the connection outside of the call.}
  \item{verify}{a logical value that controls whether we have to return
    to the Web server to make the user explicitly authorize access.}
  \item{\dots}{additional arguments passed to the \code{curlPerform} call.}
}
\value{
  an updated version of \code{cred}, the \code{OAuthCredentials}.
}
\references{
}
\author{
Duncan Temple Lang
}


\seealso{
  \code{\link{oauth}}
  \code{\link{OAuthRequest}}
}
\examples{
\dontrun{
 reqURL <- "https://api.dropbox.com/1/oauth/request_token"
 authURL <- "https://www.dropbox.com/1/oauth/authorize"
 accessURL <- "https://api.dropbox.com/1/oauth/access_token/"

 cKey <-getOption("DropboxKey")
 cSecret <-getOption("DropboxSecret")

     # Here we sub-class the OAuthCredentials class specificallly
     # for Dropbox. This will allow us to check is(, "DropboxCredentials")
     # and ensure we are not using credentials for another service.
  setClass("DropboxCredentials", contains = "OAuthCredentials")


  k = oauth(cKey, cSecret, reqURL, authURL, accessURL,
             obj = new("DropboxCredentials"))
  cred = handshake(k, post = FALSE)
}
}
\keyword{IO}
\concept{OAuth}
\concept{security}
