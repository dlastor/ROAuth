\name{OAuthRequest}
\alias{OAuthRequest}
\title{Invoke a Web service method using  OAuth signing}
\description{
  This function invokes a REST Web service method
  using the OAuth credentials previously negotiated
  to allow authorized requests.
}
\usage{
OAuthRequest(cred, URL, params = character(), method = "GET",
              customHeader = NULL, curl = getCurlHandle(),
               ..., binary = NA)
}

\arguments{
  \item{cred}{an object of class \code{\link{OAuthCredentials-class}}
      that has been completed via \code{handshake} or \code{authorize},
      i.e. the final key and secret have been obtained.
   }
  \item{URL}{ the URL to which to send the request.
}
\item{params}{a character vector or list of named values
  that represent the inputs to the request. These are
  used to create the signature for the request.
}
\item{method}{the HTTP method to use for the request. This should be
   \code{"GET"}, \code{"POST"}, \code{"PUT"} or \code{"DELETE"}.}
  \item{customHeader}{The name of this  argument may change to
    customOAuthHeader.
   This currently is expected to be a named character vector that will
   be added to the \code{Authorization} string used in the HTTP header.
   This is not used in signing the request. An example is that we add
   the hash of the file being uploaded to Mendeley via the
   field \code{"oauth_body_hash"}.
   }
  \item{curl}{a CURL handle instance used to make the request}
  \item{\dots}{options that are passed to \code{curlPerform} to
    customize the HTTP request}
  \item{binary}{a logical value that identifies whether the result
    should be treated as binary content or text. The
    \code{\link[RCurl]{dynCurlReader}}
    function uses this to govern how it handles the content of the HTTP
    response.
    If this is \code{NA},   \code{\link[RCurl]{dynCurlReader}}
    uses the Content-Type in the HTTP response' header to determine
    what to do. The caller should specify this if
    \code{\link[RCurl]{dynCurlReader}} will get this wrong,
    either because it doesn't know about a certain MIME type
    or because the MIME type returned by the Web server is incorrect.
   }
}

\value{
  The result of the HTTP request.
}
\author{
Duncan Temple Lang
}

\seealso{
  \code{\link{oauth}}
  \code{\link{handshake}}
}
\examples{

}
\keyword{IO}

