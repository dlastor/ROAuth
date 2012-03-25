setRefClass("OAuth",
            fields = list(
              consumerKey = "character",
              consumerSecret = "character",
              oauthKey = "character",
              oauthSecret = "character",
              needsVerifier = "logical",
              handshakeComplete = "logical",
              verifier = "character",
              requestURL = "character",
              authURL = "character",
              accessURL = "character",
              signMethod = 'character',
              postRequest = 'logical'
             ),
            methods = list(
              initialize = function(needsVerifier, ...) {
                if (!missing(needsVerifier))
                  needsVerifier <<- needsVerifier
                else
                  needsVerifier <<- TRUE
                handshakeComplete <<- FALSE
                postRequest <<- TRUE
                callSuper(...)
                .self
              },
              
              handshake = function(signMethod='HMAC', curl=getCurlHandle(), post = .self$postRequest, ...) {
                ' Performs the OAuth handshake.  In most cases
                  the user will need to complete a manual step
                  with their web browser, entering a PIN into
                  this function.
                '
                handshakeComplete <<- FALSE
                signMethod <<- signMethod

                obj <- authorize(.self, post = post, curl = curl, signMethod = signMethod, ...)
                
                oauthKey <<- obj@oauthKey
                oauthSecret <<- obj@oauthSecret
                
                handshakeComplete <<- TRUE
              },
              
              isVerified = function() {
                'Will report if this object is verified or not.
                 Verification can either involve not needing it
                 in the first place, or as part of the handshake'
                if (.self$needsVerifier)
                  length(verifier) != 0
                else
                  TRUE
              },
              
              OAuthRequest = function(URL, params = character(), method = "GET",
                                      customHeader = NULL, curl = getCurlHandle(), ...) #, .opts = list())
               {
                ' If the OAuth handshake has been completed, will
                submit a URL request with an OAuth signature, returning
                any response from the server
                '
                if (! .self$handshakeComplete)
                  stop("This OAuth instance has not been verified")

                httpFunc <- switch(method,
                                   POST = oauthPOST,
                                   GET = oauthGET,
                                   PUT = oauthPUT,
                                   stop("method must be POST, PUT or GET"))

                httpFunc(URLencode(URL), params = params, consumerKey = .self$consumerKey,
                         consumerSecret = .self$consumerSecret,
                         oauthKey = .self$oauthKey, oauthSecret = .self$oauthSecret,
                         customHeader = .self$customHeader, curl = curl, #XXX use customHeader in formals.
                         signMethod = .self$signMethod, ...)#, .opts = .opts)
              }
              )
            )

OAuthFactory <- getRefClass("OAuth")
OAuthFactory$accessors(names(OAuthFactory$fields()))

